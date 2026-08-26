use crate::{
    ClientAuth, ClientJwks, Origin, ProviderSnapshot, Relay, ResourceKey, SecretString, Upstream,
};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};
use url::Url;

pub const API_VERSION: &str = "oauthmux.dev/v1alpha1";

pub fn resource_schema() -> schemars::Schema {
    schemars::schema_for!(ResourceDocument)
}

#[derive(Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum ResourceDocument {
    Upstream(UpstreamResource),
    Relay(RelayResource),
}

impl ResourceDocument {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Upstream(_) => "Upstream",
            Self::Relay(_) => "Relay",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Upstream(resource) => &resource.metadata.name,
            Self::Relay(resource) => &resource.metadata.name,
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamResource {
    #[serde(rename = "apiVersion")]
    pub api_version: ApiVersion,
    pub metadata: Metadata,
    pub spec: UpstreamResourceSpec,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayResource {
    #[serde(rename = "apiVersion")]
    pub api_version: ApiVersion,
    pub metadata: Metadata,
    pub spec: RelayResourceSpec,
}

#[derive(Deserialize, JsonSchema)]
pub enum ApiVersion {
    #[serde(rename = "oauthmux.dev/v1alpha1")]
    V1Alpha1,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamResourceSpec {
    pub issuer_url: String,
    #[serde(default)]
    pub endpoints: UpstreamEndpoints,
    pub oauth_client: OAuthClient,
}

#[derive(Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamEndpoints {
    #[serde(default)]
    pub authorization: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub jwks: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: SecretValue,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayResourceSpec {
    pub upstream_ref: ResourceReference,
    #[serde(default)]
    pub scopes: ScopePolicy,
    pub client_authentication: ClientAuthentication,
    #[serde(default)]
    pub redirect_policy: RedirectPolicy,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceReference {
    pub name: String,
}

#[derive(Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    #[serde(default)]
    pub default: Vec<String>,
    #[serde(default)]
    pub allowed: Option<Vec<String>>,
}

#[derive(Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedirectPolicy {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub default_redirect_uri: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ClientAuthentication {
    UpstreamClient,
    Public,
    ClientSecret {
        #[serde(rename = "clientId")]
        client_id: String,
        #[serde(rename = "clientSecret")]
        client_secret: SecretValue,
    },
    PrivateKeyJwt {
        #[serde(rename = "clientId")]
        client_id: String,
        jwks: serde_json::Value,
    },
}

#[derive(Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SecretValue {
    Value(InlineSecret),
    ValueFrom(ReferencedSecret),
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InlineSecret {
    value: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReferencedSecret {
    value_from: SecretSource,
}

impl SecretValue {
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Value(secret) => Some(&secret.value),
            Self::ValueFrom(_) => None,
        }
    }

    pub fn value_from(&self) -> Option<&SecretSource> {
        match self {
            Self::Value(_) => None,
            Self::ValueFrom(secret) => Some(&secret.value_from),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SecretSource {
    Env {
        name: String,
    },
    File {
        path: String,
    },
    SsmParameter {
        name: String,
    },
    SecretsManager {
        #[serde(rename = "secretId")]
        secret_id: String,
        #[serde(default, rename = "jsonKey")]
        json_key: Option<String>,
    },
}

#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve_value(&self, value: &str) -> anyhow::Result<SecretString>;
    async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString>;
}

pub async fn compile_resources(
    documents: Vec<ResourceDocument>,
    secrets: &dyn SecretResolver,
) -> anyhow::Result<ProviderSnapshot> {
    let mut upstream_documents = Vec::new();
    let mut relay_documents = Vec::new();
    let mut identities = std::collections::HashSet::new();

    for document in documents {
        let identity = (document.kind(), document.name().to_owned());
        if !identities.insert(identity.clone()) {
            return Err(anyhow!("duplicate {}/{}", identity.0, identity.1));
        }
        match document {
            ResourceDocument::Upstream(resource) => upstream_documents.push(resource),
            ResourceDocument::Relay(resource) => relay_documents.push(resource),
        }
    }

    let mut snapshot = ProviderSnapshot::default();
    let mut secret_cache = HashMap::new();
    for resource in upstream_documents {
        let key = resource_key("Upstream", &resource.metadata.name)?;
        let secret = resolve_secret(
            &resource.spec.oauth_client.client_secret,
            secrets,
            &mut secret_cache,
        )
        .await
        .with_context(|| format!("Upstream/{key} spec.oauthClient.clientSecret"))?;
        let upstream = Upstream {
            key: key.clone(),
            issuer_url: parse_url("spec.issuerUrl", &resource.spec.issuer_url)?,
            authorization_endpoint: parse_optional_url(
                "spec.endpoints.authorization",
                resource.spec.endpoints.authorization,
            )?,
            token_endpoint: parse_optional_url(
                "spec.endpoints.token",
                resource.spec.endpoints.token,
            )?,
            jwks_uri: parse_optional_url("spec.endpoints.jwks", resource.spec.endpoints.jwks)?,
            client_id: resource.spec.oauth_client.client_id,
            client_secret: secret,
        };
        upstream
            .validate()
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("Upstream/{key}"))?;
        snapshot.upstreams.insert(key, Arc::new(upstream));
    }

    for resource in relay_documents {
        let key = resource_key("Relay", &resource.metadata.name)?;
        let upstream = resource_key("Upstream", &resource.spec.upstream_ref.name)?;
        let client_auth = match resource.spec.client_authentication {
            ClientAuthentication::UpstreamClient => ClientAuth::UpstreamClient,
            ClientAuthentication::Public => ClientAuth::Public,
            ClientAuthentication::ClientSecret {
                client_id,
                client_secret,
            } => ClientAuth::ClientSecret {
                client_id,
                client_secret: resolve_secret(&client_secret, secrets, &mut secret_cache)
                    .await
                    .with_context(|| {
                        format!("Relay/{key} spec.clientAuthentication.clientSecret")
                    })?,
            },
            ClientAuthentication::PrivateKeyJwt { client_id, jwks } => ClientAuth::PrivateKeyJwt {
                client_id,
                jwks: match jwks {
                    serde_json::Value::String(value) => ClientJwks::Url(
                        Url::parse(&value).context("spec.clientAuthentication.jwks URL")?,
                    ),
                    value => ClientJwks::Inline(value),
                },
            },
        };
        let allowed_redirect_origins = resource
            .spec
            .redirect_policy
            .allowed_origins
            .iter()
            .map(|value| Origin::parse(value).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<Vec<_>>>()
            .with_context(|| format!("Relay/{key} spec.redirectPolicy.allowedOrigins"))?;
        let relay = Relay {
            key: key.clone(),
            upstream,
            client_auth,
            scopes: resource.spec.scopes.default,
            allowed_scopes: resource.spec.scopes.allowed,
            allowed_redirect_origins,
            default_redirect_uri: parse_optional_url(
                "spec.redirectPolicy.defaultRedirectUri",
                resource.spec.redirect_policy.default_redirect_uri,
            )?,
        };
        relay
            .validate()
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("Relay/{key}"))?;
        snapshot.relays.insert(key, Arc::new(relay));
    }

    snapshot.validate().map_err(anyhow::Error::msg)?;
    Ok(snapshot)
}

async fn resolve_secret(
    secret: &SecretValue,
    resolver: &dyn SecretResolver,
    cache: &mut HashMap<SecretSource, SecretString>,
) -> anyhow::Result<SecretString> {
    if let Some(value) = secret.value() {
        return resolver.resolve_value(value).await;
    }
    let source = secret.value_from().expect("validated source");
    if let Some(value) = cache.get(source) {
        return Ok(value.clone());
    }
    let value = resolver.resolve_source(source).await?;
    cache.insert(source.clone(), value.clone());
    Ok(value)
}

fn resource_key(kind: &str, value: &str) -> anyhow::Result<ResourceKey> {
    if value.contains('/') {
        return Err(anyhow!(
            "{kind}/{value}: metadata.name must be one path segment"
        ));
    }
    ResourceKey::new(value).map_err(|error| anyhow!("{kind}/{value}: metadata.name {error}"))
}

fn parse_url(field: &str, value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value).with_context(|| field.to_owned())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(anyhow!("{field}: must be an absolute http(s) URL"));
    }
    Ok(url)
}

fn parse_optional_url(field: &str, value: Option<String>) -> anyhow::Result<Option<Url>> {
    value.map(|value| parse_url(field, &value)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockSecrets {
        calls: Mutex<Vec<SecretSource>>,
    }

    #[async_trait]
    impl SecretResolver for MockSecrets {
        async fn resolve_value(&self, value: &str) -> anyhow::Result<SecretString> {
            Ok(SecretString::new(value))
        }

        async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
            self.calls.lock().unwrap().push(source.clone());
            Ok(SecretString::new("resolved"))
        }
    }

    fn documents(secret: SecretValue) -> Vec<ResourceDocument> {
        vec![
            ResourceDocument::Upstream(UpstreamResource {
                api_version: ApiVersion::V1Alpha1,
                metadata: Metadata {
                    name: "google".into(),
                },
                spec: UpstreamResourceSpec {
                    issuer_url: "https://issuer.example".into(),
                    endpoints: UpstreamEndpoints::default(),
                    oauth_client: OAuthClient {
                        client_id: "client".into(),
                        client_secret: secret,
                    },
                },
            }),
            ResourceDocument::Relay(RelayResource {
                api_version: ApiVersion::V1Alpha1,
                metadata: Metadata {
                    name: "cognito".into(),
                },
                spec: RelayResourceSpec {
                    upstream_ref: ResourceReference {
                        name: "google".into(),
                    },
                    scopes: ScopePolicy::default(),
                    client_authentication: ClientAuthentication::UpstreamClient,
                    redirect_policy: RedirectPolicy::default(),
                },
            }),
        ]
    }

    #[tokio::test]
    async fn compiles_references_and_resolves_secret_source() {
        let source = SecretSource::Env {
            name: "GOOGLE_SECRET".into(),
        };
        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };
        let snapshot = compile_resources(
            documents(SecretValue::ValueFrom(ReferencedSecret {
                value_from: source.clone(),
            })),
            &secrets,
        )
        .await
        .unwrap();
        assert_eq!(snapshot.upstreams.len(), 1);
        assert_eq!(snapshot.relays.len(), 1);
        assert_eq!(*secrets.calls.lock().unwrap(), vec![source]);
    }

    #[tokio::test]
    async fn resolves_and_deduplicates_relay_client_secret_references() {
        let source = SecretSource::SsmParameter {
            name: "/oauthmux/secrets/shared".into(),
        };
        let mut resources = documents(SecretValue::ValueFrom(ReferencedSecret {
            value_from: source.clone(),
        }));
        let ResourceDocument::Relay(relay) = &mut resources[1] else {
            unreachable!();
        };
        relay.spec.client_authentication = ClientAuthentication::ClientSecret {
            client_id: "downstream".into(),
            client_secret: SecretValue::ValueFrom(ReferencedSecret {
                value_from: source.clone(),
            }),
        };
        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };

        let snapshot = compile_resources(resources, &secrets).await.unwrap();
        let relay = snapshot.relays.values().next().unwrap();
        let ClientAuth::ClientSecret { client_secret, .. } = &relay.client_auth else {
            panic!("expected relay client secret authentication");
        };
        assert_eq!(client_secret.expose(), "resolved");
        assert_eq!(*secrets.calls.lock().unwrap(), vec![source]);
    }

    #[tokio::test]
    async fn rejects_missing_reference_and_ambiguous_secret() {
        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };
        let mut resources = documents(SecretValue::Value(InlineSecret {
            value: "inline".into(),
        }));
        resources.remove(0);
        assert!(compile_resources(resources, &secrets)
            .await
            .unwrap_err()
            .to_string()
            .contains("does not exist"));

        let ambiguous = r#"{"value":"inline","valueFrom":{"env":{"name":"X"}}}"#;
        assert!(serde_json::from_str::<SecretValue>(ambiguous).is_err());
    }

    #[test]
    fn generated_schema_contains_versioned_resources_and_json_key() {
        let schema = serde_json::to_string(&resource_schema()).unwrap();
        assert!(schema.contains(API_VERSION));
        assert!(schema.contains("Upstream"));
        assert!(schema.contains("Relay"));
        assert!(schema.contains("secretsManager"));
        assert!(schema.contains("jsonKey"));
    }
}
