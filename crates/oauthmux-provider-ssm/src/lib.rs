use anyhow::{anyhow, Context};
use async_trait::async_trait;
use oauthmux_core::{
    ClientAuth, ClientJwks, ConfigProvider, Instance, InstanceKey, Origin, ProviderSnapshot,
    SecretString, UpstreamSpec,
};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
use url::Url;

pub const DEFAULT_PREFIX: &str = "/oauthmux/instances/";
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct Parameter {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Default)]
pub struct ParameterPage {
    pub parameters: Vec<Parameter>,
    pub next_token: Option<String>,
}

#[async_trait]
pub trait SsmClient: Send + Sync + 'static {
    async fn get_parameters_by_path(
        &self,
        path: &str,
        next_token: Option<String>,
    ) -> anyhow::Result<ParameterPage>;
}

#[cfg(feature = "aws")]
pub struct AwsSsmClient(pub aws_sdk_ssm::Client);

#[cfg(feature = "aws")]
#[async_trait]
impl SsmClient for AwsSsmClient {
    async fn get_parameters_by_path(
        &self,
        path: &str,
        next_token: Option<String>,
    ) -> anyhow::Result<ParameterPage> {
        let output = self
            .0
            .get_parameters_by_path()
            .path(path)
            .recursive(true)
            .with_decryption(true)
            .set_next_token(next_token)
            .send()
            .await
            .context("GetParametersByPath")?;
        let parameters = output
            .parameters()
            .iter()
            .filter_map(|parameter| {
                Some(Parameter {
                    name: parameter.name()?.to_owned(),
                    value: parameter.value()?.to_owned(),
                })
            })
            .collect();
        Ok(ParameterPage {
            parameters,
            next_token: output.next_token().map(str::to_owned),
        })
    }
}

pub struct SsmProvider<C> {
    client: Arc<C>,
    prefix: String,
    poll_interval: Duration,
}

impl<C> SsmProvider<C> {
    pub fn new(
        client: Arc<C>,
        prefix: impl Into<String>,
        poll_interval: Duration,
    ) -> anyhow::Result<Self> {
        let prefix = prefix.into();
        if !prefix.starts_with('/') || !prefix.ends_with('/') {
            return Err(anyhow!("SSM prefix must start and end with '/'"));
        }
        if poll_interval.is_zero() {
            return Err(anyhow!("SSM poll interval must be greater than zero"));
        }
        Ok(Self {
            client,
            prefix,
            poll_interval,
        })
    }
}

impl<C: SsmClient> SsmProvider<C> {
    pub async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        let mut snapshot = ProviderSnapshot::default();
        let mut token = None;
        loop {
            let page = self
                .client
                .get_parameters_by_path(&self.prefix, token)
                .await?;
            for parameter in page.parameters {
                let key_text = match parameter
                    .name
                    .strip_prefix(&self.prefix)
                    .filter(|name| !name.is_empty())
                {
                    Some(value) => value,
                    None => {
                        tracing::error!(parameter = %parameter.name, "SSM parameter is outside the configured prefix");
                        continue;
                    }
                };
                match parse_instance(key_text, &parameter.value) {
                    Ok(instance) => {
                        snapshot
                            .instances
                            .insert(instance.key.clone(), Arc::new(instance));
                    }
                    Err(error) => {
                        tracing::error!(parameter = %parameter.name, %error, "malformed SSM instance parameter; skipping instance");
                    }
                }
            }
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        Ok(snapshot)
    }
}

#[async_trait]
impl<C: SsmClient> ConfigProvider for SsmProvider<C> {
    fn name(&self) -> &str {
        "ssm"
    }

    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()> {
        let mut has_sent = false;
        loop {
            match self.load().await {
                Ok(snapshot) => {
                    if tx.send(snapshot).is_err() {
                        return Ok(());
                    }
                    has_sent = true;
                }
                Err(error) if !has_sent => return Err(error),
                Err(error) => {
                    tracing::error!(%error, "SSM poll failed; keeping last good snapshot")
                }
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstance {
    issuer_url: String,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    client_secret_file: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    allowed_redirect_origins: Vec<String>,
    #[serde(default)]
    default_redirect_uri: Option<String>,
    client_auth: RawClientAuth,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum RawClientAuth {
    Public,
    ClientSecret {
        client_id: String,
        client_secret: String,
    },
    PrivateKeyJwt {
        client_id: String,
        jwks: serde_json::Value,
    },
}

pub fn parse_instance(name: &str, document: &str) -> anyhow::Result<Instance> {
    if name.contains('/') {
        return Err(anyhow!(
            "key: SSM-provider instance keys must be one path segment"
        ));
    }
    let raw: RawInstance = serde_yaml::from_str(document).context("parse YAML/JSON")?;
    if raw.client_secret_file.is_some() {
        return Err(anyhow!(
            "client_secret_file is not supported by the SSM provider"
        ));
    }
    let key = InstanceKey::new(name).map_err(|e| anyhow!("key: {e}"))?;
    let allowed_redirect_origins = raw
        .allowed_redirect_origins
        .iter()
        .map(|value| Origin::parse(value).map_err(anyhow::Error::msg))
        .collect::<anyhow::Result<Vec<_>>>()
        .context("allowed_redirect_origins")?;
    let client_auth = match raw.client_auth {
        RawClientAuth::Public => ClientAuth::Public,
        RawClientAuth::ClientSecret {
            client_id,
            client_secret,
        } => ClientAuth::ClientSecret {
            client_id,
            client_secret: SecretString::new(client_secret),
        },
        RawClientAuth::PrivateKeyJwt { client_id, jwks } => ClientAuth::PrivateKeyJwt {
            client_id,
            jwks: match jwks {
                serde_json::Value::String(value) => {
                    ClientJwks::Url(Url::parse(&value).context("client_auth.jwks URL")?)
                }
                value => ClientJwks::Inline(value),
            },
        },
    };
    let instance = Instance {
        key,
        upstream: UpstreamSpec {
            issuer_url: parse_url("issuer_url", &raw.issuer_url)?,
            authorization_endpoint: parse_optional_url(
                "authorization_endpoint",
                raw.authorization_endpoint,
            )?,
            token_endpoint: parse_optional_url("token_endpoint", raw.token_endpoint)?,
            jwks_uri: parse_optional_url("jwks_uri", raw.jwks_uri)?,
            client_id: raw.client_id,
            client_secret: SecretString::new(raw.client_secret),
            scopes: raw.scopes,
        },
        client_auth,
        allowed_redirect_origins,
        default_redirect_uri: parse_optional_url("default_redirect_uri", raw.default_redirect_uri)?,
    };
    instance.validate().map_err(anyhow::Error::msg)?;
    Ok(instance)
}

fn parse_url(field: &str, value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value).with_context(|| field.to_owned())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!("{field}: must use http or https"));
    }
    Ok(url)
}

fn parse_optional_url(field: &str, value: Option<String>) -> anyhow::Result<Option<Url>> {
    value.map(|value| parse_url(field, &value)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    struct MockClient(Mutex<VecDeque<ParameterPage>>);

    #[async_trait]
    impl SsmClient for MockClient {
        async fn get_parameters_by_path(
            &self,
            _: &str,
            _: Option<String>,
        ) -> anyhow::Result<ParameterPage> {
            self.0
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow!("unexpected call"))
        }
    }

    fn document() -> String {
        r#"
issuer_url: https://issuer.example
authorization_endpoint: https://issuer.example/auth
token_endpoint: https://issuer.example/token
client_id: upstream
client_secret: secret
scopes: [openid]
allowed_redirect_origins: [https://app.example]
default_redirect_uri: https://app.example/callback
client_auth:
  mode: public
"#
        .into()
    }

    #[tokio::test]
    async fn paginates_and_skips_only_malformed_instance() {
        let client = Arc::new(MockClient(Mutex::new(VecDeque::from([
            ParameterPage {
                parameters: vec![Parameter {
                    name: "/oauthmux/instances/good".into(),
                    value: document(),
                }],
                next_token: Some("next".into()),
            },
            ParameterPage {
                parameters: vec![
                    Parameter {
                        name: "/oauthmux/instances/bad".into(),
                        value: "not: [yaml".into(),
                    },
                    Parameter {
                        name: "/oauthmux/instances/good-two".into(),
                        value: document(),
                    },
                ],
                next_token: None,
            },
        ]))));
        let provider =
            SsmProvider::new(client, "/oauthmux/instances/", Duration::from_secs(60)).unwrap();
        let snapshot = provider.load().await.unwrap();
        assert_eq!(snapshot.instances.len(), 2);
    }

    #[test]
    fn rejects_file_secret_and_invalid_prefix() {
        let with_file = document().replace(
            "client_secret: secret",
            "client_secret: secret\nclient_secret_file: /secret",
        );
        assert!(parse_instance("bad", &with_file)
            .unwrap_err()
            .to_string()
            .contains("client_secret_file"));
        let client = Arc::new(MockClient(Mutex::new(VecDeque::new())));
        assert!(SsmProvider::new(client, "missing-slashes", Duration::from_secs(1)).is_err());
        let client = Arc::new(MockClient(Mutex::new(VecDeque::new())));
        assert!(SsmProvider::new(client, DEFAULT_PREFIX, Duration::ZERO).is_err());
    }
}
