use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, str::FromStr, sync::Arc};
use url::Url;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InstanceKey(String);

impl InstanceKey {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.starts_with('/')
            || value.ends_with('/')
            || value.split('/').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            })
        {
            return Err("must contain non-empty URL-safe path segments".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InstanceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for InstanceKey {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Origin(Url);

impl Origin {
    pub fn parse(value: &str) -> Result<Self, String> {
        let url = Url::parse(value).map_err(|e| e.to_string())?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err("must be an http(s) origin".into());
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err("must contain only scheme, host, and optional port".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("must not contain user information".into());
        }
        Ok(Self(url))
    }

    pub fn url(&self) -> &Url {
        &self.0
    }

    pub fn matches(&self, other: &Url) -> bool {
        same_origin(&self.0, other)
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Default, Eq, PartialEq, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Instance {
    pub key: InstanceKey,
    pub upstream: UpstreamSpec,
    pub client_auth: ClientAuth,
    pub allowed_redirect_origins: Vec<Origin>,
    pub default_redirect_uri: Option<Url>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpstreamSpec {
    pub issuer_url: Url,
    pub authorization_endpoint: Option<Url>,
    pub token_endpoint: Option<Url>,
    pub jwks_uri: Option<Url>,
    pub client_id: String,
    pub client_secret: SecretString,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ClientAuth {
    Public,
    ClientSecret {
        client_id: String,
        client_secret: SecretString,
    },
    PrivateKeyJwt {
        client_id: String,
        jwks: ClientJwks,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClientJwks {
    Url(Url),
    Inline(serde_json::Value),
}

impl Instance {
    pub fn redirect_allowed(&self, redirect: &Url) -> bool {
        if !matches!(redirect.scheme(), "http" | "https")
            || redirect.host_str().is_none()
            || redirect.fragment().is_some()
            || !redirect.username().is_empty()
            || redirect.password().is_some()
        {
            return false;
        }
        let loopback = redirect.scheme() == "http"
            && matches!(redirect.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        loopback
            || self
                .allowed_redirect_origins
                .iter()
                .any(|o| o.matches(redirect))
    }

    pub fn validate(&self) -> Result<(), String> {
        for (field, url) in std::iter::once(("upstream.issuer_url", &self.upstream.issuer_url))
            .chain(
                self.upstream
                    .authorization_endpoint
                    .as_ref()
                    .map(|url| ("upstream.authorization_endpoint", url)),
            )
            .chain(
                self.upstream
                    .token_endpoint
                    .as_ref()
                    .map(|url| ("upstream.token_endpoint", url)),
            )
            .chain(
                self.upstream
                    .jwks_uri
                    .as_ref()
                    .map(|url| ("upstream.jwks_uri", url)),
            )
        {
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(format!("{field} must be an absolute http(s) URL"));
            }
        }
        if self.upstream.client_id.is_empty() {
            return Err("upstream.client_id must not be empty".into());
        }
        if self.upstream.client_secret.expose().is_empty() {
            return Err("upstream.client_secret must not be empty".into());
        }
        if let Some(default) = &self.default_redirect_uri {
            if !self.redirect_allowed(default) {
                return Err("default_redirect_uri origin is not allowed".into());
            }
        }
        match &self.client_auth {
            ClientAuth::ClientSecret {
                client_id,
                client_secret,
            } if client_id.is_empty() || client_secret.expose().is_empty() => {
                Err("client_auth credentials must not be empty".into())
            }
            ClientAuth::PrivateKeyJwt { client_id, .. } if client_id.is_empty() => {
                Err("client_auth.client_id must not be empty".into())
            }
            ClientAuth::PrivateKeyJwt {
                jwks: ClientJwks::Url(url),
                ..
            } if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() => {
                Err("client_auth.jwks must be an absolute http(s) URL".into())
            }
            ClientAuth::PrivateKeyJwt {
                jwks: ClientJwks::Inline(value),
                ..
            } if !value
                .get("keys")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|keys| !keys.is_empty()) =>
            {
                Err("client_auth.jwks must contain a non-empty keys array".into())
            }
            _ => Ok(()),
        }
    }
}

pub(crate) fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            == b.host_str()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        && a.port_or_known_default() == b.port_or_known_default()
}

pub type InstanceMap = std::collections::HashMap<InstanceKey, Arc<Instance>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_require_exact_origin_or_http_loopback() {
        let origin = Origin::parse("https://app.example.com").unwrap();
        let mut instance = Instance {
            key: InstanceKey::new("google").unwrap(),
            upstream: UpstreamSpec {
                issuer_url: Url::parse("https://issuer.example").unwrap(),
                authorization_endpoint: None,
                token_endpoint: None,
                jwks_uri: None,
                client_id: "id".into(),
                client_secret: SecretString::new("secret"),
                scopes: vec![],
            },
            client_auth: ClientAuth::Public,
            allowed_redirect_origins: vec![origin],
            default_redirect_uri: None,
        };
        assert!(instance.redirect_allowed(&Url::parse("https://app.example.com/cb").unwrap()));
        assert!(instance.redirect_allowed(&Url::parse("http://localhost:5173/cb").unwrap()));
        for bad in [
            "https://app.example.com.evil.test/cb",
            "https://app.example.com@evil.test/cb",
            "http://app.example.com/cb",
            "javascript://localhost/x",
            "http://localhost.evil.test/cb",
            "https://user@app.example.com/cb",
            "https://app.example.com/cb#fragment",
        ] {
            assert!(
                !instance.redirect_allowed(&Url::parse(bad).unwrap()),
                "{bad}"
            );
        }
        instance.default_redirect_uri = Some(Url::parse("https://evil.test/cb").unwrap());
        assert!(instance.validate().is_err());
    }
}
