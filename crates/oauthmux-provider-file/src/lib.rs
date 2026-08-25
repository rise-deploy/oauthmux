use anyhow::{anyhow, Context};
use async_trait::async_trait;
use oauthmux_core::{
    ClientAuth, ClientJwks, ConfigProvider, Instance, InstanceKey, Origin, ProviderSnapshot,
    SecretString, UpstreamSpec,
};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::watch;
use url::Url;

pub const DEFAULT_PATH: &str = "/etc/oauthmux/config.yaml";
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

pub struct FileProvider {
    path: PathBuf,
    poll_interval: Duration,
}

impl Default for FileProvider {
    fn default() -> Self {
        Self {
            path: DEFAULT_PATH.into(),
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

impl FileProvider {
    pub fn new(path: impl Into<PathBuf>, poll_interval: Duration) -> anyhow::Result<Self> {
        if poll_interval.is_zero() {
            return Err(anyhow!(
                "file provider poll interval must be greater than zero"
            ));
        }
        Ok(Self {
            path: path.into(),
            poll_interval,
        })
    }

    pub async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        let contents = tokio::fs::read_to_string(&self.path)
            .await
            .with_context(|| format!("read {}", self.path.display()))?;
        parse_config(&contents, |path| std::fs::read_to_string(path))
    }
}

#[async_trait]
impl ConfigProvider for FileProvider {
    fn name(&self) -> &str {
        "file"
    }

    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()> {
        let first = self.load().await?;
        tx.send(first)
            .map_err(|_| anyhow!("registry receiver closed"))?;
        let mut last_modified = tokio::fs::metadata(&self.path)
            .await
            .ok()
            .and_then(|meta| meta.modified().ok());
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let modified = tokio::fs::metadata(&self.path)
                .await
                .ok()
                .and_then(|meta| meta.modified().ok());
            if modified == last_modified {
                continue;
            }
            match self.load().await {
                Ok(snapshot) => {
                    if tx.send(snapshot).is_err() {
                        return Ok(());
                    }
                    last_modified = modified;
                }
                Err(error) => {
                    tracing::error!(path = %self.path.display(), %error, "invalid file provider configuration; keeping last good snapshot");
                }
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    instances: BTreeMap<String, RawInstance>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInstance {
    issuer_url: String,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    client_secret_file: Option<PathBuf>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    allowed_redirect_origins: Vec<String>,
    #[serde(default)]
    default_redirect_uri: Option<String>,
    client_auth: RawClientAuth,
}

#[derive(Clone, Deserialize)]
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

pub fn parse_config(
    yaml: &str,
    read_secret_file: impl Fn(&std::path::Path) -> std::io::Result<String>,
) -> anyhow::Result<ProviderSnapshot> {
    let config: FileConfig = serde_yaml::from_str(yaml).context("parse YAML")?;
    let mut snapshot = ProviderSnapshot::default();
    for (name, raw) in config.instances {
        let instance = raw
            .into_instance(&name, &read_secret_file)
            .with_context(|| format!("instance {name}"))?;
        snapshot
            .instances
            .insert(instance.key.clone(), Arc::new(instance));
    }
    Ok(snapshot)
}

impl RawInstance {
    fn into_instance(
        self,
        name: &str,
        read_secret_file: &impl Fn(&std::path::Path) -> std::io::Result<String>,
    ) -> anyhow::Result<Instance> {
        if name.contains('/') {
            return Err(anyhow!(
                "key: file-provider instance keys must be one path segment"
            ));
        }
        let key = InstanceKey::new(name).map_err(|e| anyhow!("key: {e}"))?;
        let secret = match (self.client_secret, self.client_secret_file) {
            (Some(secret), None) => interpolate_secret(&secret).context("client_secret")?,
            (None, Some(path)) => read_secret_file(&path)
                .with_context(|| format!("client_secret_file {}", path.display()))?
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
            _ => {
                return Err(anyhow!(
                    "exactly one of client_secret or client_secret_file is required"
                ))
            }
        };
        let allowed_redirect_origins = self
            .allowed_redirect_origins
            .iter()
            .map(|value| Origin::parse(value).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<Vec<_>>>()
            .context("allowed_redirect_origins")?;
        let client_auth = match self.client_auth {
            RawClientAuth::Public => ClientAuth::Public,
            RawClientAuth::ClientSecret {
                client_id,
                client_secret,
            } => ClientAuth::ClientSecret {
                client_id,
                client_secret: SecretString::new(
                    interpolate_secret(&client_secret).context("client_auth.client_secret")?,
                ),
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
                issuer_url: parse_url("issuer_url", &self.issuer_url)?,
                authorization_endpoint: parse_optional_url(
                    "authorization_endpoint",
                    self.authorization_endpoint,
                )?,
                token_endpoint: parse_optional_url("token_endpoint", self.token_endpoint)?,
                jwks_uri: parse_optional_url("jwks_uri", self.jwks_uri)?,
                client_id: self.client_id,
                client_secret: SecretString::new(secret),
                scopes: self.scopes,
            },
            client_auth,
            allowed_redirect_origins,
            default_redirect_uri: parse_optional_url(
                "default_redirect_uri",
                self.default_redirect_uri,
            )?,
        };
        instance.validate().map_err(anyhow::Error::msg)?;
        Ok(instance)
    }
}

fn interpolate_secret(value: &str) -> anyhow::Result<String> {
    if let Some(name) = value.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(anyhow!("invalid environment variable reference"));
        }
        std::env::var(name).map_err(|_| anyhow!("environment variable {name} is not set"))
    } else {
        Ok(value.to_owned())
    }
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
    use std::io::Write;

    const VALID: &str = r#"
instances:
  google:
    issuer_url: https://accounts.example
    client_id: upstream
    client_secret: upstream-secret
    scopes: [openid]
    allowed_redirect_origins: [https://app.example]
    default_redirect_uri: https://app.example/callback
    client_auth:
      mode: public
"#;

    #[test]
    fn parses_valid_file() {
        let snapshot = parse_config(VALID, |_| unreachable!()).unwrap();
        assert!(snapshot
            .instances
            .contains_key(&InstanceKey::new("google").unwrap()));
    }

    #[test]
    fn rejects_secret_source_xor_violations() {
        let neither = VALID.replace("    client_secret: upstream-secret\n", "");
        assert!(parse_config(&neither, |_| unreachable!())
            .unwrap_err()
            .to_string()
            .contains("google"));
        let both = VALID.replace(
            "    client_secret: upstream-secret",
            "    client_secret: upstream-secret\n    client_secret_file: /secret",
        );
        assert!(parse_config(&both, |_| Ok("file".into())).is_err());
    }

    #[test]
    fn secret_file_is_trimmed_and_missing_env_names_variable() {
        let file = VALID.replace(
            "client_secret: upstream-secret",
            "client_secret_file: /secret",
        );
        let snapshot = parse_config(&file, |_| Ok("secret\n".into())).unwrap();
        assert_eq!(
            snapshot
                .instances
                .values()
                .next()
                .unwrap()
                .upstream
                .client_secret
                .expose(),
            "secret"
        );
        let missing = VALID.replace("upstream-secret", "${OAUTHMUX_TEST_DEFINITELY_MISSING}");
        let error = parse_config(&missing, |_| unreachable!())
            .unwrap_err()
            .to_string();
        assert!(error.contains("google"));
        assert!(format!(
            "{:#}",
            parse_config(&missing, |_| unreachable!()).unwrap_err()
        )
        .contains("OAUTHMUX_TEST_DEFINITELY_MISSING"));
    }

    #[test]
    fn validation_names_instance_and_field() {
        let invalid = VALID.replace("https://app.example]", "https://app.example/path]");
        let error = format!(
            "{:#}",
            parse_config(&invalid, |_| unreachable!()).unwrap_err()
        );
        assert!(error.contains("instance google"));
        assert!(error.contains("allowed_redirect_origins"));
    }

    #[test]
    fn rejects_unservable_key_bad_urls_and_invalid_default() {
        assert!(FileProvider::new("config.yaml", Duration::ZERO).is_err());
        let nested = VALID.replace("google:", "project/google:");
        assert!(format!(
            "{:#}",
            parse_config(&nested, |_| unreachable!()).unwrap_err()
        )
        .contains("one path segment"));

        let bad_issuer = VALID.replace("https://accounts.example", "file:///issuer");
        assert!(format!(
            "{:#}",
            parse_config(&bad_issuer, |_| unreachable!()).unwrap_err()
        )
        .contains("issuer_url"));

        let bad_default = VALID.replace(
            "https://app.example/callback",
            "https://other.example/callback",
        );
        assert!(format!(
            "{:#}",
            parse_config(&bad_default, |_| unreachable!()).unwrap_err()
        )
        .contains("default_redirect_uri"));
    }

    #[tokio::test]
    async fn hot_reload_retains_last_good_snapshot() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(VALID.as_bytes()).unwrap();
        file.flush().unwrap();
        let provider = Arc::new(FileProvider::new(file.path(), Duration::from_millis(10)).unwrap());
        let (tx, mut rx) = watch::channel(ProviderSnapshot::default());
        let task = tokio::spawn(provider.run(tx));
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow_and_update().instances.len(), 1);

        tokio::time::sleep(Duration::from_millis(20)).await;
        std::fs::write(file.path(), "instances: [invalid").unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(rx.borrow().instances.len(), 1);

        tokio::time::sleep(Duration::from_millis(20)).await;
        std::fs::write(file.path(), VALID.replace("google:", "github:")).unwrap();
        tokio::time::timeout(Duration::from_secs(1), rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(rx
            .borrow()
            .instances
            .contains_key(&InstanceKey::new("github").unwrap()));
        task.abort();
    }
}
