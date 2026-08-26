use anyhow::{anyhow, Context};
use async_trait::async_trait;
use oauthmux_core::{
    compile_resources, ConfigProvider, ProviderSnapshot, ResourceDocument, SecretResolver,
    SecretSource, SecretString,
};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::watch;

pub const DEFAULT_PATH: &str = "/etc/oauthmux/config.yaml";
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

trait LocalSecrets: Send + Sync {
    fn environment(&self, name: &str) -> anyhow::Result<String>;
    fn file(&self, path: &std::path::Path) -> anyhow::Result<String>;
}

struct SystemLocalSecrets;

impl LocalSecrets for SystemLocalSecrets {
    fn environment(&self, name: &str) -> anyhow::Result<String> {
        std::env::var(name).with_context(|| format!("environment variable {name} is not set"))
    }

    fn file(&self, path: &std::path::Path) -> anyhow::Result<String> {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
    }
}

pub struct FileProvider {
    path: PathBuf,
    poll_interval: Duration,
    secrets: Arc<dyn LocalSecrets>,
}

impl Default for FileProvider {
    fn default() -> Self {
        Self {
            path: DEFAULT_PATH.into(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            secrets: Arc::new(SystemLocalSecrets),
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
            secrets: Arc::new(SystemLocalSecrets),
        })
    }

    pub async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        let contents = tokio::fs::read_to_string(&self.path)
            .await
            .with_context(|| format!("read {}", self.path.display()))?;
        let documents = parse_documents(&contents)?;
        let resolver = FileSecretResolver {
            base: self
                .path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            secrets: self.secrets.as_ref(),
        };
        compile_resources(documents, &resolver).await
    }
}

#[async_trait]
impl ConfigProvider for FileProvider {
    fn name(&self) -> &str {
        "file"
    }

    async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        FileProvider::load(self).await
    }

    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()> {
        tx.send(self.load().await?)
            .map_err(|_| anyhow!("registry receiver closed"))?;
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match self.load().await {
                Ok(snapshot) => {
                    if tx.send(snapshot).is_err() {
                        return Ok(());
                    }
                }
                Err(error) => {
                    tracing::error!(path = %self.path.display(), %error, "invalid file provider configuration; keeping last good snapshot");
                }
            }
        }
    }
}

fn parse_documents(yaml: &str) -> anyhow::Result<Vec<ResourceDocument>> {
    serde_yaml::Deserializer::from_str(yaml)
        .map(|document| ResourceDocument::deserialize(document).context("parse resource document"))
        .collect()
}

struct FileSecretResolver<'a> {
    base: &'a std::path::Path,
    secrets: &'a dyn LocalSecrets,
}

#[async_trait]
impl SecretResolver for FileSecretResolver<'_> {
    async fn resolve_value(&self, value: &str) -> anyhow::Result<SecretString> {
        Ok(SecretString::new(value))
    }

    async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
        let value = match source {
            SecretSource::Env { name } => self.secrets.environment(name)?,
            SecretSource::File { path } => {
                let path = PathBuf::from(path);
                let path = if path.is_absolute() {
                    path
                } else {
                    self.base.join(path)
                };
                self.secrets.file(&path)?
            }
            SecretSource::SsmParameter { .. } | SecretSource::SecretsManager { .. } => {
                return Err(anyhow!(
                    "AWS secret sources are not supported by the File provider"
                ))
            }
        };
        Ok(SecretString::new(value.trim_end_matches(['\r', '\n'])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Mutex};
    use tempfile::NamedTempFile;

    #[derive(Default)]
    struct MockLocalSecrets {
        environment: HashMap<String, String>,
        files: HashMap<PathBuf, String>,
        calls: Mutex<Vec<String>>,
    }

    impl LocalSecrets for MockLocalSecrets {
        fn environment(&self, name: &str) -> anyhow::Result<String> {
            self.calls.lock().unwrap().push(format!("env:{name}"));
            self.environment
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("missing environment variable"))
        }

        fn file(&self, path: &std::path::Path) -> anyhow::Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("file:{}", path.display()));
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| anyhow!("missing secret file"))
        }
    }

    fn yaml(secret: &str) -> String {
        format!(
            r#"apiVersion: oauthmux.dev/v1alpha1
kind: Upstream
metadata:
  name: google
spec:
  issuerUrl: https://issuer.example
  oauthClient:
    clientId: upstream
    clientSecret:
{secret}
---
apiVersion: oauthmux.dev/v1alpha1
kind: Relay
metadata:
  name: cognito-google
spec:
  upstreamRef:
    name: google
  clientAuthentication:
    type: UpstreamClient
  redirectPolicy:
    allowedOrigins: [https://app.example]
"#
        )
    }

    async fn load_with(secret: &str, secrets: Arc<dyn LocalSecrets>) -> ProviderSnapshot {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), yaml(secret)).unwrap();
        let provider = FileProvider {
            path: file.path().to_owned(),
            poll_interval: Duration::from_secs(1),
            secrets,
        };
        provider.load().await.unwrap()
    }

    #[tokio::test]
    async fn resolves_inline_environment_and_relative_file_secrets() {
        let inline = load_with("      value: inline", Arc::new(MockLocalSecrets::default())).await;
        assert_eq!(
            inline
                .upstreams
                .values()
                .next()
                .unwrap()
                .client_secret
                .expose(),
            "inline"
        );

        let environment = Arc::new(MockLocalSecrets {
            environment: HashMap::from([("GOOGLE_SECRET".into(), "from-env".into())]),
            ..Default::default()
        });
        let snapshot = load_with(
            "      valueFrom:\n        env:\n          name: GOOGLE_SECRET",
            environment.clone(),
        )
        .await;
        assert_eq!(
            snapshot
                .upstreams
                .values()
                .next()
                .unwrap()
                .client_secret
                .expose(),
            "from-env"
        );
        assert_eq!(
            environment.calls.lock().unwrap().as_slice(),
            ["env:GOOGLE_SECRET"]
        );

        let file = NamedTempFile::new().unwrap();
        let base = file.path().parent().unwrap();
        let secret_path = base.join("relative-secret");
        let files = Arc::new(MockLocalSecrets {
            files: HashMap::from([(secret_path.clone(), "from-file\n".into())]),
            ..Default::default()
        });
        let snapshot = load_with(
            "      valueFrom:\n        file:\n          path: relative-secret",
            files.clone(),
        )
        .await;
        assert_eq!(
            snapshot
                .upstreams
                .values()
                .next()
                .unwrap()
                .client_secret
                .expose(),
            "from-file"
        );
        assert!(files.calls.lock().unwrap()[0].ends_with("relative-secret"));
    }

    #[tokio::test]
    async fn rejects_aws_secret_sources() {
        for secret in [
            "      valueFrom:\n        ssmParameter:\n          name: /secret",
            "      valueFrom:\n        secretsManager:\n          secretId: oauthmux/google\n          jsonKey: clientSecret",
        ] {
            let file = NamedTempFile::new().unwrap();
            std::fs::write(file.path(), yaml(secret)).unwrap();
            let provider = FileProvider::new(file.path(), Duration::from_secs(1)).unwrap();
            assert!(provider
                .load()
                .await
                .unwrap_err()
                .to_string()
                .contains("Upstream/google"));
        }
    }

    #[test]
    fn rejects_zero_poll_interval() {
        assert!(FileProvider::new("config.yaml", Duration::ZERO).is_err());
    }
}
