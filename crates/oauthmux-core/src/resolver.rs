use crate::{Instance, InstanceKey, InstanceMap};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::{watch, Mutex};

#[derive(Debug, Error)]
#[error("instance resolution failed: {0}")]
pub struct ResolveError(pub String);

#[derive(Debug, Error)]
#[error("replay cache failed: {0}")]
pub struct CacheError(pub String);

#[async_trait]
pub trait InstanceResolver: Send + Sync + 'static {
    async fn resolve(&self, key: &InstanceKey) -> Result<Option<Arc<Instance>>, ResolveError>;
}

#[derive(Clone, Debug, Default)]
pub struct ProviderSnapshot {
    pub instances: InstanceMap,
}

#[async_trait]
pub trait ConfigProvider: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()>;
}

#[async_trait]
pub trait ReplayCache: Send + Sync + 'static {
    async fn first_use(&self, id: &str, ttl: Duration) -> Result<bool, CacheError>;
}

#[derive(Default)]
pub struct MemoryReplayCache {
    entries: Mutex<HashMap<String, std::time::Instant>>,
}

#[async_trait]
impl ReplayCache for MemoryReplayCache {
    async fn first_use(&self, id: &str, ttl: Duration) -> Result<bool, CacheError> {
        let now = std::time::Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_, expires| *expires > now);
        if entries.contains_key(id) {
            return Ok(false);
        }
        entries.insert(id.to_owned(), now + ttl);
        Ok(true)
    }
}

pub struct Registry {
    instances: ArcSwap<InstanceMap>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            instances: ArcSwap::from_pointee(HashMap::new()),
        }
    }
}

impl Registry {
    pub fn replace(&self, instances: InstanceMap) {
        self.instances.store(Arc::new(instances));
    }

    pub fn snapshot(&self) -> Arc<InstanceMap> {
        self.instances.load_full()
    }

    pub fn merge_ordered<'a>(
        snapshots: impl IntoIterator<Item = (&'a str, &'a ProviderSnapshot)>,
    ) -> InstanceMap {
        let mut merged = HashMap::new();
        for (provider, snapshot) in snapshots {
            for (key, value) in &snapshot.instances {
                if merged.contains_key(key) {
                    tracing::error!(%provider, %key, "provider instance key collision; keeping earlier provider");
                } else {
                    merged.insert(key.clone(), value.clone());
                }
            }
        }
        merged
    }
}

#[async_trait]
impl InstanceResolver for Registry {
    async fn resolve(&self, key: &InstanceKey) -> Result<Option<Arc<Instance>>, ResolveError> {
        Ok(self.instances.load().get(key).cloned())
    }
}

#[async_trait]
impl InstanceResolver for InstanceMap {
    async fn resolve(&self, key: &InstanceKey) -> Result<Option<Arc<Instance>>, ResolveError> {
        Ok(self.get(key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientAuth, SecretString, UpstreamSpec};
    use url::Url;

    fn instance(key: &str) -> Arc<Instance> {
        Arc::new(Instance {
            key: InstanceKey::new(key).unwrap(),
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
            allowed_redirect_origins: vec![],
            default_redirect_uri: None,
        })
    }

    #[test]
    fn earlier_provider_wins_collision() {
        let key = InstanceKey::new("same").unwrap();
        let a = instance("same");
        let mut first = ProviderSnapshot::default();
        first.instances.insert(key.clone(), a.clone());
        let mut second = ProviderSnapshot::default();
        second.instances.insert(key.clone(), instance("same"));
        let merged = Registry::merge_ordered([("first", &first), ("second", &second)]);
        assert!(Arc::ptr_eq(merged.get(&key).unwrap(), &a));
    }
}
