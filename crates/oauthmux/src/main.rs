use anyhow::{anyhow, Context};
#[cfg(feature = "lambda")]
use axum::{
    extract::{Request, State},
    middleware::{self, Next},
    response::Response,
};
use axum::{http::StatusCode, routing::get, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use oauthmux_core::{
    resource_schema, router, ConfigProvider, KeyStrategy, MemoryReplayCache, MuxConfig,
    ProviderSnapshot, Registry, XChaChaSealer,
};
use oauthmux_provider_file::FileProvider;
use oauthmux_provider_ssm::{AwsSecretsManagerClient, AwsSsmClient, SsmProvider};
#[cfg(feature = "lambda")]
use std::time::SystemTime;
use std::{
    env,
    io::IsTerminal,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::watch;
#[cfg(feature = "lambda")]
use tokio::sync::Mutex;
use url::Url;

struct RunningProvider {
    name: String,
    #[cfg(feature = "lambda")]
    provider: Arc<dyn ConfigProvider>,
    rx: watch::Receiver<ProviderSnapshot>,
    #[cfg(feature = "lambda")]
    task: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "lambda")]
struct LambdaProvider {
    name: String,
    provider: Arc<dyn ConfigProvider>,
    snapshot: ProviderSnapshot,
}

#[cfg(feature = "lambda")]
struct LambdaRefreshState {
    // Wall time includes intervals while Lambda has frozen the process.
    last_attempt: SystemTime,
    providers: Vec<LambdaProvider>,
}

#[cfg(feature = "lambda")]
struct LambdaConfigRefresher {
    registry: Arc<Registry>,
    ttl: Duration,
    state: Mutex<LambdaRefreshState>,
}

#[cfg(feature = "lambda")]
const DEFAULT_LAMBDA_CONFIG_TTL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if env::args().nth(1).as_deref() == Some("schema") {
        println!("{}", serde_json::to_string_pretty(&resource_schema())?);
        return Ok(());
    }
    init_tracing();
    let public_url = required_url("OAUTHMUX_PUBLIC_URL")?;
    let current = seal_key("OAUTHMUX_SEAL_KEY", true)?.expect("required key");
    let previous = seal_key("OAUTHMUX_SEAL_KEY_PREVIOUS", false)?;
    let sealer = Arc::new(XChaChaSealer::new(&current, previous.as_deref())?);
    let providers = configured_providers().await?;
    if providers.is_empty() {
        return Err(anyhow!(
            "at least one provider is required; set OAUTHMUX_PROVIDER_FILE or OAUTHMUX_PROVIDER_SSM_PREFIX"
        ));
    }
    let registry = Arc::new(Registry::default());
    let mut running = start_providers(providers);
    await_initial_snapshots(&mut running).await?;
    replace_registry(&registry, &running);

    let mux = router(
        registry.clone(),
        MuxConfig {
            public_url,
            sealer,
            replay_cache: Some(Arc::new(MemoryReplayCache::default())),
            http: reqwest::Client::builder().build()?,
        },
        KeyStrategy::SingleSegment,
    );
    let ready = Arc::new(AtomicBool::new(true));
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route(
            "/readyz",
            get({
                let ready = ready.clone();
                move || async move {
                    if ready.load(Ordering::Relaxed) {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }
            }),
        )
        .merge(mux);

    if is_lambda_runtime() {
        #[cfg(feature = "lambda")]
        {
            // Lambda refreshes providers at invocation boundaries because it freezes between requests.
            let refresh_ttl =
                duration_env("OAUTHMUX_LAMBDA_CONFIG_TTL", DEFAULT_LAMBDA_CONFIG_TTL)?;
            let refresher = Arc::new(LambdaConfigRefresher::new(registry, running, refresh_ttl));
            let app = app.layer(middleware::from_fn_with_state(
                refresher,
                refresh_lambda_config,
            ));
            tracing::info!("starting AWS Lambda runtime");
            lambda_http::run(app)
                .await
                .map_err(|error| anyhow!("Lambda runtime failed: {error}"))?;
            return Ok(());
        }
        #[cfg(not(feature = "lambda"))]
        return Err(anyhow!("binary was built without the lambda feature"));
    }

    let updater = spawn_registry_updater(registry, running);
    let listen = env::var("OAUTHMUX_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    tracing::info!(%listen, "oauthmux ready");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    updater.abort();
    Ok(())
}

async fn configured_providers() -> anyhow::Result<Vec<Arc<dyn ConfigProvider>>> {
    let mut providers: Vec<Arc<dyn ConfigProvider>> = Vec::new();
    if let Ok(path) = env::var("OAUTHMUX_PROVIDER_FILE") {
        providers.push(Arc::new(FileProvider::new(
            path,
            duration_env("OAUTHMUX_PROVIDER_FILE_POLL", Duration::from_secs(30))?,
        )?));
    }
    if let Ok(prefix) = env::var("OAUTHMUX_PROVIDER_SSM_PREFIX") {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Arc::new(AwsSsmClient(aws_sdk_ssm_client(&config)));
        let secrets_manager = Arc::new(AwsSecretsManagerClient(
            aws_sdk_secretsmanager::Client::new(&config),
        ));
        providers.push(Arc::new(SsmProvider::new(
            client,
            secrets_manager,
            prefix,
            duration_env("OAUTHMUX_PROVIDER_SSM_POLL", Duration::from_secs(60))?,
        )?));
    }
    Ok(providers)
}

fn aws_sdk_ssm_client(config: &aws_config::SdkConfig) -> aws_sdk_ssm::Client {
    aws_sdk_ssm::Client::new(config)
}

fn start_providers(providers: Vec<Arc<dyn ConfigProvider>>) -> Vec<RunningProvider> {
    providers
        .into_iter()
        .map(|provider| {
            let name = provider.name().to_owned();
            let (tx, rx) = watch::channel(ProviderSnapshot::default());
            let log_name = name.clone();
            let task_provider = provider.clone();
            let task = tokio::spawn(async move {
                if let Err(error) = task_provider.run(tx).await {
                    tracing::error!(provider = %log_name, %error, "config provider stopped");
                }
            });
            #[cfg(not(feature = "lambda"))]
            drop(task);
            RunningProvider {
                name,
                #[cfg(feature = "lambda")]
                provider,
                rx,
                #[cfg(feature = "lambda")]
                task,
            }
        })
        .collect()
}

#[cfg(feature = "lambda")]
impl LambdaConfigRefresher {
    fn new(registry: Arc<Registry>, providers: Vec<RunningProvider>, ttl: Duration) -> Self {
        let providers = providers
            .into_iter()
            .map(|running| {
                running.task.abort();
                LambdaProvider {
                    name: running.name,
                    provider: running.provider,
                    snapshot: running.rx.borrow().clone(),
                }
            })
            .collect();
        Self {
            registry,
            ttl,
            state: Mutex::new(LambdaRefreshState {
                last_attempt: SystemTime::now(),
                providers,
            }),
        }
    }

    async fn refresh_if_stale(&self) {
        let mut state = self.state.lock().await;
        let is_fresh = SystemTime::now()
            .duration_since(state.last_attempt)
            .is_ok_and(|age| age < self.ttl);
        if is_fresh {
            return;
        }
        state.last_attempt = SystemTime::now();

        for provider in &mut state.providers {
            match provider.provider.load().await {
                Ok(snapshot) => provider.snapshot = snapshot,
                Err(error) => {
                    tracing::error!(
                        provider = %provider.name,
                        %error,
                        "Lambda provider refresh failed; keeping last good snapshot"
                    );
                }
            }
        }

        let snapshots: Vec<_> = state
            .providers
            .iter()
            .map(|provider| (provider.name.as_str(), &provider.snapshot))
            .collect();
        self.registry.replace(Registry::merge_ordered(
            snapshots.iter().map(|(name, snapshot)| (*name, *snapshot)),
        ));
    }
}

#[cfg(feature = "lambda")]
async fn refresh_lambda_config(
    State(refresher): State<Arc<LambdaConfigRefresher>>,
    request: Request,
    next: Next,
) -> Response {
    refresher.refresh_if_stale().await;
    next.run(request).await
}

async fn await_initial_snapshots(providers: &mut [RunningProvider]) -> anyhow::Result<()> {
    for provider in providers {
        provider.rx.changed().await.with_context(|| {
            format!(
                "provider {} stopped before its first snapshot",
                provider.name
            )
        })?;
    }
    Ok(())
}

fn replace_registry(registry: &Registry, providers: &[RunningProvider]) {
    let snapshots: Vec<_> = providers
        .iter()
        .map(|provider| (provider.name.as_str(), provider.rx.borrow().clone()))
        .collect();
    registry.replace(Registry::merge_ordered(
        snapshots.iter().map(|(name, snapshot)| (*name, snapshot)),
    ));
}

fn spawn_registry_updater(
    registry: Arc<Registry>,
    mut providers: Vec<RunningProvider>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let mut changed = false;
            for provider in &mut providers {
                match provider.rx.has_changed() {
                    Ok(true) => {
                        provider.rx.borrow_and_update();
                        changed = true;
                    }
                    Ok(false) => {}
                    Err(_) => {}
                }
            }
            if changed {
                replace_registry(&registry, &providers);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}

fn required_url(name: &str) -> anyhow::Result<Url> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    let url = Url::parse(&value).with_context(|| format!("{name} must be a URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(anyhow!("{name} must be an absolute http(s) URL"));
    }
    Ok(url)
}

fn seal_key(name: &str, required: bool) -> anyhow::Result<Option<Vec<u8>>> {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(_) if required => return Err(anyhow!("{name} is required")),
        Err(_) => return Ok(None),
    };
    let encoded = value.strip_prefix("base64:").unwrap_or(&value);
    let bytes = STANDARD
        .decode(encoded)
        .with_context(|| format!("{name} must be base64"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{name} must decode to exactly 32 bytes"));
    }
    Ok(Some(bytes))
}

fn duration_env(name: &str, default: Duration) -> anyhow::Result<Duration> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    parse_duration(name, &value)
}

fn parse_duration(name: &str, value: &str) -> anyhow::Result<Duration> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1_u64)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else {
        return Err(anyhow!("{name} must use ms, s, or m units"));
    };
    let millis: u64 = number.parse().with_context(|| format!("invalid {name}"))?;
    let duration = Duration::from_millis(millis.saturating_mul(multiplier));
    if duration.is_zero() {
        return Err(anyhow!("{name} must be greater than zero"));
    }
    Ok(duration)
}

fn is_lambda_runtime() -> bool {
    env::var_os("AWS_LAMBDA_RUNTIME_API").is_some()
}

fn init_tracing() {
    let filter = env::var("OAUTHMUX_LOG").unwrap_or_else(|_| "info".into());
    let builder =
        tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(filter));
    if std::io::stdout().is_terminal() {
        builder.compact().init();
    } else {
        builder.json().init();
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "lambda")]
    use async_trait::async_trait;
    #[cfg(feature = "lambda")]
    use oauthmux_core::{ClientAuth, Relay, ResourceKey, SecretString, Upstream};

    #[cfg(feature = "lambda")]
    use std::sync::atomic::AtomicUsize;

    #[cfg(feature = "lambda")]
    struct ReloadingProvider {
        loads: AtomicUsize,
    }

    #[cfg(feature = "lambda")]
    fn snapshot(key_text: &str) -> ProviderSnapshot {
        let key = ResourceKey::new(key_text).unwrap();
        let upstream = Arc::new(Upstream {
            key: key.clone(),
            issuer_url: Url::parse("https://issuer.example").unwrap(),
            authorization_endpoint: Some(Url::parse("https://issuer.example/authorize").unwrap()),
            token_endpoint: Some(Url::parse("https://issuer.example/token").unwrap()),
            jwks_uri: None,
            client_id: "upstream".into(),
            client_secret: SecretString::new("secret"),
        });
        let relay = Arc::new(Relay {
            key: key.clone(),
            upstream: key.clone(),
            client_auth: ClientAuth::Public,
            scopes: vec![],
            allowed_scopes: None,
            allowed_redirect_origins: vec![],
            default_redirect_uri: None,
        });
        let mut snapshot = ProviderSnapshot::default();
        snapshot.upstreams.insert(key.clone(), upstream);
        snapshot.relays.insert(key, relay);
        snapshot
    }

    #[cfg(feature = "lambda")]
    #[async_trait]
    impl ConfigProvider for ReloadingProvider {
        fn name(&self) -> &str {
            "reload-test"
        }

        async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
            match self.loads.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(snapshot("initial")),
                1 => Ok(snapshot("refreshed")),
                _ => Err(anyhow!("refresh failed")),
            }
        }

        async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()> {
            tx.send(self.load().await?)?;
            std::future::pending().await
        }
    }

    #[test]
    fn durations_require_units_and_positive_values() {
        assert_eq!(
            parse_duration("TEST", "2s").unwrap(),
            Duration::from_secs(2)
        );
        assert!(parse_duration("TEST", "0s").is_err());
    }

    #[cfg(feature = "lambda")]
    #[tokio::test]
    async fn lambda_refreshes_stale_configuration_and_keeps_last_good_snapshot() {
        let registry = Arc::new(Registry::default());
        let provider = Arc::new(ReloadingProvider {
            loads: AtomicUsize::new(0),
        });
        let mut providers = start_providers(vec![provider]);
        await_initial_snapshots(&mut providers).await.unwrap();
        replace_registry(&registry, &providers);
        let refresher =
            LambdaConfigRefresher::new(registry.clone(), providers, DEFAULT_LAMBDA_CONFIG_TTL);
        refresher.refresh_if_stale().await;
        assert!(registry
            .snapshot()
            .relays
            .contains_key(&ResourceKey::new("initial").unwrap()));

        refresher.state.lock().await.last_attempt = SystemTime::now() - DEFAULT_LAMBDA_CONFIG_TTL;
        refresher.refresh_if_stale().await;
        assert!(registry
            .snapshot()
            .relays
            .contains_key(&ResourceKey::new("refreshed").unwrap()));

        refresher.state.lock().await.last_attempt = SystemTime::now() - DEFAULT_LAMBDA_CONFIG_TTL;
        refresher.refresh_if_stale().await;
        assert!(registry
            .snapshot()
            .relays
            .contains_key(&ResourceKey::new("refreshed").unwrap()));
        assert_eq!(DEFAULT_LAMBDA_CONFIG_TTL, Duration::from_secs(60));
    }
}
