# oauthmux — OAuth/OIDC Multiplexing Proxy

**Spec for initial implementation in this (empty) repository.**
Working names: repository/library crate `rise-oauth-multiplexer`, binary `oauthmux`. Names may be
finalized later; keep them confined to `Cargo.toml` metadata, the bin name, and the env-var prefix
so a rename is mechanical.

## 1. Mission

Build a reusable OAuth/OIDC multiplexing proxy in Rust. It gives an upstream OAuth provider
(Google, GitHub, Snowflake, Dex, any OIDC or plain-OAuth2 provider) **one stable callback URL**
per configured *instance*, and multiplexes that across many application redirect targets
(production, previews, localhost). It implements: authorization-code flow with PKCE, code
exchange, refresh-token proxying, OIDC discovery and JWKS proxying.

The design is **Traefik-shaped**: a core engine serves the flows; pluggable **config providers**
discover instance configuration from different sources (a YAML file, AWS SSM parameters, later
Kubernetes objects or a Rise control plane).

Two consumption modes, both first-class:

1. **Library** — a host application (concretely: the Rise backend,
   `github.com/rise-deploy/rise`) mounts the Axum routes and supplies its own dynamic
   instance-resolution trait impl. The crate API must make this replacement possible without the
   host importing anything but the core crate.
2. **Standalone binary** — a minimal single-binary server, shipped as a Docker image, that runs
   the same engine with config providers. A Lambda execution mode comes later; do not preclude it
   (see §10).

### Reference implementation

This project extracts and generalizes an existing, working implementation inside the Rise
codebase (`github.com/rise-deploy/rise`, branch `develop`). If that repo is accessible, **read it
first and port code from it** rather than re-deriving the protocol logic:

| Rise path | What to take |
| --- | --- |
| `src/server/extensions/providers/oauth/handlers.rs` | The five endpoint handlers: authorize, callback, token (incl. CORS/OPTIONS), OIDC discovery, JWKS. Port the flow logic; replace project/extension DB lookups with the `InstanceResolver` seam and the project-derived redirect check with the instance's explicit origin allow-list. |
| `src/server/extensions/providers/oauth/provider.rs` | OIDC endpoint discovery from `issuer_url` (`.well-known/openid-configuration`), upstream code exchange, refresh proxying, Rise-client-credential handling. |
| `src/server/extensions/providers/oauth/models.rs` | Type shapes: instance spec, transient flow state, `TokenRequest`/`OAuth2TokenResponse`/`OAuth2ErrorResponse` (RFC 6749 shapes), callback params. |
| `src/server/extensions/providers/oauth/routes.rs` | Route table (`/oidc/{project}/{extension}/…`) — the two-segment key shape the embedded host will keep using. |
| `docs/user/src/content/docs/user-guide/oauth.md` | The authoritative description of externally observable behavior. Treat this as the protocol contract. |

**Semantics to preserve exactly** (they are documented user-facing behavior in Rise):

- Authorization codes are single-use*, expire after **5 minutes**. State tokens expire after
  **10 minutes**. (*See §5 for the stateless relaxation.)
- PKCE method `S256` only.
- Loopback (`http://localhost:*`, `http://127.0.0.1:*`) redirect URIs are always allowed, for
  local development.
- Secret comparisons are constant-time (use the `subtle` crate).
- The token endpoint is RFC 6749-compliant: form-encoded request, JSON response, proper
  `error`/`error_description` bodies, CORS support (`POST` + preflight `OPTIONS`).
- Discovery responses rewrite upstream endpoint URLs to the proxy's own URLs; JWKS is proxied
  from upstream.
- The upstream token response is passed through faithfully on exchange (preserve body,
  content-type, and status from upstream rather than re-encoding lossily).

If the Rise repo is not accessible, implement from this spec plus the RFCs (6749, 7636, 7523);
the spec is self-sufficient.

## 2. Repository layout

Cargo workspace:

```
crates/
  oauthmux-core/          # engine: domain model, seams, Axum router, sealing, flows
  oauthmux-provider-file/ # YAML file config provider
  oauthmux-provider-ssm/  # AWS SSM Parameter Store config provider
  oauthmux/               # the binary: config loading, provider wiring, server runtime
Dockerfile
.github/workflows/ci.yml
README.md
SPEC.md                   # this file
```

Rules:

- `oauthmux-core` has **no** AWS, Kubernetes, or file-watching dependencies, and no `tokio`
  features beyond what Axum needs. It is the crate the Rise backend will depend on.
- Providers depend on core, never the reverse.
- The binary crate is thin: parse config, construct providers, run the server.
- Rust stable, edition 2021+. `cargo fmt` and `cargo clippy --workspace --all-targets
  -- -D warnings` must pass in CI. Suggested key dependencies: `axum`, `tokio`, `reqwest`
  (rustls), `serde`/`serde_yaml`, `chacha20poly1305` (or `aes-gcm`), `jsonwebtoken`, `subtle`,
  `arc-swap`, `tracing`, `aws-sdk-ssm` (provider crate only).

## 3. Core domain model (`oauthmux-core`)

```rust
/// Opaque instance address. The standalone binary uses one path segment
/// ("google"); an embedding host may map several segments onto it
/// ("my-app/oauth-google").
pub struct InstanceKey(String);

pub struct Instance {
    pub key: InstanceKey,
    pub upstream: UpstreamSpec,
    pub client_auth: ClientAuth,
    /// Exact origins (scheme + host + port) allowed as post-flow redirect
    /// targets, e.g. "https://app.example.com". Loopback origins are always
    /// implicitly allowed. No wildcards.
    pub allowed_redirect_origins: Vec<Origin>,
    /// Default redirect target when the authorize request names none.
    pub default_redirect_uri: Option<Url>,
}

pub struct UpstreamSpec {
    pub issuer_url: Url,
    /// Optional overrides for non-OIDC providers (GitHub etc.). When absent,
    /// resolved from {issuer_url}/.well-known/openid-configuration and cached
    /// with a TTL (~1h) per instance.
    pub authorization_endpoint: Option<Url>,
    pub token_endpoint: Option<Url>,
    pub jwks_uri: Option<Url>,
    pub client_id: String,
    pub client_secret: SecretString,   // resolved by the provider (§6)
    pub scopes: Vec<String>,
    /// Optional restriction for requested and configured default scopes.
    pub allowed_scopes: Option<Vec<String>>,
}

/// How the *application* authenticates to this proxy's /token endpoint.
pub enum ClientAuth {
    /// Public client: PKCE required, no client credential.
    Public,
    /// Confidential client with a shared secret (constant-time compare).
    ClientSecret { client_id: String, client_secret: SecretString },
    /// Confidential client presenting an RFC 7523 JWT assertion
    /// (`client_assertion_type=…:jwt-bearer`), verified against a public key.
    /// No client credential at rest. (Milestone M2.)
    PrivateKeyJwt { client_id: String, jwks: ClientJwks }, // inline JWKS or URL
}
```

### Trait seams

```rust
/// What the router consumes. Every request resolves the instance fresh —
/// no snapshot assumption — so a DB-backed host (Rise) can implement this
/// directly.
#[async_trait]
pub trait InstanceResolver: Send + Sync + 'static {
    async fn resolve(&self, key: &InstanceKey) -> Result<Option<Arc<Instance>>, ResolveError>;
}

/// Traefik-style config source. Emits full snapshots; the runtime merges
/// snapshots from all providers into a `Registry` (an `arc_swap` map) which
/// itself implements `InstanceResolver`. Push (watch) and poll providers both
/// fit: a poll provider re-emits on its interval.
#[async_trait]
pub trait ConfigProvider: Send + Sync + 'static {
    fn name(&self) -> &str;
    /// Long-running task: send a full snapshot of this provider's instances
    /// whenever they (may) have changed. First send completes startup readiness.
    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()>;
}

/// AEAD sealing for transient state (§5). Keyed, versioned, rotation-aware:
/// seal with the current key, unseal with current-then-previous.
pub trait Sealer: Send + Sync + 'static { /* seal(&[u8]) -> String; unseal(&str) -> Result<Vec<u8>> */ }

/// Optional replay cache restoring strict single-use codes (§5).
#[async_trait]
pub trait ReplayCache: Send + Sync + 'static {
    /// Returns true the first time a given envelope id is seen, false after.
    async fn first_use(&self, id: &str, ttl: Duration) -> Result<bool, CacheError>;
}
```

Merge rule for multiple providers: instance keys are namespaced per provider run only if they
collide; on collision, **log an error and keep the instance from the earlier-configured
provider** (deterministic order = configuration order). Never silently pick one.

### Router / embedding API

```rust
pub struct MuxConfig {
    pub public_url: Url,              // external base URL of this proxy
    pub sealer: Arc<dyn Sealer>,
    pub replay_cache: Option<Arc<dyn ReplayCache>>,
    pub http: reqwest::Client,        // injected so hosts control TLS/proxy settings
}

/// One wildcard route set; the KeyStrategy maps matched path segments to an
/// InstanceKey. `SingleSegment` serves the standalone binary
/// (`/oidc/{instance}/…`); `TwoSegment` serves the Rise embedding
/// (`/oidc/{project}/{extension}/…`, key = "{project}/{extension}");
/// `Custom(fn)` covers anything else.
pub enum KeyStrategy { SingleSegment, TwoSegment, Custom(Arc<dyn Fn(&[&str]) -> Option<InstanceKey> + Send + Sync>) }

pub fn router(resolver: Arc<dyn InstanceResolver>, cfg: MuxConfig, keys: KeyStrategy)
    -> axum::Router;   // nestable: host mounts it at any prefix
```

Acceptance for the embedding mode: a doc-tested example in `oauthmux-core` that mounts the router
with `TwoSegment` and a `HashMap`-backed resolver — this is the exact shape Rise will use.

## 4. HTTP endpoints

All under the mounted prefix, per instance key `K` (shown single-segment):

| Route | Behavior |
| --- | --- |
| `GET /oidc/{K}/authorize` | Validates the application redirect and downstream PKCE, seals application state, and generates independent upstream state and PKCE. oauthmux replaces `client_id`, `redirect_uri`, `state`, `code_challenge`, and `code_challenge_method`; constrains the flow to authorization code with query response mode; and forwards the remaining query pairs. A supplied `scope` is preserved subject to `allowed_scopes`; configured `scopes` is the fallback. OIDC request objects are rejected. |
| `GET /oidc/{K}/callback` | Unseals and validates state (TTL 10 min, instance key match), exchanges the upstream code with the upstream credentials and PKCE verifier, and seals the raw token response into the application code. The application receives its original state and all non-owned upstream response parameters. |
| `POST /oidc/{K}/token` | Form-encoded, RFC 6749. `authorization_code` authenticates the application, validates TTL/replay/redirect/PKCE, and returns the stored upstream response verbatim. `refresh_token` authenticates the application, preserves grant extensions, replaces downstream client authentication with upstream credentials, and relays the upstream response. CORS reflects allowed origins and supports preflight `OPTIONS`. |
| `GET /oidc/{K}/.well-known/openid-configuration` | Fetch upstream discovery (if OIDC), rewrite `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` to `{public_url}/oidc/{K}/…`. For non-OIDC instances, synthesize a minimal document from the configured endpoints. |
| `GET /oidc/{K}/jwks` | Proxy upstream JWKS (cache ~10 min). 404 for instances with no JWKS. |
| `GET /healthz` | Liveness (binary only, not part of the embeddable router). |
| `GET /readyz` | Ready once every configured provider has delivered its first snapshot (binary only). |

Unknown instance keys → 404 with an RFC 6749-style error body on `/token`, plain 404 elsewhere.
Never reflect unvalidated `redirect_uri` values into responses (open-redirect defense).

## 5. Transient state: sealed envelopes (stateless-ish)

No database. Both transient records are AEAD envelopes (XChaCha20-Poly1305 or AES-256-GCM)
sealed by the `Sealer`:

- **Flow-state envelope** — carried through the upstream round-trip in the `state` parameter:
  `{instance_key, app_redirect_uri, app_state, upstream_pkce_verifier, client_code_challenge?,
  client_code_challenge_method?, issued_at, nonce}`. TTL 10 minutes, enforced at unseal.
- **Authorization-code envelope** — *is* the code handed to the application:
  `{instance_key, envelope_id (random 128-bit), issued_at, redirect_uri, client_code_challenge?,
  upstream_response: {status, content_type, body}}`. TTL 5 minutes.

Envelope format: `v1.<base64url(nonce || ciphertext || tag)>`; the instance key is bound as AEAD
associated data. Mind URL practicality: envelopes travel in query strings — keep serialization
compact (serde + a compact binary format such as `postcard`), and document that very large
upstream token responses can exceed URL limits (log a warning above ~4 KB sealed).

**Single-use caveat (must be documented in the README):** without a `ReplayCache`, "single-use"
degrades to "valid for 5 minutes". Ship an in-memory `ReplayCache` (per-replica, enabled by
default in the binary) and leave Redis/etc. to future provider crates. The Rise embedding can
back `ReplayCache` with its existing table if desired.

**Keys & rotation:** the binary takes `OAUTHMUX_SEAL_KEY` (base64, 32 bytes) plus optional
`OAUTHMUX_SEAL_KEY_PREVIOUS` for rotation. Refuse to start without a key; refuse a key of the
wrong length. Never log key material or envelope plaintexts.

## 6. Config providers

### 6.1 File provider (`oauthmux-provider-file`) — Milestone M1

Reads one YAML file, default `/etc/oauthmux/config.yaml` (path configurable). Schema:

```yaml
instances:
  google:
    issuer_url: https://accounts.google.com
    client_id: 1234.apps.googleusercontent.com
    client_secret: ${GOOGLE_SECRET}          # env interpolation
    # client_secret_file: /run/secrets/google  # or file indirection
    scopes: [openid, email, profile]
    allowed_redirect_origins: [https://app.example.com]
    default_redirect_uri: https://app.example.com/
    client_auth:
      mode: public                            # public | client_secret | private_key_jwt
  github:
    issuer_url: https://github.com
    authorization_endpoint: https://github.com/login/oauth/authorize
    token_endpoint: https://github.com/login/oauth/access_token
    client_id: Iv1.abc
    client_secret_file: /run/secrets/github
    scopes: [read:user, user:email]
    allowed_redirect_origins: [https://app.example.com]
    client_auth:
      mode: client_secret
      client_id: my-app
      client_secret: ${MUX_GITHUB_CLIENT_SECRET}
```

Rules: `client_secret` XOR `client_secret_file`, exactly one. `${VAR}` interpolation resolves
from the process environment at load time; a missing variable is a hard error naming the variable
(never the value). Hot-reload: poll mtime every 30 s (configurable); an invalid file logs an
error and **keeps the last good snapshot**. Validation errors name the instance and field.

### 6.2 SSM provider (`oauthmux-provider-ssm`) — Milestone M1/M2

Discovers instances under a parameter prefix, default shape: one parameter per instance,
`{prefix}{instance-key}` (e.g. `/oauthmux/instances/google`), value = the same YAML/JSON
document as one file-provider instance entry (secrets inline — SSM `SecureString` is the secret
store, so `client_secret` plaintext-in-parameter is the expected form; `client_secret_file` is
rejected here).

- Enumerate with `GetParametersByPath` (recursive, `WithDecryption=true`), handling pagination.
- Poll on an interval (default 60 s, configurable). Diffing is unnecessary — emit the snapshot;
  the registry swap is cheap.
- Region/credentials from the default AWS provider chain. Required IAM (document in README):
  `ssm:GetParametersByPath` on the prefix, `kms:Decrypt` on the key encrypting the parameters.
- A malformed parameter fails **that instance** (logged with the parameter name), not the
  snapshot.
- Unit-test the parsing/merge logic against a mocked SSM trait; do not require live AWS in CI.

### 6.3 Future providers (do not implement; do not preclude)

Kubernetes (ConfigMap/CRD watch), Rise control plane (resource API), env-var-only single
instance. The `ConfigProvider` trait is the only contract they need.

## 7. Standalone binary (`oauthmux`)

Env-first configuration (prefix `OAUTHMUX_`):

```
OAUTHMUX_PUBLIC_URL=https://auth.example.com     # required
OAUTHMUX_SEAL_KEY=base64:…                       # required, 32 bytes
OAUTHMUX_SEAL_KEY_PREVIOUS=base64:…              # optional, rotation
OAUTHMUX_LISTEN=0.0.0.0:8080                     # default
OAUTHMUX_PROVIDER_FILE=/etc/oauthmux/config.yaml # enables file provider
OAUTHMUX_PROVIDER_FILE_POLL=30s
OAUTHMUX_PROVIDER_SSM_PREFIX=/oauthmux/instances/ # enables SSM provider
OAUTHMUX_PROVIDER_SSM_POLL=60s
OAUTHMUX_LOG=info                                # tracing filter
```

At least one provider must be enabled or startup fails with a clear message. Routes:
`/oidc/{instance}/…` (SingleSegment), `/healthz`, `/readyz`. Structured logs via
`tracing-subscriber` (JSON when not a TTY). Graceful shutdown on SIGTERM/SIGINT. No config
file for the binary itself — env only.

## 8. Docker image

Multi-stage build to a single static binary:

- Build stage: `rust:<pinned>` with `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl`.
- Final stage: `scratch` (or `gcr.io/distroless/static` if scratch fights you) containing the
  binary + CA certificates (`/etc/ssl/certs/ca-certificates.crt` — reqwest/rustls needs roots
  for upstream calls). Non-root user. `EXPOSE 8080`, `ENTRYPOINT ["/oauthmux"]`.
- CI builds `linux/amd64` and `linux/arm64` via buildx. Target image size: tens of MB.

## 9. Testing & acceptance

- **Unit:** envelope seal/unseal round-trip, TTL expiry, key rotation (previous-key unseal),
  tamper rejection; redirect-origin validation incl. loopback and open-redirect attempts; PKCE
  S256 verification; client-secret constant-time auth; provider YAML parsing incl. every
  validation error path; snapshot merge + collision rule.
- **Integration (in CI, no external services):** an in-process signed OIDC fixture exercises
  public and confidential clients, request relay, scope policy, refresh, nonce and ID-token trust,
  replay, redirect validation, discovery, and two-segment embedding. Google and Cognito behavior
  is expressed as small profiles over the generic fixture.
- **End to end:** a pinned Dex container and the standalone oauthmux process run the complete
  authorization-code, ID-token validation, refresh, replay, and redirect-policy flow through
  `mise run e2e`.
- **CI:** fmt check, clippy `-D warnings`, in-process tests, Dex E2E, and Docker build.

## 10. Milestones

1. **M1 — core + file provider + binary.** Workspace, core engine (flows, sealing, router,
   `Public` + `ClientSecret` auth), file provider with hot-reload, binary with env config,
   mock-IdP integration suite, README with quickstart.
2. **M2 — SSM provider + private_key_jwt.** SSM discovery per §6.2; `PrivateKeyJwt` client auth
   (RFC 7523 assertion verification, inline JWKS and JWKS URL with caching).
3. **M3 — image + release.** Dockerfile per §8, multi-arch CI publish, versioned release
   workflow, operator docs (IAM policy snippet, key rotation runbook, replay-cache caveat).
4. **M4 (stretch, do not start unasked) — Lambda mode.** `lambda` feature on the binary crate
   using `lambda_http` over the same router. Design constraint honored throughout: no background
   state beyond the provider registry; providers must tolerate load-once-per-cold-start usage.

## 11. Non-goals

- No database, no user sessions, no UI, no token storage after exchange (applications own their
  tokens).
- No Rise types or Rise-specific behavior in any crate here; the Rise migration to this crate
  happens in the Rise repository, later, against the §3 embedding API.
- No wildcard redirect origins, no PKCE `plain`, no implicit grant.
