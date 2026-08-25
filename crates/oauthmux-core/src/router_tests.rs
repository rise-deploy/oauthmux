use super::*;
use crate::{
    ClientAuth, InstanceMap, MemoryReplayCache, Origin, SecretString, UpstreamSpec, XChaChaSealer,
};
use axum::{
    body::Body,
    extract::{Query, State},
    http::Request,
    routing::{get, post},
};
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::{
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use std::collections::HashMap;
use tower::ServiceExt;

#[derive(Clone)]
struct MockIdpState {
    base: Url,
}

async fn mock_discovery(State(state): State<MockIdpState>) -> Json<Value> {
    Json(json!({
        "issuer": state.base,
        "authorization_endpoint": state.base.join("authorize").unwrap(),
        "token_endpoint": state.base.join("token").unwrap(),
        "jwks_uri": state.base.join("jwks").unwrap(),
        "custom_field": "preserved"
    }))
}

async fn mock_authorize(Query(query): Query<HashMap<String, String>>) -> Response {
    let mut callback = Url::parse(query.get("redirect_uri").unwrap()).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", "upstream-code")
        .append_pair("state", query.get("state").unwrap());
    found(callback.as_str())
}

async fn mock_token(body: String) -> Response {
    if body.contains("grant_type=refresh_token") {
        return Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(header::CONTENT_TYPE, "application/vnd.oauth-refresh+json")
            .body(Body::from(
                r#"{"access_token":"refreshed","token_type":"Bearer"}"#,
            ))
            .unwrap();
    }
    Response::builder()
        .status(StatusCode::CREATED)
        .header(header::CONTENT_TYPE, "application/vnd.oauth-token+json")
        .body(Body::from(
            r#"{"access_token":"access","refresh_token":"refresh","token_type":"Bearer"}"#,
        ))
        .unwrap()
}

async fn mock_jwks() -> Json<Value> {
    Json(json!({ "keys": [] }))
}

async fn setup(
    key: &str,
    auth: ClientAuth,
    strategy: KeyStrategy,
) -> (Router, Arc<XChaChaSealer>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = Url::parse(&format!("http://{address}/")).unwrap();
    let idp = Router::new()
        .route("/.well-known/openid-configuration", get(mock_discovery))
        .route("/authorize", get(mock_authorize))
        .route("/token", post(mock_token))
        .route("/jwks", get(mock_jwks))
        .with_state(MockIdpState { base: base.clone() });
    let task = tokio::spawn(async move { axum::serve(listener, idp).await.unwrap() });

    let key = InstanceKey::new(key).unwrap();
    let instance = Arc::new(Instance {
        key: key.clone(),
        upstream: UpstreamSpec {
            issuer_url: base,
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            client_id: "upstream-client".into(),
            client_secret: SecretString::new("upstream-secret"),
            scopes: vec!["openid".into(), "email".into()],
        },
        client_auth: auth,
        allowed_redirect_origins: vec![Origin::parse("https://app.example").unwrap()],
        default_redirect_uri: Some(Url::parse("https://app.example/callback").unwrap()),
    });
    let mut instances = InstanceMap::new();
    instances.insert(key, instance);
    let sealer = Arc::new(XChaChaSealer::new(&[7_u8; 32], None).unwrap());
    let app = router(
        Arc::new(instances),
        MuxConfig {
            public_url: Url::parse("https://mux.example/").unwrap(),
            sealer: sealer.clone(),
            replay_cache: Some(Arc::new(MemoryReplayCache::default())),
            http: reqwest::Client::new(),
        },
        strategy,
    );
    (app, sealer, task)
}

async fn response_body(response: Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

async fn authorization_code(app: &Router, path_key: &str, challenge: Option<&str>) -> String {
    let mut uri = format!(
        "/oidc/{path_key}/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=app-state"
    );
    if let Some(challenge) = challenge {
        uri.push_str("&code_challenge=");
        uri.push_str(challenge);
        uri.push_str("&code_challenge_method=S256");
    }
    let authorize = app
        .clone()
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(authorize.status(), StatusCode::FOUND);
    let upstream_location = authorize.headers()[header::LOCATION].to_str().unwrap();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let upstream = client.get(upstream_location).send().await.unwrap();
    assert_eq!(upstream.status(), StatusCode::FOUND);
    let callback = Url::parse(upstream.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let local_callback = format!("{}?{}", callback.path(), callback.query().unwrap());
    let callback_response = app
        .clone()
        .oneshot(Request::get(local_callback).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(callback_response.status(), StatusCode::FOUND);
    let app_redirect = Url::parse(
        callback_response.headers()[header::LOCATION]
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        app_redirect
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1,
        "app-state"
    );
    app_redirect
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned()
}

async fn post_token(app: &Router, path_key: &str, form: &str) -> Response {
    app.clone()
        .oneshot(
            Request::post(format!("/oidc/{path_key}/token"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, "https://app.example")
                .body(Body::from(form.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn public_pkce_flow_preserves_upstream_response_and_rejects_replay() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let verifier = "a-public-verifier-with-enough-entropy-123456789";
    let challenge = pkce_challenge(verifier);
    let code = authorization_code(&app, "google", Some(&challenge)).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", verifier),
    ])
    .unwrap();
    let response = post_token(&app, "google", &form).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.oauth-token+json"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://app.example"
    );
    assert!(String::from_utf8(response_body(response).await)
        .unwrap()
        .contains("access"));
    let replay = post_token(&app, "google", &form).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(String::from_utf8(response_body(replay).await)
        .unwrap()
        .contains("already used"));
    task.abort();
}

#[tokio::test]
async fn confidential_flow_and_refresh_authenticate_client_secret() {
    let auth = ClientAuth::ClientSecret {
        client_id: "application".into(),
        client_secret: SecretString::new("application-secret"),
    };
    let (app, _, task) = setup("github", auth, KeyStrategy::SingleSegment).await;
    let code = authorization_code(&app, "github", None).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("client_id", "application"),
        ("client_secret", "application-secret"),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "github", &form).await.status(),
        StatusCode::CREATED
    );
    let refresh = serde_urlencoded::to_string([
        ("grant_type", "refresh_token"),
        ("refresh_token", "refresh"),
        ("client_id", "application"),
        ("client_secret", "application-secret"),
    ])
    .unwrap();
    let response = post_token(&app, "github", &refresh).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.oauth-refresh+json"
    );
    let invalid = refresh.replace("application-secret", "wrong");
    assert_eq!(
        post_token(&app, "github", &invalid).await.status(),
        StatusCode::UNAUTHORIZED
    );
    task.abort();
}

#[tokio::test]
async fn expired_code_and_invalid_redirect_are_rejected() {
    let (app, sealer, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let invalid = app.clone().oneshot(
        Request::get("/oidc/google/authorize?redirect_uri=https%3A%2F%2Fapp.example.evil.test%2Fcb&code_challenge=x&code_challenge_method=S256")
            .body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let expired = CodeEnvelope {
        instance_key: "google".into(),
        envelope_id: [9; 16],
        issued_at: unix_now() - CODE_TTL - 1,
        redirect_uri: "https://app.example/callback".into(),
        client_code_challenge: Some(pkce_challenge("verifier")),
        upstream_response: StoredResponse {
            status: 200,
            content_type: None,
            body: vec![],
        },
    };
    let code = sealer
        .seal(&postcard::to_stdvec(&expired).unwrap(), b"google")
        .unwrap();
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", "verifier"),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "google", &form).await.status(),
        StatusCode::BAD_REQUEST
    );

    let expired_flow = FlowEnvelope {
        instance_key: "google".into(),
        app_redirect_uri: "https://app.example/callback".into(),
        app_state: None,
        upstream_pkce_verifier: "upstream-verifier".into(),
        client_code_challenge: Some(pkce_challenge("verifier")),
        client_code_challenge_method: Some("S256".into()),
        issued_at: unix_now() - FLOW_TTL - 1,
        nonce: [4; 16],
    };
    let state = sealer
        .seal(&postcard::to_stdvec(&expired_flow).unwrap(), b"google")
        .unwrap();
    let callback = app
        .clone()
        .oneshot(
            Request::get(format!("/oidc/google/callback?code=upstream&state={state}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    task.abort();
}

#[tokio::test]
async fn upstream_authorization_errors_relay_only_to_validated_redirect() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let challenge = pkce_challenge("an-application-verifier-with-at-least-forty-three-characters");
    let authorize = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/oidc/google/authorize?state=application&code_challenge={challenge}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let upstream = Url::parse(authorize.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let state = upstream
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let response = app
        .oneshot(
            Request::get(format!(
                "/oidc/google/callback?error=access_denied&error_description=declined&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let redirect = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(redirect.host_str(), Some("app.example"));
    assert!(redirect.query().unwrap().contains("error=access_denied"));
    assert!(redirect.query().unwrap().contains("state=application"));
    task.abort();
}

#[tokio::test]
async fn discovery_and_jwks_are_rewritten_and_proxied() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let response = app
        .clone()
        .oneshot(
            Request::get("/oidc/google/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response_body(response).await).unwrap();
    assert_eq!(value["issuer"], "https://mux.example/oidc/google");
    assert_eq!(
        value["authorization_endpoint"],
        "https://mux.example/oidc/google/authorize"
    );
    assert_eq!(
        value["token_endpoint"],
        "https://mux.example/oidc/google/token"
    );
    assert_eq!(value["jwks_uri"], "https://mux.example/oidc/google/jwks");
    assert_eq!(value["custom_field"], "preserved");
    let jwks = app
        .oneshot(
            Request::get("/oidc/google/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
    task.abort();
}

#[tokio::test]
async fn token_preflight_reflects_only_an_allowed_origin() {
    let (app, _, task) = setup("google", ClientAuth::Public, KeyStrategy::SingleSegment).await;
    let allowed = app
        .clone()
        .oneshot(
            Request::options("/oidc/google/token")
                .header(header::ORIGIN, "https://app.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        allowed.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "POST, OPTIONS"
    );
    let denied = app
        .oneshot(
            Request::options("/oidc/google/token")
                .header(header::ORIGIN, "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(!denied
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    task.abort();
}

#[tokio::test]
async fn two_segment_embedding_runs_the_same_flow() {
    let (app, _, task) = setup(
        "project/google",
        ClientAuth::Public,
        KeyStrategy::TwoSegment,
    )
    .await;
    let verifier = "two-segment-verifier-with-at-least-forty-three-characters";
    let code = authorization_code(&app, "project/google", Some(&pkce_challenge(verifier))).await;
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("code_verifier", verifier),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "project/google", &form).await.status(),
        StatusCode::CREATED
    );
    task.abort();
}

#[tokio::test]
async fn private_key_jwt_authenticates_a_signed_assertion() {
    let private = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": "application-key",
            "alg": "RS256",
            "use": "sig",
            "n": URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())
        }]
    });
    let auth = ClientAuth::PrivateKeyJwt {
        client_id: "jwt-application".into(),
        jwks: ClientJwks::Inline(jwks),
    };
    let (app, _, task) = setup("jwt", auth, KeyStrategy::SingleSegment).await;
    let code = authorization_code(&app, "jwt", None).await;
    let claims = json!({
        "iss": "jwt-application",
        "sub": "jwt-application",
        "aud": "https://mux.example/oidc/jwt/token",
        "exp": unix_now() + 60,
        "iat": unix_now(),
        "jti": "unique-assertion"
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("application-key".into());
    let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
    let assertion = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "https://app.example/callback"),
        ("client_id", "jwt-application"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
    ])
    .unwrap();
    assert_eq!(
        post_token(&app, "jwt", &form).await.status(),
        StatusCode::CREATED
    );
    task.abort();
}
