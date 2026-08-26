---
title: Configuration
description: Reference for oauthmux Upstream and Relay resources, policies, and secret values.
---

oauthmux configuration is a stream of strict, versioned resources. Each resource has an API
version, kind, name, and kind-specific specification. Unknown fields, unsupported API versions,
duplicate identities, and invalid references reject the complete candidate snapshot.

```yaml oauthmux-config
apiVersion: oauthmux.dev/v1alpha1
kind: Upstream
metadata:
  name: google
spec:
  issuerUrl: https://accounts.google.com
  endpoints:
    authorization: https://accounts.google.com/o/oauth2/v2/auth
    token: https://oauth2.googleapis.com/token
    jwks: https://www.googleapis.com/oauth2/v3/certs
  oauthClient:
    clientId: 123456789.apps.googleusercontent.com
    clientSecret:
      valueFrom:
        env:
          name: GOOGLE_CLIENT_SECRET
---
apiVersion: oauthmux.dev/v1alpha1
kind: Relay
metadata:
  name: cognito-google
spec:
  upstreamRef:
    name: google
  scopes:
    default: [openid, email, profile]
    allowed: [openid, email, profile]
  clientAuthentication:
    type: UpstreamClient
  redirectPolicy:
    allowedOrigins:
      - https://pool-a.auth.eu-west-1.amazoncognito.com
      - https://pool-b.auth.us-east-1.amazoncognito.com
```

`Upstream` owns the external issuer, provider endpoints, OAuth client registration, credentials,
and stable provider callback. `Relay` owns transparent-relay scopes, downstream authentication,
and redirect policy. Several relays can reference one upstream and use the same callback.

## Common fields

| Field | Required | Meaning |
| --- | --- | --- |
| `apiVersion` | yes | Exactly `oauthmux.dev/v1alpha1`. |
| `kind` | yes | `Upstream` or `Relay`. `Broker` is reserved but unavailable. |
| `metadata.name` | yes | URL-safe resource name containing ASCII letters, numbers, `.`, `_`, or `-`. File and SSM resource names occupy one path segment. |

An upstream and a relay may use the same name because identities include the resource kind.

## Upstream

| Field | Required | Meaning |
| --- | --- | --- |
| `spec.issuerUrl` | yes | Absolute HTTP(S) issuer URL used for discovery and preserved as the transparent trust authority. |
| `spec.endpoints.authorization` | no | Explicit upstream authorization endpoint. Discovery supplies it when omitted. |
| `spec.endpoints.token` | no | Explicit upstream token endpoint. Discovery supplies it when omitted. |
| `spec.endpoints.jwks` | no | Explicit upstream JWKS endpoint. Discovery supplies it when omitted. |
| `spec.oauthClient.clientId` | yes | Provider OAuth client ID. |
| `spec.oauthClient.clientSecret` | yes | Provider OAuth client secret as a [secret value](#secret-values). |

The callback registered with the provider is derived from `OAUTHMUX_PUBLIC_URL` and the upstream
name:

```text
https://login.example.com/oidc/upstreams/google/callback
```

Explicit endpoints are useful for providers without standard discovery. When authorization or
token is omitted, oauthmux reads `{issuerUrl}/.well-known/openid-configuration`. The issuer and
JWKS remain upstream-owned in transparent relay mode.

## Relay

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `spec.upstreamRef.name` | yes | — | Existing upstream used for authorization and token exchange. |
| `spec.scopes.default` | no | `[]` | Scopes used when the authorization request omits `scope`. |
| `spec.scopes.allowed` | no | unrestricted | Complete allow-list for configured and requested scopes. Every default scope must be allowed. |
| `spec.clientAuthentication` | yes | — | Authentication policy for requests to the relay token endpoint. |
| `spec.redirectPolicy.allowedOrigins` | no | `[]` | Exact HTTP(S) origins allowed to receive authorization results. |
| `spec.redirectPolicy.defaultRedirectUri` | no | unset | Redirect used when authorization omits `redirect_uri`; its origin must be allowed. |

Relay endpoints are derived from the relay name:

```text
https://login.example.com/oidc/cognito-google/authorize
https://login.example.com/oidc/cognito-google/token
```

Allowed redirects match scheme, host, and effective port exactly. Paths are not part of an origin
entry. HTTP loopback redirects on `localhost`, `127.0.0.1`, and `::1` are accepted for local
development. User information, fragments, wildcards, and prefix matching are not accepted.

## Client authentication

`spec.clientAuthentication` selects how a relying party authenticates to the relay token endpoint.

### UpstreamClient

The relying party presents the referenced upstream's client ID and secret. This is useful when a
manually configured relying party, such as Cognito, already stores those credentials.

```yaml
clientAuthentication:
  type: UpstreamClient
```

### Public

No client secret is accepted. Every authorization-code flow must use S256 PKCE.

```yaml
clientAuthentication:
  type: Public
```

### ClientSecret

The relay has a distinct downstream client ID and secret. The secret supports the same provider-
specific sources as the upstream client secret.

```yaml
clientAuthentication:
  type: ClientSecret
  clientId: relying-party
  clientSecret:
    valueFrom:
      env:
        name: RELAY_CLIENT_SECRET
```

### PrivateKeyJwt

The relying party sends an RFC 7523 client assertion. `jwks` is either an HTTPS URL or an inline
JWKS object with a non-empty `keys` array. The assertion issuer and subject must equal `clientId`,
and its audience must equal the relay token endpoint.

```yaml
clientAuthentication:
  type: PrivateKeyJwt
  clientId: relying-party
  jwks:
    keys:
      - kty: RSA
        kid: relying-party-2026-01
        use: sig
        alg: RS256
        n: base64url-modulus
        e: AQAB
```

## Secret values

A secret-bearing field contains exactly one inline value or one reference:

```yaml
clientSecret:
  value: local-development-secret
```

```yaml
clientSecret:
  valueFrom:
    env:
      name: GOOGLE_CLIENT_SECRET
```

```yaml
clientSecret:
  valueFrom:
    file:
      path: ./secrets/google-client-secret
```

```yaml
clientSecret:
  valueFrom:
    ssmParameter:
      name: /oauthmux/secrets/google-client-secret
```

```yaml
clientSecret:
  valueFrom:
    secretsManager:
      secretId: oauthmux/google
      jsonKey: clientSecret
```

The active configuration provider determines which sources are accepted:

| Provider | Accepted secret forms |
| --- | --- |
| [File](/oauthmux/reference/file-provider/) | `value`, `valueFrom.env`, `valueFrom.file` |
| [AWS SSM](/oauthmux/reference/ssm-provider/) | `valueFrom.ssmParameter`, `valueFrom.secretsManager` |

Identical references are resolved once while compiling a candidate snapshot. Resolved values have
a redacted debug representation and are not included in configuration errors.

## JSON Schema

Generate the schema directly from the Rust configuration types:

```console
oauthmux schema > oauthmux.schema.json
```

The schema describes one resource document; a File provider configuration is a YAML stream of
those documents. The published [oauthmux JSON Schema](/oauthmux/oauthmux.schema.json) includes
field descriptions, strict unions, and the exact API version. CI checks that it remains synchronized
with the Rust types.
