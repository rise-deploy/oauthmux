---
title: Getting started
description: Run oauthmux with a File provider and connect the first transparent relay.
sidebar:
  order: 1
---

This guide runs oauthmux as a native server with one upstream and one public relay. The resulting
relay keeps token trust with the upstream provider while giving that provider one stable oauthmux
callback.

## Prerequisites

- [mise](https://mise.jdx.dev/) for the repository toolchain
- An OAuth/OIDC provider client ID and secret
- An application that supports separate issuer, JWKS, authorization, and token endpoints

Install the pinned tools and build oauthmux:

```console
mise install
cargo build -p oauthmux
```

## Create the configuration

Save this as `config.yaml`. Replace the issuer, endpoints, and client credentials with values from
the provider. The example makes every upstream endpoint explicit so the routing boundary is
visible.

```yaml oauthmux-config
apiVersion: oauthmux.dev/v1alpha1
kind: Upstream
metadata:
  name: example
spec:
  issuerUrl: https://issuer.example.com
  endpoints:
    authorization: https://issuer.example.com/oauth2/authorize
    token: https://issuer.example.com/oauth2/token
    jwks: https://issuer.example.com/.well-known/jwks.json
  oauthClient:
    clientId: example-client-id
    clientSecret:
      valueFrom:
        env:
          name: EXAMPLE_CLIENT_SECRET
---
apiVersion: oauthmux.dev/v1alpha1
kind: Relay
metadata:
  name: example
spec:
  upstreamRef:
    name: example
  scopes:
    default: [openid, email, profile]
    allowed: [openid, email, profile]
  clientAuthentication:
    type: Public
  redirectPolicy:
    - uri: https://app.example.com/oauth/callback
```

If the issuer publishes standard OIDC discovery metadata, omit the complete `spec.endpoints`
block. oauthmux then resolves the authorization, token, and JWKS endpoints from
`{issuerUrl}/.well-known/openid-configuration`.

`Public` relays require the application to use S256 PKCE. Server-side relying parties can instead
use `UpstreamClient`, a relay-specific `ClientSecret`, or `PrivateKeyJwt`; see
[Client authentication](/oauthmux/configuration/#client-authentication).
Every authorization request must send the exact configured `redirect_uri`.

## Start oauthmux

Generate a 32-byte sealing key and start the server:

```console
export EXAMPLE_CLIENT_SECRET='provider-client-secret'
export OAUTHMUX_PUBLIC_URL='https://login.example.com/oidc'
export OAUTHMUX_SEAL_KEY="base64:$(openssl rand -base64 32)"
export OAUTHMUX_PROVIDER_FILE="$PWD/config.yaml"
cargo run -p oauthmux
```

The native server listens on `0.0.0.0:8080` by default. `/healthz` reports process liveness and
`/readyz` becomes healthy after every configured provider has supplied its first valid snapshot.

## Register and consume the endpoints

Register this callback with the external provider:

```text
https://login.example.com/oidc/upstream/example/callback
```

Configure the relying party with the upstream issuer, JWKS, and UserInfo endpoints. Route only its
authorization and token requests through the relay:

```text
https://login.example.com/oidc/relay/example/authorize
https://login.example.com/oidc/relay/example/token
```

This separation is the defining constraint of [transparent relay mode](/oauthmux/modes/). A client
that requires oauthmux to be its discovered issuer needs brokered issuer mode, which is planned but
not available.

## Choose the production provider

- Use the [File provider](/oauthmux/reference/file-provider/) for a mounted configuration file,
  container secrets, or environment-backed secrets.
- Use the [AWS SSM provider](/oauthmux/reference/ssm-provider/) for Lambda and AWS deployments that
  need independently managed resource documents and secrets.

Continue with [Runtime and deployment](/oauthmux/reference/runtime/) for container and Lambda
behavior, or follow the [Cognito relay to Google guide](/oauthmux/guides/cognito-google-relay/) for
a concrete multi-pool topology.
