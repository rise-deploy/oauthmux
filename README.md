# oauthmux

`oauthmux` gives an external OAuth/OIDC client one stable callback and safely relays authorization
results to an explicit set of application origins. It is an embeddable Axum router and a standalone
server for native, container, and AWS Lambda deployments.

An **upstream** represents one provider OAuth client, its credentials, and its stable callback. A
**relay** references that upstream and defines downstream authentication, scopes, and redirect
policy. Several relays can share one upstream without adding provider callbacks.

```mermaid
flowchart LR
    RP[Relying parties]
    M[oauthmux relay]
    U[Upstream OAuth client]

    RP -->|authorize and token| M
    M -->|authorization and code exchange| U
    U -->|one stable callback| M
    M -->|validated application redirect| RP
```

## Operating modes

| Mode | Token issuer and signer | Status |
| --- | --- | --- |
| Transparent relay | Upstream provider | Available |
| Brokered issuer | oauthmux | Planned |

Transparent relay returns the upstream token response unchanged. The relying party continues to
trust the upstream issuer, JWKS, audience, and UserInfo endpoint while routing authorization and
token requests through oauthmux. This requires a relying party that supports manual endpoint
configuration; Amazon Cognito is one example.

Brokered issuer will validate the upstream identity and issue a new oauthmux-signed identity. It is
a separate trust model with its own signing keys, JWKS, audience, claims, and UserInfo contract.

## Capabilities

- Authorization-code flow with independent upstream S256 PKCE.
- Public, shared-secret, upstream-client, and RFC 7523 `private_key_jwt` relay authentication.
- Exact URI, HTTPS-origin, and variable-port loopback redirect policies with sealed state/code envelopes.
- Transparent authorization, token, refresh, discovery metadata, and JWKS routing.
- Multi-document File configuration with local or AWS-backed secret references.
- AWS SSM resource discovery with SSM `SecureString` and Secrets Manager `jsonKey` references.
- Invocation-driven Lambda configuration refresh with a 60-second default TTL.
- Multi-architecture images at `ghcr.io/rise-deploy/oauthmux`.

## Documentation

- [Getting started](https://rise-deploy.github.io/oauthmux/getting-started/)
- [Operating modes](https://rise-deploy.github.io/oauthmux/modes/)
- [Cognito relay to Google](https://rise-deploy.github.io/oauthmux/guides/cognito-google-relay/)
- [Configuration reference](https://rise-deploy.github.io/oauthmux/configuration/)
- [File provider](https://rise-deploy.github.io/oauthmux/reference/file-provider/)
- [AWS SSM provider](https://rise-deploy.github.io/oauthmux/reference/ssm-provider/)
- [Runtime and deployment](https://rise-deploy.github.io/oauthmux/reference/runtime/)
- [HTTP endpoints](https://rise-deploy.github.io/oauthmux/reference/http-endpoints/)

The executable publishes its configuration contract directly:

```console
oauthmux schema > oauthmux.schema.json
```

## Development

[mise](https://mise.jdx.dev/) installs the pinned Rust, Node.js, and validation tools:

```console
mise install
mise run check
mise run e2e
```

Serve the documentation locally with:

```console
mise run docs:serve
```

The regular test suite uses in-process OAuth/OIDC fixtures. `mise run e2e` runs the standalone
binary through a complete authorization-code and refresh flow against a pinned Dex container. No
test contacts Google or Amazon Cognito.

The workspace contains:

```text
crates/oauthmux-core/          protocol engine and embeddable router
crates/oauthmux-secret-resolver/ shared inline, environment, file, and cloud secret dispatch
crates/oauthmux-provider-file/ File configuration provider
crates/oauthmux-provider-ssm/  AWS SSM and Secrets Manager provider
crates/oauthmux/               standalone native and Lambda runtime
```

The core exposes resolver and replay-cache seams for hosts that need database-backed configuration
or distributed single-use authorization codes.
