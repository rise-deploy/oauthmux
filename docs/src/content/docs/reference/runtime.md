---
title: Runtime and deployment
description: Configure oauthmux native, container, and AWS Lambda execution.
---

The `oauthmux` executable uses the same Axum router in native server and AWS Lambda modes. It loads
every configured provider before serving traffic.

## Environment variables

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `OAUTHMUX_PUBLIC_URL` | yes | — | Externally visible absolute base URL used to construct callbacks and relay endpoints. |
| `OAUTHMUX_SEAL_KEY` | yes | — | Raw base64 or `base64:`-prefixed 32-byte key for state and authorization-code envelopes. |
| `OAUTHMUX_SEAL_KEY_PREVIOUS` | no | unset | Previous 32-byte key accepted while rotating envelopes. |
| `OAUTHMUX_LISTEN` | native only | `0.0.0.0:8080` | Native server socket. |
| `OAUTHMUX_PROVIDER_FILE` | one provider required | disabled | File provider YAML path. |
| `OAUTHMUX_PROVIDER_FILE_POLL` | no | `30s` | File and referenced-secret reload interval. |
| `OAUTHMUX_PROVIDER_SSM_PREFIX` | one provider required | disabled | Absolute SSM root ending in `/`. |
| `OAUTHMUX_PROVIDER_SSM_POLL` | no | `60s` | Native SSM reload interval. |
| `OAUTHMUX_LAMBDA_CONFIG_TTL` | no | `60s` | Maximum Lambda snapshot age before invocation-driven refresh. |
| `OAUTHMUX_ALLOW_LOCALHOST_LOOPBACK` | no | `false` | Treat `localhost` as an alias for configured IP-literal loopback redirect matchers. |
| `OAUTHMUX_LOG` | no | `info` | `tracing` filter. |

Durations require an explicit unit such as `30s`, `5m`, or `1h` and must be greater than zero.
The localhost compatibility value must be `true` or `false`.
When both providers are enabled, File is evaluated before SSM for collision precedence.

## Build features

The standalone crate enables `aws` and `lambda` by default. `aws` supplies SSM resource discovery
and AWS secret resolution for both File and SSM providers. A native File-only build without AWS
SDK dependencies uses `--no-default-features`; in that build, File resources can use inline,
environment, and file secrets, while AWS secret references fail configuration validation.

## Native server

Native mode binds `OAUTHMUX_LISTEN`, reloads providers on their polling intervals, and shuts down
on SIGTERM or SIGINT. It exposes:

- `GET /healthz` for process liveness.
- `GET /readyz` after every provider has supplied its initial snapshot.

Logs use human-readable output on a terminal and JSON when stdout is not a terminal.

## Container image

Multi-architecture images are published at `ghcr.io/rise-deploy/oauthmux` for AMD64 and ARM64.
Every published build has an immutable `sha-<short-commit>` tag; builds from a version tag also
publish that version tag.

The image is a non-root, scratch-based executable listening on port 8080. Mount a File provider
configuration or supply AWS credentials for the SSM provider. Terminate TLS at the ingress, load
balancer, API Gateway, or Function URL, and set `OAUTHMUX_PUBLIC_URL` to the public HTTPS base URL.

## AWS Lambda

The executable enters Lambda mode when `AWS_LAMBDA_RUNTIME_API` is present. Provider initialization
is part of cold start, so the Lambda event loop begins only after every provider has supplied a
valid initial snapshot.

Lambda can freeze the process between requests, so background polling cannot bound configuration
age. Before each invocation, oauthmux compares wall-clock time with the last refresh attempt. Once
the snapshot reaches `OAUTHMUX_LAMBDA_CONFIG_TTL`, it synchronously reloads each provider. A
successful provider replaces its snapshot; a failure retains that provider's last-good snapshot.

Configure an API Gateway HTTP API or Lambda Function URL to forward every oauthmux route. The
function role needs the permissions documented by the selected provider. The default binary
includes the Lambda Runtime API client.

## Sealing-key rotation

Transient state lives for ten minutes and sealed authorization codes live for five minutes. To
rotate keys, set the new key as `OAUTHMUX_SEAL_KEY` and the active key as
`OAUTHMUX_SEAL_KEY_PREVIOUS`. Keep the previous key available for at least ten minutes, then remove
it after envelopes created with it have expired.

The standalone runtime uses an in-memory replay cache. Authorization codes are single-use within
one native process or one warm Lambda execution environment. Deployments requiring global
single-use semantics need a shared `ReplayCache` implementation through the embeddable core.
