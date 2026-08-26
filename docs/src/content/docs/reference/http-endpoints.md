---
title: HTTP endpoints
description: Reference for oauthmux relay, callback, metadata, and health routes.
---

For relay name `R` referencing upstream name `U`, oauthmux serves:

| Method and route | Behavior |
| --- | --- |
| `GET /oidc/{R}/authorize` | Validates redirect and scope policy, creates independent upstream state and S256 PKCE, then redirects to the upstream. |
| `GET /oidc/upstreams/{U}/callback` | Validates upstream-bound state, exchanges the upstream code, and returns a sealed code to the originating relay redirect. |
| `POST /oidc/{R}/token` | Authenticates the relying party, validates the sealed code, redirect, and PKCE, then returns the stored upstream response unchanged. |
| `POST /oidc/{R}/token` with `refresh_token` | Authenticates the relying party and relays the refresh grant with upstream credentials. |
| `OPTIONS /oidc/{R}/token` | Returns CORS headers only for an allowed origin. |
| `GET /oidc/{R}/.well-known/openid-configuration` | Preserves upstream issuer/JWKS metadata and rewrites authorization and token endpoints to the relay. |
| `GET /oidc/{R}/jwks` | Proxies the referenced upstream JWKS. |
| `GET /healthz` | Reports standalone process liveness. |
| `GET /readyz` | Reports readiness after initial provider snapshots are available. |

## Authorization endpoint

Only authorization-code flow and query response mode are accepted. oauthmux owns and replaces
`client_id`, `redirect_uri`, `state`, upstream PKCE, and `response_type`. Other parameters,
including `nonce`, `prompt`, `login_hint`, `access_type`, `hd`, repeated `resource` values, and
provider extensions, are forwarded.

OIDC `request` and `request_uri` objects are rejected because their embedded routing fields cannot
be reconciled safely with proxy-owned values. A supplied scope must pass the relay allow-list. A
public relay also requires a valid S256 application code challenge.

`redirect_uri` is required and must match one configured redirect-policy entry. Static query
parameters are part of the match. oauthmux appends authorization results and application state
only after the redirect has passed policy.

## Callback

The callback is owned by the upstream, not by an individual relay. Sealed state identifies the
originating relay and validated application redirect, so several relays can share the same
upstream callback. Upstream error parameters are returned only to that validated redirect.

oauthmux exchanges a successful upstream code immediately. It stores the upstream status, content
type, and body inside the sealed application code and never exposes the upstream code to the
application.

## Token endpoint

The authorization-code request must use the same redirect URI and, when present, the matching PKCE
verifier. Successful exchange returns the upstream status, content type, and body bytes unchanged.
The standalone replay cache rejects a second use in the same process.

Refresh grants preserve extension fields and replace downstream authentication with the referenced
upstream client credentials. Unsupported grants and invalid requests use RFC 6749-style JSON error
bodies.

## Transparent metadata

Relay metadata is useful to inspect the routed authorization and token endpoints, but is not a
portable OIDC Discovery contract. The metadata URL is hosted by oauthmux while `issuer` remains the
upstream issuer. Configure transparent-relay relying parties with manual endpoints as described in
[Operating modes](/oauthmux/modes/).
