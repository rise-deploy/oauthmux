---
title: oauthmux
description: One stable upstream OAuth callback, safely relayed to an explicit set of applications.
---

oauthmux multiplexes a provider callback across production, preview, and local application
origins. It owns the authorization transport and callback state while keeping each redirect target
inside an explicit origin policy.

The available transparent relay returns upstream token responses unchanged. The relying party
therefore trusts the upstream issuer and keys even though authorization and token requests pass
through oauthmux.

An **upstream** represents one provider OAuth client and its stable callback. A **relay** references
that upstream and defines the scopes, downstream authentication, and allowed application origins.
Several relays can share one upstream without creating additional provider callbacks.

## Start here

- [Getting started](/oauthmux/getting-started/) runs the first File-backed transparent relay.
- [Operating modes](/oauthmux/modes/) explains the endpoint and trust boundaries of transparent
  relay and brokered issuer modes.
- [Cognito relay to Google](/oauthmux/guides/cognito-google-relay/) applies one stable Google
  callback to any number of Cognito user pools.

## Reference

- [Configuration](/oauthmux/configuration/) defines upstreams, relays, authentication, redirect
  policy, scopes, and secret values.
- [File provider](/oauthmux/reference/file-provider/) and
  [AWS SSM provider](/oauthmux/reference/ssm-provider/) describe the available configuration
  sources.
- [Runtime and deployment](/oauthmux/reference/runtime/) covers native, container, and Lambda
  execution.
- [HTTP endpoints](/oauthmux/reference/http-endpoints/) describes relay, callback, metadata, and
  health routes.

## Availability

| Mode | Token issuer and signer | Status |
| --- | --- | --- |
| Transparent relay | Upstream provider | Available |
| Brokered issuer | oauthmux | Planned |
