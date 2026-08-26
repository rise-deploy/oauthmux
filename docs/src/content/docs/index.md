---
title: oauthmux
description: One stable upstream OAuth callback, safely relayed to an explicit set of applications.
template: splash
hero:
  tagline: Keep provider callbacks stable without confusing endpoint routing with token trust.
  actions:
    - text: Get started
      link: /oauthmux/getting-started/
      icon: right-arrow
      variant: primary
    - text: Understand the operating modes
      link: /oauthmux/modes/
      icon: open-book
    - text: Configure Cognito with Google
      link: /oauthmux/guides/cognito-google-relay/
      icon: external
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

Start with [Getting started](/oauthmux/getting-started/), then use the
[configuration reference](/oauthmux/configuration/) for the complete resource model and secret
sources.
