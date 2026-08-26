---
title: File provider
description: Load oauthmux resources and local secret references from a YAML document stream.
---

The File provider reads a multi-document YAML stream from one path. It is suitable for native
servers, mounted container configuration, and development environments.

## Enable the provider

```console
export OAUTHMUX_PROVIDER_FILE=/etc/oauthmux/config.yaml
export OAUTHMUX_PROVIDER_FILE_POLL=30s
```

The poll interval must include a unit such as `s` or `m` and must be greater than zero. It defaults
to `30s`.

## Resource file

Put every upstream and relay in the same YAML stream, separated by `---`:

```yaml oauthmux-config
apiVersion: oauthmux.dev/v1alpha1
kind: Upstream
metadata:
  name: example
spec:
  issuerUrl: https://issuer.example.com
  oauthClient:
    clientId: example-client
    clientSecret:
      valueFrom:
        file:
          path: ./secrets/provider-client-secret
---
apiVersion: oauthmux.dev/v1alpha1
kind: Relay
metadata:
  name: example
spec:
  upstreamRef:
    name: example
  scopes:
    default: [openid, email]
  clientAuthentication:
    type: Public
  redirectPolicy:
    allowedOrigins:
      - https://app.example.com
```

Relative secret paths resolve from the resource file's directory. Referenced environment and file
values have trailing CR/LF characters removed, which supports mounted secret files ending in a
newline.

## Secret sources

The File provider accepts these forms:

```yaml
clientSecret:
  value: local-development-secret
```

```yaml
clientSecret:
  valueFrom:
    env:
      name: PROVIDER_CLIENT_SECRET
```

```yaml
clientSecret:
  valueFrom:
    file:
      path: ./secrets/provider-client-secret
```

SSM Parameter Store and Secrets Manager references are rejected by this provider. Use the
[AWS SSM provider](/oauthmux/reference/ssm-provider/) when configuration should resolve AWS-backed
secrets.

## Reload behavior

The complete resource stream and every referenced secret are re-read on each poll, including when
the resource file itself has not changed. A valid candidate replaces the provider snapshot as one
unit. A read, parse, reference, secret, or validation error retains the complete last-good
snapshot.

When both File and SSM providers are enabled, File has precedence for a resource with the same kind
and name. Collisions are logged and do not combine individual fields.

See [Configuration](/oauthmux/configuration/) for every resource field and validation rule.
