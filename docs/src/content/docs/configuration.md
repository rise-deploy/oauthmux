---
title: Configuration
description: Configure oauthmux resources and secret sources with the File or AWS SSM provider.
sidebar:
  order: 3
---

oauthmux configuration is a stream of typed resources. Each document has an API version, a kind,
a name, and a kind-specific specification:

```yaml
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
and stable provider callback. `Relay` owns transparent-relay scopes, downstream client
authentication, and redirect policy. Several relays can reference one upstream and therefore use
the same provider callback:

```text
https://login.example.com/oidc/upstreams/google/callback
```

Relay authorization and token endpoints use the relay name:

```text
https://login.example.com/oidc/cognito-google/authorize
https://login.example.com/oidc/cognito-google/token
```

## File provider

Set `OAUTHMUX_PROVIDER_FILE` to a multi-document YAML file. A secret-bearing field accepts exactly
one of an inline value, an environment source, or a file source:

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

Relative secret paths resolve from the configuration file's directory. Each provider refresh
reloads the complete document stream and every referenced secret before publishing the snapshot.

## AWS SSM provider

Set `OAUTHMUX_PROVIDER_SSM_PREFIX=/oauthmux/`. The provider discovers full resource documents at
fixed paths:

```text
/oauthmux/upstreams/google
/oauthmux/relays/cognito-google
/oauthmux/brokers/workforce
```

`Upstream` and `Relay` parameters use the SSM `String` type. The path kind and name must match the
document's `kind` and `metadata.name`. `Broker` is a reserved path kind and is rejected until
brokered issuer mode is available.

An SSM resource document references a separate `SecureString` parameter by its absolute name:

```yaml
clientSecret:
  valueFrom:
    ssmParameter:
      name: /oauthmux/secrets/google-client-secret
```

It can instead reference an AWS Secrets Manager `SecretString`:

```yaml
clientSecret:
  valueFrom:
    secretsManager:
      secretId: oauthmux/google
```

`jsonKey` selects one top-level string field from a JSON `SecretString`:

```yaml
clientSecret:
  valueFrom:
    secretsManager:
      secretId: oauthmux/google
      jsonKey: clientSecret
```

Without `jsonKey`, the complete `SecretString` is used. Binary secrets, nested paths, missing
fields, and non-string selected values are rejected. Every refresh fetches the current secret
values; a failure retains the complete last-good snapshot.

The runtime role needs `ssm:GetParametersByPath` for the resource paths, `ssm:GetParameter` for
referenced SSM secrets, `secretsmanager:GetSecretValue` for referenced Secrets Manager secrets,
and `kms:Decrypt` when a customer-managed key protects either source.

## JSON Schema

The executable generates the schema directly from the Rust configuration types:

```console
oauthmux schema > oauthmux.schema.json
```

The schema describes one resource document; a File provider configuration is a YAML stream of
those documents. The documentation publishes the current
[oauthmux JSON Schema](/oauthmux/oauthmux.schema.json).
