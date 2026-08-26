---
title: AWS SSM provider
description: Load oauthmux resources from SSM Parameter Store and resolve AWS-managed secrets.
---

The AWS SSM provider discovers complete resource documents under fixed Parameter Store paths. It
can resolve client secrets from an exact SSM `SecureString` or an AWS Secrets Manager
`SecretString`.

## Enable the provider

```console
export OAUTHMUX_PROVIDER_SSM_PREFIX=/oauthmux/
export OAUTHMUX_PROVIDER_SSM_POLL=60s
```

The prefix must start and end with `/`. AWS region, credentials, and endpoint selection follow the
standard AWS SDK provider chain. The poll interval defaults to `60s`.

## Resource parameters

The provider enumerates these subpaths independently:

```text
/oauthmux/upstreams/{name}
/oauthmux/relays/{name}
/oauthmux/brokers/{name}
```

Each parameter uses the SSM `String` type and contains one complete YAML or JSON resource document.
The path kind and name must match `kind` and `metadata.name` in the document. Names occupy exactly
one path segment. `Broker` is reserved and rejects the candidate snapshot because brokered issuer
mode is unavailable.

For example, store the first document at `/oauthmux/upstreams/google` and the second at
`/oauthmux/relays/cognito-google`:

```yaml oauthmux-config
apiVersion: oauthmux.dev/v1alpha1
kind: Upstream
metadata:
  name: google
spec:
  issuerUrl: https://accounts.google.com
  oauthClient:
    clientId: 123456789.apps.googleusercontent.com
    clientSecret:
      valueFrom:
        ssmParameter:
          name: /oauthmux/secrets/google-client-secret
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
  clientAuthentication:
    type: UpstreamClient
  redirectPolicy:
    allowedOrigins:
      - https://pool.auth.eu-west-1.amazoncognito.com
```

## SSM secret reference

An SSM reference names an absolute parameter. The referenced parameter must use `SecureString`:

```yaml
clientSecret:
  valueFrom:
    ssmParameter:
      name: /oauthmux/secrets/google-client-secret
```

Resource discovery does not enumerate the secrets subtree; each secret is fetched by its exact
name with decryption enabled.

## Secrets Manager reference

Without `jsonKey`, the complete `SecretString` is the client secret:

```yaml
clientSecret:
  valueFrom:
    secretsManager:
      secretId: oauthmux/google
```

With `jsonKey`, the `SecretString` must contain a JSON object and the selected top-level field must
be a string:

```yaml
clientSecret:
  valueFrom:
    secretsManager:
      secretId: oauthmux/google
      jsonKey: clientSecret
```

Nested JSON paths, missing fields, non-string selected values, and binary secrets are rejected.
Inline, environment, and file secret forms are also rejected by this provider.

## IAM permissions

The runtime role needs permissions equivalent to:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:GetParametersByPath",
      "Resource": [
        "arn:aws:ssm:REGION:ACCOUNT:parameter/oauthmux/upstreams/*",
        "arn:aws:ssm:REGION:ACCOUNT:parameter/oauthmux/relays/*",
        "arn:aws:ssm:REGION:ACCOUNT:parameter/oauthmux/brokers/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:REGION:ACCOUNT:parameter/oauthmux/secrets/*"
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:oauthmux/*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }
  ]
}
```

Limit each statement to the configured paths, secret IDs, and KMS keys. `kms:Decrypt` is needed
when a customer-managed KMS key protects the referenced SSM or Secrets Manager value.

## Refresh behavior

Native mode builds a complete candidate on each poll. The provider follows SSM pagination,
resolves every referenced secret, validates the complete graph, and publishes it atomically. A
failure retains the last-good snapshot.

SSM reads are not transactional. During a multi-parameter rollout, an inconsistent candidate is
rejected until a later refresh observes a complete valid graph. Lambda performs the same load at
invocation boundaries according to `OAUTHMUX_LAMBDA_CONFIG_TTL`; see
[Runtime and deployment](/oauthmux/reference/runtime/).
