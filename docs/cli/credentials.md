---
title: Credentials
description: Manage provider credentials that bind secrets to auth strategies.
---

Credentials bind a provider to a vault secret and an auth strategy. For registry-backed providers, credentials are auto-provisioned when you create a matching secret. Manual credential creation is only needed for custom/non-registry providers or per-tenant host overrides.

## create

Create a credential manually.

```bash
# Minimal (header auth)
aivault credential create my-api \
  --provider my-api \
  --secret-ref vault:secret:<secret-id> \
  --auth header \
  --host api.example.com

# With custom header template
aivault credential create my-api \
  --provider my-api \
  --secret-ref vault:secret:<secret-id> \
  --auth header \
  --header-name x-api-key \
  --value-template "{{secret}}" \
  --host api.example.com

# Query auth
aivault credential create my-api \
  --provider my-api \
  --secret-ref vault:secret:<secret-id> \
  --auth query \
  --query-param api_key \
  --host api.example.com

# Per-tenant host override (Shopify)
aivault credential create my-shopify \
  --provider shopify \
  --secret-ref vault:secret:<secret-id> \
  --host my-store.myshopify.com

# Multi-header auth
aivault credential create my-datadog \
  --provider my-datadog \
  --secret-ref vault:secret:<secret-id> \
  --auth multi-header \
  --auth-header "DD-API-KEY={{api_key}}" \
  --auth-header "DD-APPLICATION-KEY={{app_key}}" \
  --host api.datadoghq.com

# OAuth2
aivault credential create my-spotify \
  --provider spotify \
  --secret-ref vault:secret:<secret-id> \
  --auth oauth2 \
  --grant-type refresh_token \
  --token-endpoint https://accounts.spotify.com/api/token \
  --host api.spotify.com

# AWS SigV4
aivault credential create my-bedrock \
  --provider aws-bedrock \
  --secret-ref vault:secret:<secret-id> \
  --auth aws-sigv4 \
  --aws-service bedrock-runtime \
  --aws-region us-east-1 \
  --host bedrock-runtime.us-east-1.amazonaws.com

# Workspace-scoped
aivault credential create my-api-staging \
  --provider my-api \
  --secret-ref vault:secret:<secret-id> \
  --auth header \
  --host api-staging.example.com \
  --workspace-id staging
```

### When to create credentials manually

- **Custom providers** not in the built-in registry
- **Per-tenant hosts** (e.g. `my-store.myshopify.com`)
- **Multiple accounts** for the same provider
- **Workspace/group-scoped** credential overrides

For registry-backed providers, you typically only need `aivault secrets create` — the credential is auto-provisioned. If you do create a credential manually for a registry provider, you don't need to specify `--auth` (it's inherited from the registry).

## list

List configured credentials.

```bash
aivault credential list
aivault credential list -v   # full JSON detail
```

## delete

Delete a credential.

```bash
aivault credential delete <id>
```

Next: [Capabilities](/cli/capabilities)
