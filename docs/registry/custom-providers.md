---
title: Custom providers
description: Adding providers that aren't in the built-in registry.
---

For providers not covered by the built-in registry, you create credentials and capabilities manually.

## Step 1: Store the secret

```bash
aivault secrets create --name MY_CUSTOM_KEY --value "..." --scope global
```

Because `MY_CUSTOM_KEY` doesn't match any registry provider, this creates an unpinned secret with no auto-provisioning.

## Step 2: Create a credential

```bash
aivault credential create my-api \
  --provider my-api \
  --secret-ref "vault:secret:<secret-id>" \
  --auth header \
  --header-name authorization \
  --value-template "Bearer {{secret}}" \
  --host api.example.com
```

See [Credentials](/cli/credentials) for all auth strategies and options.

## Step 3: Create capabilities

```bash
aivault capability create my-api/users \
  --provider my-api \
  --credential my-api \
  --method GET \
  --method POST \
  --path /v1/users \
  --host api.example.com

aivault capability create my-api/orders \
  --provider my-api \
  --credential my-api \
  --method GET \
  --path /v1/orders \
  --host api.example.com
```

## Step 4: Invoke

```bash
aivault invoke my-api/users --method GET
aivault invoke my-api/orders --method GET --path /v1/orders?status=active
```

## Security considerations

Custom providers are **less secure** than registry-compiled providers because:
- The secret is not pinned to a provider (it could be referenced by multiple credentials)
- The capability definitions can be modified at runtime
- There's no compiled-in host allow-list

For production use, consider contributing your provider to the official registry. This gives you:
- Immutable secret pinning
- Compiled-in auth strategy and host definitions
- Tamper-proof capability definitions

## Contributing to the registry

To add a provider to the built-in registry, create a JSON file in `registry/` following the [registry schema](/registry/schema). Example:

```json
{
  "$schema": "./schemas/registry-provider.schema.json",
  "provider": "my-api",
  "vaultSecrets": {
    "MY_API_KEY": "secret"
  },
  "auth": {
    "header": {
      "header_name": "authorization",
      "value_template": "Bearer {{secret}}"
    }
  },
  "hosts": ["api.example.com"],
  "capabilities": [
    {
      "id": "my-api/users",
      "provider": "my-api",
      "allow": {
        "hosts": ["api.example.com"],
        "methods": ["GET", "POST"],
        "pathPrefixes": ["/v1/users"]
      }
    }
  ]
}
```

Next: [Registry schema](/registry/schema)
