---
title: Registry
description: Built-in provider registry and how to extend it.
---

The built-in registry ships 30+ provider definitions covering AI, communication, productivity, payments, and more. These definitions are compiled into the binary to prevent runtime forgery.

## How registry matching works

When you store a secret with `aivault secrets create --name <NAME>`, the system checks every registry provider's `vaultSecrets` map. If `<NAME>` matches a key, the secret is:

1. **Pinned** to that provider (immutable — cannot be re-pinned)
2. Used to **auto-provision** a credential with the correct auth strategy
3. Used to **enable** all capabilities defined in the registry entry

For example, `OPENAI_API_KEY` matches the `openai` provider's `vaultSecrets`:
```json
{ "OPENAI_API_KEY": "secret" }
```

This tells the system: "when someone stores `OPENAI_API_KEY`, pin it to `openai` and map it to the `{{secret}}` placeholder in auth templates."

## Security properties of the registry

- **Compiled into binary** — provider definitions cannot be tampered with at runtime
- **Immutable pinning** — once a secret is pinned to a provider, it cannot be moved
- **Host allow-lists** — each capability specifies exactly which hosts it can reach
- **Single host per capability** — prevents cross-host confusion

## Pages in this section

- [Custom providers](/registry/custom-providers) — adding providers not in the built-in registry
- [Registry schema](/registry/schema) — the JSON schema for registry provider definitions
