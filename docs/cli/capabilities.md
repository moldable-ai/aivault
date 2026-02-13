---
title: Capabilities
description: Browse, create, and manage capability definitions and bindings.
---

Capabilities define what a caller can do — which methods, paths, and hosts are allowed. Most capabilities come from the built-in registry; you can also create custom ones.

## list

List all capabilities (registered + built-in registry), grouped by readiness.

```bash
aivault capability list
aivault capability list -v   # full JSON detail
```

Capabilities are grouped as:
- **Ready** — credential and secret are configured, can invoke immediately
- **Available** — defined in registry but no credential yet (store the matching secret to activate)

## describe

Show how to invoke a capability: allowed methods, path prefixes, and example invocations. Works for any registry capability, even without a credential configured.

```bash
aivault capability describe openai/chat-completions
aivault capability describe stripe/charges
```

Aliases: `args`, `shape`, `inspect`

## create

Create a custom capability definition (for non-registry providers).

```bash
aivault capability create my-api/users \
  --provider my-api \
  --credential my-api \
  --method GET \
  --method POST \
  --path /v1/users \
  --host api.example.com
```

## delete

Delete a capability definition.

```bash
aivault capability delete my-api/users
```

## policy set

Set advanced policy constraints on a capability.

```bash
aivault capability policy set \
  --capability openai/chat-completions \
  --rate-limit-per-minute 60 \
  --max-request-body-bytes 1048576 \
  --max-response-body-bytes 10485760 \
  --response-block "api_key" \
  --response-block "secret"
```

| Flag | Effect |
|------|--------|
| `--rate-limit-per-minute` | Max requests per minute for this capability |
| `--max-request-body-bytes` | Max request body size (rejects larger payloads) |
| `--max-response-body-bytes` | Max response body size (truncates larger responses) |
| `--response-block` | Field names redacted from JSON response bodies |

## bind

Bind a capability to a vault secret reference. For registry-backed providers, binding happens automatically. Manual binding is for custom capabilities or advanced overrides.

```bash
aivault capability bind \
  --capability openai/chat-completions \
  --secret-ref vault:secret:<secret-id> \
  --scope global

# Workspace-scoped binding
aivault capability bind \
  --capability openai/chat-completions \
  --secret-ref vault:secret:<secret-id> \
  --scope workspace \
  --workspace-id my-workspace

# Consumer-specific binding
aivault capability bind \
  --capability openai/chat-completions \
  --secret-ref vault:secret:<secret-id> \
  --scope global \
  --consumer my-agent
```

## unbind

Remove a capability-to-secret binding.

```bash
aivault capability unbind --capability openai/chat-completions
aivault capability unbind --capability openai/chat-completions \
  --scope workspace --workspace-id my-workspace
```

## bindings

List capability-to-secret bindings.

```bash
aivault capability bindings
aivault capability bindings --capability openai/chat-completions
aivault capability bindings --scope global
aivault capability bindings -v   # full JSON detail
```

Next: [Invoke](/cli/invoke)
