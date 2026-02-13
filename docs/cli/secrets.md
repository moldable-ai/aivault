---
title: Secrets
description: Create, list, update, rotate, and delete encrypted secrets.
---

Secrets are the core unit of storage in aivault. Each secret holds an encrypted value that is never returned to callers — only injected by the broker during proxied requests.

## list

List secrets (metadata only, no values).

```bash
aivault secrets list
aivault secrets list --scope global
aivault secrets list --scope workspace --workspace-id my-ws
aivault secrets list -v   # full JSON detail
```

## create

Create a new encrypted secret. If the name matches a registry provider's `vaultSecrets`, the secret is pinned to that provider and the credential + capabilities are auto-provisioned.

```bash
# Registry-backed (auto-provisions credential + capabilities)
aivault secrets create --name OPENAI_API_KEY --value "sk-..." --scope global
# → Secret created: OPENAI_API_KEY (pinned to provider: openai)
# → Credential auto-provisioned: openai (17 capabilities enabled)

# Custom (no registry match, no auto-provisioning)
aivault secrets create --name MY_CUSTOM_KEY --value "..." --scope global

# With aliases
aivault secrets create --name OPENAI_API_KEY --value "sk-..." \
  --scope global --alias openai --alias gpt-key

# Workspace-scoped
aivault secrets create --name OPENAI_API_KEY --value "sk-..." \
  --scope workspace --workspace-id my-workspace

# Group-scoped
aivault secrets create --name OPENAI_API_KEY --value "sk-..." \
  --scope group --workspace-id my-workspace --group-id my-group
```

### Registry matching

When the secret name matches a registry provider's `vaultSecrets` key (e.g. `OPENAI_API_KEY` → `openai`), the system:
1. Pins the secret to that provider (immutable)
2. Auto-creates the credential with the correct auth strategy
3. Enables all capabilities defined in the registry entry

For multi-secret providers (e.g. Trello needs `TRELLO_API_KEY` + `TRELLO_TOKEN`), the credential auto-provisions once all required secrets are present.

## update

Update secret name or aliases (not the value — use `rotate` for that).

```bash
aivault secrets update --id <secret-id> --name NEW_NAME
aivault secrets update --id <secret-id> --alias new-alias
aivault secrets update --id <secret-id> --clear-aliases
```

## rotate

Rotate a secret's encrypted value. Re-encrypts with a new DEK.

```bash
aivault secrets rotate --id <secret-id> --value "new-value"
```

The old value is discarded and the new value is encrypted with a fresh DEK. An audit event is logged.

## delete

Revoke and delete a secret.

```bash
aivault secrets delete --id <secret-id>
```

This also removes any credential and capability bindings that depended on this secret.

## attach-group / detach-group

Attach or detach a secret from a workspace group.

```bash
aivault secrets attach-group \
  --id <secret-id> \
  --workspace-id my-workspace \
  --group-id my-group

aivault secrets detach-group \
  --id <secret-id> \
  --workspace-id my-workspace \
  --group-id my-group
```

## import

Bulk import secrets from `KEY=VALUE` pairs.

```bash
aivault secrets import \
  --entry OPENAI_API_KEY=sk-... \
  --entry ANTHROPIC_API_KEY=sk-ant-... \
  --entry GITHUB_TOKEN=ghp-... \
  --scope global
```

Each entry is processed as if you ran `secrets create` individually — registry matching, pinning, and auto-provisioning apply.

Next: [Credentials](/cli/credentials)
