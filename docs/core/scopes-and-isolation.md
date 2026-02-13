---
title: Scopes and isolation
description: Workspace and group boundaries for multi-tenant secret management.
---

aivault supports three scope levels for secrets and credentials, enabling isolation between different execution contexts.

## Scope levels

### Global

```bash
aivault secrets create --name OPENAI_API_KEY --value "..." --scope global
```

Global secrets are available to all callers regardless of workspace or group context. Use this for secrets shared across your entire setup.

### Workspace

```bash
aivault secrets create --name OPENAI_API_KEY --value "..." \
  --scope workspace --workspace-id my-workspace
```

Workspace-scoped secrets are only visible when the caller provides a matching `--workspace-id`. Use this to isolate secrets between different projects or tenants.

### Group

```bash
aivault secrets create --name OPENAI_API_KEY --value "..." \
  --scope group --workspace-id my-workspace --group-id my-group
```

Group-scoped secrets are only visible when the caller provides matching `--workspace-id` and `--group-id`. This is the most restrictive scope.

## How scope resolution works

When the broker resolves a credential for a request, it considers the caller's execution context:

1. If `--workspace-id` and `--group-id` are provided, the broker first looks for group-scoped credentials
2. If no group-scoped credential matches, it falls back to workspace-scoped credentials
3. If no workspace-scoped credential matches, it falls back to global credentials

This allows you to override global defaults with more specific credentials for particular workspaces or groups.

## Attaching secrets to groups

You can attach an existing secret to a group after creation:

```bash
aivault secrets attach-group \
  --id <secret-id> \
  --workspace-id my-workspace \
  --group-id my-group
```

And detach it:

```bash
aivault secrets detach-group \
  --id <secret-id> \
  --workspace-id my-workspace \
  --group-id my-group
```

## Credential scoping

Credentials auto-provisioned from the registry inherit the scope of the secret that created them. Manually created credentials can also be scoped:

```bash
aivault credential create my-openai-staging \
  --provider openai \
  --secret-ref vault:secret:<id> \
  --workspace-id staging
```

## Capability bindings

Capability-to-secret bindings can also be scoped:

```bash
aivault capability bind \
  --capability openai/chat-completions \
  --secret-ref vault:secret:<id> \
  --scope workspace \
  --workspace-id my-workspace
```

## Invocation context

When invoking a capability, pass the execution context to select the right credentials:

```bash
aivault invoke openai/chat-completions \
  --workspace-id my-workspace \
  --group-id my-group \
  --body '{"model":"gpt-5.2","messages":[...]}'
```

The broker uses this context for credential resolution and includes it in the audit log.

Next: [CLI reference](/cli)
