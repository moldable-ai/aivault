---
title: Getting started
description: Store your first secret and make a proxied API call in under a minute.
---

This guide walks you through a complete flow: initialize the vault, store a secret, and invoke a capability — all without exposing the secret to calling code.

**Required reading:** [Security model](/core/security-model) (how aivault keeps secrets safe).

## Prerequisites
- The `aivault` binary installed and on your `PATH` (see [Install](/install))
- On macOS/Linux, `aivaultd` installed alongside `aivault` (used by `invoke` by default). If you only have `aivault`, set `AIVAULTD_DISABLE=1`.
- An API key for at least one supported provider (e.g. OpenAI)

## 1) Check vault status

```bash
aivault status
```

The vault auto-initializes on first run with safe defaults:
- **macOS**: uses the system Keychain
- **Other platforms**: uses the file provider with a key at `~/.aivault/keys/kek.key` (outside the vault directory)

If you prefer a passphrase-protected vault (manual unlock after restart), initialize explicitly:

```bash
aivault init --provider passphrase --passphrase "your-passphrase"
```

See [Vault lifecycle](/cli/vault-lifecycle) for all provider options.

## 2) Store a secret

```bash
aivault secrets create \
  --name OPENAI_API_KEY \
  --value "sk-..." \
  --scope global
```

Because `OPENAI_API_KEY` matches the built-in registry, this automatically:
- **Pins** the secret to the `openai` provider (it can only be used for OpenAI hosts)
- **Provisions** the `openai` credential
- **Enables** all 17 OpenAI capabilities (chat, transcription, embeddings, images, etc.)

## 3) Browse capabilities

```bash
# List all capabilities and their readiness
aivault capability list

# Inspect a specific capability
aivault capability describe openai/chat-completions
```

The `describe` command shows allowed methods, path prefixes, and example invocations.

## 4) Invoke a capability

```bash
aivault invoke openai/chat-completions \
  --method POST \
  --body '{"model":"gpt-5.2","messages":[{"role":"user","content":"hello"}]}'
```

The broker validates the request against capability policy, decrypts the secret from the vault, injects the auth header, and proxies the request to `api.openai.com`. The response is returned with auth-class headers stripped.

For structured output:

```bash
# JSON output
aivault json openai/chat-completions \
  --method POST \
  --body '{"model":"gpt-5.2","messages":[{"role":"user","content":"hello"}]}'

# Markdown output
aivault markdown openai/chat-completions \
  --method POST \
  --body '{"model":"gpt-5.2","messages":[{"role":"user","content":"hello"}]}'
```

## 5) Verify security posture

```bash
# View audit log
aivault audit

# Confirm secrets are never printed
aivault secrets list
```

Secret values are never printed by any command. The audit log records every create, rotate, and invoke event.

## What just happened

```
You (CLI)
  │
  │  "invoke openai/chat-completions with this body"
  ▼
Broker runtime
  ├─ Validated: POST is allowed, path matches /v1/chat/completions
  ├─ Resolved: openai credential → vault secret OPENAI_API_KEY
  ├─ Decrypted: secret from vault (XChaCha20-Poly1305)
  ├─ Injected: Authorization: Bearer sk-... into outgoing request
  ├─ Host: api.openai.com (derived from capability, not from caller)
  ▼
api.openai.com
  │
  ▼
Response returned to you (auth headers stripped)
```

The calling code (you, a script, an agent) never saw the secret. Even if the calling code were compromised, it could only make requests the capability policy allows — to the hosts the registry defines.

## Multi-secret providers

Some providers require multiple secrets (e.g. Trello needs both an API key and a token). The credential auto-provisions once all required secrets are present:

```bash
aivault secrets create --name TRELLO_API_KEY --value "your-key" --scope global
# → Waiting for TRELLO_TOKEN to complete trello credential

aivault secrets create --name TRELLO_TOKEN --value "your-token" --scope global
# → Credential auto-provisioned: trello (17 capabilities enabled)
```

## Bulk import

If you have multiple secrets to store:

```bash
aivault secrets import \
  --entry OPENAI_API_KEY=sk-... \
  --entry ANTHROPIC_API_KEY=sk-ant-... \
  --entry GITHUB_TOKEN=ghp-... \
  --scope global
```

## Isolating test data

To use an isolated vault for testing without touching your real secrets:

```bash
export AIVAULT_DIR="$(mktemp -d)"
aivault status
aivault secrets create --name OPENAI_API_KEY --value sk-test --scope global
aivault invoke openai/chat-completions --body '...'
```

Next: [Security model](/core/security-model)

If you're setting this up for an agent-heavy environment, also see:
- [macOS setup](/macos)
- [Linux / servers setup](/linux-servers)
