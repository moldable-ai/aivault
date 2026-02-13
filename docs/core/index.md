---
title: Core concepts
description: The key ideas behind aivault's zero-trust design.
---

aivault enforces a hard security boundary between untrusted code and API secrets. This section explains the core concepts that make that possible.

## Key ideas

- **Vault** — encrypted secret storage with pluggable key providers (macOS Keychain, passphrase, env var, file). Secrets are encrypted at rest with XChaCha20-Poly1305 and never leave the vault in plaintext except during broker-owned auth injection.
- **Broker** — the zero-trust proxy runtime that validates every request against capability policy, decrypts the secret, injects auth on the wire, and returns a sanitized response.
- **Registry** — a built-in catalog of 30+ provider definitions (OpenAI, Stripe, Slack, GitHub, etc.) with pre-configured auth strategies and capability allow-lists, compiled into the binary.
- **Capabilities** — scoped API permissions that define exactly which methods, paths, and hosts a caller can reach. Callers invoke capabilities, not raw URLs.
- **Credentials** — bindings between a provider, a vault secret, and an auth strategy. For registry providers, credentials auto-provision when you store a matching secret.
- **Scopes** — isolation boundaries (global, workspace, group) that control which secrets and credentials are visible to which callers.

## How they fit together

```
Caller (CLI / agent / SDK)
  │
  │  "invoke openai/chat-completions"
  ▼
Capability policy
  ├─ Allowed methods: POST, GET
  ├─ Allowed paths: /v1/chat/completions
  ├─ Allowed hosts: api.openai.com
  ▼
Credential resolution
  ├─ Provider: openai
  ├─ Secret ref: vault:secret:<id>
  ├─ Auth strategy: header (Bearer {{secret}})
  ▼
Vault decryption
  ├─ Decrypt secret with XChaCha20-Poly1305
  ├─ Inject auth into outgoing request
  ▼
Upstream provider (api.openai.com)
  │
  ▼
Response sanitization
  ├─ Strip auth-class headers
  ├─ Apply response blocklist
  └─ Return to caller
```

## Pages in this section

- [Architecture](/core/architecture) — request flow and component design
- [Security model](/core/security-model) — the zero-trust properties aivault enforces
- [Vault](/core/vault) — encryption, key providers, and secret lifecycle
- [Broker](/core/broker) — the proxy runtime validation pipeline
- [Registry](/core/registry) — built-in provider definitions
- [Auth strategies](/core/auth-strategies) — how secrets become auth headers, query params, path segments, and more
- [Scopes and isolation](/core/scopes-and-isolation) — workspace and group boundaries
