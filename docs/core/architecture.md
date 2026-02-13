---
title: Architecture
description: How requests flow through the vault, broker, and upstream provider.
---

aivault has three core layers: the **vault** (encrypted secret storage), the **broker** (policy-enforced proxy runtime), and the **registry** (built-in provider definitions).

## Request flow

Every proxied request follows this pipeline:

```
1. Envelope parsing
   Caller sends: { capability, credential?, request: { method, path, headers, body } }

2. Capability lookup
   Broker finds the capability definition (registry or user-created)

3. Credential resolution
   Determines which credential to use:
   ├─ Explicit: caller specifies --credential
   ├─ Scoped: workspace/group match
   └─ Default: first credential for the capability's provider

4. Policy validation
   ├─ Request method in allow.methods?
   ├─ Request path starts with allow.pathPrefixes?
   ├─ Request host in credential's hosts list?
   └─ Advanced policy (rate limits, body size, response blocklist)?

5. Auth injection
   ├─ Decrypt secret from vault
   ├─ Render auth template (Bearer {{secret}}, query param, path prefix, etc.)
   └─ Inject into outgoing request headers/query/path

6. Request building
   ├─ Host derived from capability policy (not caller)
   ├─ Scheme always HTTPS
   └─ Caller-supplied auth headers rejected

7. Upstream execution
   Send request via HTTP client (reqwest + TLS)

8. Response sanitization
   ├─ Strip auth-class response headers
   ├─ Apply response body blocklist
   └─ Return to caller
```

## Component map

| Component | Location | Responsibility |
|-----------|----------|----------------|
| **Vault** | `src/vault/` | Encrypted secret storage, key providers, audit log |
| **Broker** | `src/broker/` | Request validation, auth injection, upstream execution |
| **Registry** | `registry/`, `src/registry.rs` | Built-in provider definitions (compiled into binary) |
| **CLI** | `src/cli.rs`, `src/app.rs` | User-facing command interface |
| **Daemon** | `src/daemon.rs`, `src/bin/aivaultd.rs` | Background process for secret isolation |

## Key design decisions

**Host derived from policy, not caller.** The upstream host is never taken from the caller's request. It's derived from the capability's allow-list. This prevents SSRF and exfiltration through crafted requests.

**Auth headers are broker-owned.** Callers cannot supply or override auth-class headers (`authorization`, `x-api-key`, etc.). The broker injects them after policy validation.

**Registry compiled into binary.** Provider definitions are embedded at build time from the `registry/` directory. This prevents runtime forgery of provider definitions.

**Single host per capability.** Each capability allow-list targets exactly one host (Core conformance). This simplifies policy reasoning and prevents cross-host confusion.

**Secret pinning.** Secrets with names matching a registry provider's `vaultSecrets` are immutably pinned to that provider. A pinned `OPENAI_API_KEY` can only be used for `api.openai.com`.

## Data flow diagram

```
┌─────────────────────────────────────────────┐
│  Caller (CLI / agent / SDK)                 │
│  ─ Never sees secrets                       │
│  ─ Can only invoke approved capabilities    │
│  ─ Cannot specify upstream host             │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Broker runtime                             │
│  ─ Validates capability policy              │
│  ─ Resolves credential + decrypts secret    │
│  ─ Injects auth on the wire                 │
│  ─ Builds request with policy-derived host  │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Upstream provider                          │
│  ─ Receives authenticated request           │
│  ─ Returns response                         │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│  Response pipeline                          │
│  ─ Strips auth-class headers                │
│  ─ Applies response blocklist               │
│  ─ Returns sanitized response to caller     │
└─────────────────────────────────────────────┘
```

Next: [Security model](/core/security-model)
