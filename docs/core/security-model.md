---
title: Security model
description: The zero-trust properties aivault enforces and why they matter.
---

aivault enforces a zero-trust boundary between untrusted code and API secrets. This page explains each security property and what it protects against.

## Core properties

### 1. Secrets never leave the vault

Secrets are encrypted at rest with XChaCha20-Poly1305. The only time a secret is decrypted is during broker-owned auth injection — inside the broker process, on the wire, for a single request. The decrypted value is never returned to the caller, logged, or stored in plaintext.

No command prints secret values. `aivault secrets list` shows metadata only.

### 2. Registry-pinned secrets

Secrets with names matching a registry provider's `vaultSecrets` are **immutably pinned** to that provider. For example, `OPENAI_API_KEY` is pinned to the `openai` provider and can only be injected into requests for `api.openai.com`.

This prevents exfiltration through fake capabilities or credentials that try to route a real API key to an attacker-controlled host.

### 3. Host derived from policy

The upstream host is **never** taken from the caller's request. It's derived from the capability's allow-list. A caller who invokes `openai/chat-completions` always hits `api.openai.com` — there is no way to redirect that request to another host.

This prevents SSRF and host-swap exfiltration attacks.

### 4. Auth headers are broker-owned

Callers **cannot** supply or override auth-class headers (`authorization`, `x-api-key`, cookie headers, etc.). The broker injects auth after policy validation. Any caller-supplied auth headers are rejected.

### 5. Path traversal protection

Path traversal sequences (`../`, `./`, encoded variants) are normalized and checked. A request path of `/v1/chat/../../../etc/passwd` is rejected before it reaches the upstream provider.

### 6. Redirect auth stripping

If an upstream provider responds with a 302/303 redirect, auth headers are **not** carried to the redirect target if the host differs. This prevents auth leakage through open redirects.

### 7. Localhost-only by default

The broker only accepts requests from `127.0.0.1` unless explicitly configured otherwise. This means untrusted network peers cannot invoke capabilities.

### 8. Response sanitization

Upstream response headers that carry auth-class information (cookies, auth tokens, session IDs) are stripped before the response reaches the caller. The response body can be further filtered using per-capability response blocklists.

## What this protects against

| Attack | Protection |
|--------|------------|
| **Key exfiltration via env vars** | Secrets are in the vault, not in env vars or files |
| **Prompt injection → read secrets** | No command or API returns secret values |
| **Malicious skill → exfiltrate keys** | Pinned secrets can only reach their registered provider's hosts |
| **SSRF / host-swap** | Host is derived from capability policy, not caller input |
| **Auth header injection** | Callers cannot supply auth-class headers |
| **Path traversal** | Normalized and rejected before reaching upstream |
| **Open redirect → auth leakage** | Auth headers stripped on cross-host redirects |
| **Response sniffing** | Auth-class response headers stripped |
| **Network peer attacks** | Localhost-only binding by default |

## What this does not protect against

aivault is not a sandbox or a firewall. It protects the specific boundary between untrusted code and API secrets. It does **not** protect against:

- **Compromised host machine** — if an attacker has root access to the machine running aivault, they can read vault files and attempt decryption.
- **Compromised key provider** — if the macOS Keychain, environment variable, or key file is compromised, the vault master key is exposed.
- **Side-channel attacks** — timing, power analysis, or memory inspection attacks on the broker process.
- **Upstream provider compromise** — aivault proxies requests to upstream providers. If the provider itself is compromised, aivault cannot protect against that.
- **Authorized misuse** — a user who has legitimate access to aivault can invoke any capability their credentials allow. aivault enforces policy, not intent.

For the full threat model, see [Threat model](/security/threat-model).

## Comparison: env vars vs aivault

| Property | Env vars / .env files | aivault |
|----------|----------------------|---------|
| Secret storage | Plaintext in memory / on disk | Encrypted (XChaCha20-Poly1305) |
| Access control | Any process in the tree | Capability policy per provider |
| Host restriction | None | Pinned to registry-defined hosts |
| Auth injection | Caller does it | Broker does it (caller never sees key) |
| Audit trail | None | Append-only audit log |
| Rotation | Manual find-and-replace | `aivault secrets rotate` (re-encrypts) |
| Multi-tenant | N/A | Workspace + group isolation |

Next: [Vault](/core/vault)
