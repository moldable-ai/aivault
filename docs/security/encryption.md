---
title: Encryption
description: XChaCha20-Poly1305, key hierarchy, and authenticated associated data.
---

## Algorithm

aivault uses **XChaCha20-Poly1305** for all secret encryption. This is an AEAD (Authenticated Encryption with Associated Data) cipher that provides both confidentiality and integrity.

- **XChaCha20**: Stream cipher with a 256-bit key and 192-bit nonce (extended nonce variant, safe for random nonce generation)
- **Poly1305**: MAC for authentication, ensures ciphertext has not been tampered with

## Key hierarchy

```
Key Provider
  │
  │  (macOS Keychain / Argon2(passphrase) / env var / file)
  ▼
KEK (Key Encryption Key) — 256-bit
  │
  │  wraps/unwraps
  ▼
DEK (Data Encryption Key) — per-secret, 256-bit
  │
  │  encrypts/decrypts
  ▼
Secret value ciphertext
```

Each secret has its own randomly generated DEK. The DEK is wrapped (encrypted) by the KEK and stored in the secret record alongside the ciphertext. To decrypt a secret:

1. Retrieve KEK from key provider
2. Unwrap the DEK using the KEK
3. Decrypt the secret value using the DEK
4. Verify the AEAD tag and associated data

## Key derivation (passphrase provider)

When using the passphrase key provider, the KEK is derived using **Argon2** (memory-hard key derivation function):

```
passphrase → Argon2(salt, params) → 256-bit KEK
```

The Argon2 parameters (memory cost, time cost, parallelism) and salt are stored in the vault metadata. This makes brute-force attacks against the passphrase computationally expensive.

## Authenticated associated data (AAD)

Each secret's ciphertext is bound to its metadata via AAD (version 2+):

| AAD field | Purpose |
|-----------|---------|
| Secret ID | Prevents swapping ciphertext between secrets |
| Scope | Prevents moving a workspace secret to global |
| Pinned provider | Prevents re-pinning a secret to a different provider |

If any AAD field doesn't match during decryption, the AEAD authentication fails and the operation is rejected. This prevents an attacker who has write access to vault files from performing secret-swap attacks.

## On-disk format

Secret records are stored as JSON files in `secrets/<secret_id>.json`:

```json
{
  "secret_id": "uuid",
  "name": "OPENAI_API_KEY",
  "scope": "global",
  "pinned_provider": "openai",
  "ciphertext": "<base64>",
  "wrapped_dek": "<base64>",
  "nonce": "<base64>",
  "aad_version": 2,
  "value_version": 1,
  "created_at_ms": 1700000000000,
  "updated_at_ms": 1700000000000
}
```

The `ciphertext`, `wrapped_dek`, and `nonce` fields are all base64-encoded binary. The `value_version` increments on each rotation.

## Master key rotation

`aivault rotate-master` re-wraps every DEK with the new KEK:

1. Derive new KEK from new passphrase/key
2. For each secret: unwrap DEK with old KEK, re-wrap with new KEK
3. Update vault metadata with new key provider config
4. Verify: unwrap all DEKs with new KEK to confirm

The secret ciphertexts themselves are unchanged — only the DEK wrappers are updated. This makes rotation fast even with many secrets.

## Zeroization

Sensitive values (decrypted secrets, DEKs, KEKs) are zeroized in memory after use using the `zeroize` crate. This reduces the window during which secrets exist in plaintext memory.

Next: [Audit log](/security/audit-log)
