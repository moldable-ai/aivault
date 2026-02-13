---
title: Vault
description: Encrypted secret storage with pluggable key providers.
---

The vault is aivault's encrypted secret store. It holds all secrets at rest, encrypted with XChaCha20-Poly1305, and manages the key hierarchy that protects them.

## Key hierarchy

```
Key Provider (Keychain / passphrase / env / file)
  │
  ▼
KEK (Key Encryption Key)
  │
  ▼
DEK (Data Encryption Key) — per-secret, wrapped by KEK
  │
  ▼
Encrypted secret value (XChaCha20-Poly1305 AEAD)
```

The KEK is derived from or stored by the key provider. Each secret has its own DEK, which is wrapped (encrypted) by the KEK and stored alongside the ciphertext. Decrypting a secret requires unwrapping the DEK with the KEK, then decrypting the value with the DEK.

## Key providers

aivault supports four key providers. Choose one when initializing the vault.

### macOS Keychain (default on macOS)

```bash
aivault init --provider macos-keychain
```

The KEK is stored in the macOS system Keychain under a configurable service/account name. The vault is "unlocked" whenever the Keychain is unlocked (typically when you log in). No passphrase is needed.

**Customize the Keychain entry:**
```bash
aivault init --provider macos-keychain \
  --keychain-service my-app \
  --keychain-account my-account
```

### Passphrase

```bash
aivault init --provider passphrase --passphrase "your-passphrase"
```

The KEK is derived from the passphrase using Argon2 (key derivation function). The vault must be explicitly unlocked after each restart:

```bash
aivault unlock --passphrase "your-passphrase"
```

And can be locked at any time:

```bash
aivault lock
```

### Environment variable

```bash
aivault init --provider env --env-var AIVAULT_KEY
```

The KEK is read from the specified environment variable at startup. The variable must contain a base64-encoded 32-byte key.

### File

```bash
aivault init --provider file --file-path /path/to/keyfile
```

The KEK is read from a file on disk. The file must contain a base64-encoded 32-byte key.

## Auto-initialization

On first run, `aivault status` (or any command that needs the vault) auto-initializes with safe defaults:
- **macOS (canonical install)**: uses macOS Keychain with service `aivault` (and falls back to the file provider if Keychain is unavailable)
- **Other platforms (canonical install)**: uses the file provider with a key at `~/.aivault/keys/kek.key` (outside the vault directory)
- **When `AIVAULT_DIR` is set**: uses the file provider with a key at `$AIVAULT_DIR/kek.key` (useful for isolated tests)

Auto-initialization includes a stale init-lock detector (30-second timeout) and Keychain self-healing (recreates a lost Keychain entry if no secrets exist yet).

## Secret lifecycle

| Event | What happens |
|-------|-------------|
| **Create** | Secret value encrypted, DEK wrapped, metadata stored, audit event logged |
| **Read** | Metadata returned (value never returned to caller) |
| **Rotate** | New value encrypted with new DEK, old DEK discarded, audit event logged |
| **Delete** | Secret record removed, audit event logged |
| **Attach/detach group** | Secret's group membership updated for isolation |

## Associated data (AAD)

Each encrypted secret includes authenticated associated data (AAD v2+):
- Secret ID
- Scope (global / workspace / group)
- Pinned provider (if registry-matched)

This means a ciphertext for one secret cannot be swapped into another secret's record — the AEAD authentication will fail.

## Master key rotation

```bash
aivault rotate-master --new-key <base64-key>
# or
aivault rotate-master --new-passphrase "new-passphrase"
```

This re-wraps every DEK with the new KEK. Secret values themselves are not re-encrypted (the DEKs are unchanged), but the DEK wrappers are updated atomically.

Next: [Broker](/core/broker)
