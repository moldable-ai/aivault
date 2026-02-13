---
title: Vault lifecycle
description: Initialize, unlock, lock, rotate, and audit the vault.
---

## status

Show vault state, provider, and paths.

```bash
aivault status
aivault status --verbose   # full JSON detail
```

Auto-initializes the vault if none exists (macOS Keychain on macOS in the canonical install path; file provider elsewhere).

## init

Initialize the vault with a specific key provider.

```bash
# macOS Keychain (recommended on macOS)
aivault init --provider macos-keychain

# Keychain with custom service/account
aivault init --provider macos-keychain \
  --keychain-service my-app \
  --keychain-account my-account

# Passphrase
aivault init --provider passphrase --passphrase "your-passphrase"

# Environment variable
aivault init --provider env --env-var AIVAULT_KEY

# Key file
aivault init --provider file --file-path /path/to/keyfile
```

See [Vault](/core/vault) for details on each key provider.

## unlock

Unlock a passphrase-protected vault. Only needed when the provider is `passphrase`.

```bash
aivault unlock --passphrase "your-passphrase"
```

## lock

Lock a passphrase-protected vault. The vault will require `unlock` before any secret operations.

```bash
aivault lock
```

## rotate-master

Rotate the vault master encryption key (KEK). Re-wraps every DEK with the new key.

```bash
# Rotate to a new base64 key
aivault rotate-master --new-key <base64-encoded-32-byte-key>

# Rotate to a new passphrase (passphrase provider only)
aivault rotate-master --new-passphrase "new-passphrase"
```

## audit

View the append-only audit log.

```bash
aivault audit                          # last 200 events
aivault audit --limit 50               # last 50 events
aivault audit --before-ts-ms 170000000 # events before timestamp
```

The audit log records every secret lifecycle event (create, rotate, delete, attach, detach) and every proxied invocation. See [Audit log](/security/audit-log).

Next: [Secrets](/cli/secrets)
