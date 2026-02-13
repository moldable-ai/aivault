---
title: Storage
description: File paths and directory layout.
---

## Vault root directory

By default: `~/.aivault/data/vault`

Override with `AIVAULT_DIR`:
```bash
export AIVAULT_DIR=/custom/path
```

## Directory layout

```
~/.aivault/data/vault/
├── vault.json              # Vault provider config and KEK metadata
├── broker.json             # Credentials, custom capabilities, and policy records
├── capabilities.json       # Capability-to-secret bindings
├── secrets/
│   ├── <secret-id-1>.json  # Encrypted secret record
│   ├── <secret-id-2>.json
│   └── ...
└── audit/
    ├── events-<date>.jsonl # Audit events (append-only, one file per day)
    └── ...
```

## File descriptions

### vault.json

Stores the vault provider configuration:
- Provider type (macOS Keychain, passphrase, env, file)
- Provider-specific metadata (Keychain service/account, KDF params, etc.)
- KEK check record (for passphrase provider)

Does **not** contain any secret values or the KEK itself.

### Key file (file provider)

When the vault is auto-initialized with the **file** provider (default on non-macOS, and a fallback on macOS), the KEK is stored in a separate key file:

- Canonical install: `~/.aivault/keys/kek.key` (outside the vault dir)
- When `AIVAULT_DIR` is set: `$AIVAULT_DIR/kek.key` (useful for isolated tests)

If you're backing up or migrating a vault that uses the file provider, you need both the vault directory and the key file.

### broker.json

Stores broker state:
- Credential definitions (provider, auth strategy, hosts, secret references)
- Custom capability definitions (user-created, not registry)
- Advanced policy records (rate limits, size limits, response blocklists)

### capabilities.json

Stores capability-to-secret bindings:
- Which secret is bound to which capability
- Binding scope (global, workspace, group)
- Consumer restrictions

### secrets/*.json

One file per secret. Each contains:
- Secret metadata (ID, name, aliases, scope, pinned provider, timestamps)
- Encrypted value (ciphertext, wrapped DEK, nonce)
- AAD version

Secret values are **never** stored in plaintext.

### audit/*.jsonl

Append-only audit events in newline-delimited JSON. One file per day. Contains:
- Secret lifecycle events (create, rotate, delete, pin, attach, detach)
- Invocation events (capability, credential, timestamps, context)

## Daemon socket

```
~/.aivault/run/aivaultd.sock
```

If `AIVAULT_DIR` is set, the default socket path becomes `$AIVAULT_DIR/run/aivaultd.sock`.

Override with `AIVAULTD_SOCKET`.

Next: [Testing](/ops/testing)
