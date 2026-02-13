---
title: Environment variables
description: All environment variables aivault respects.
---

## Vault configuration

| Variable | Description |
|----------|-------------|
| `AIVAULT_DIR` | Override the vault root directory (default: `~/.aivault/data/vault`) |
| `AIVAULT_KEY` | Vault master key (base64-encoded, for the `env` key provider) |
| `AIVAULT_DISABLE_DISK_LOGS` | Set to `1` to suppress audit log writes to disk |

## Daemon configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AIVAULTD_DISABLE` | `0` | Set to `1` to run broker in-process (skip daemon) |
| `AIVAULTD_AUTOSTART` | `1` | Set to `0` to require daemon already running |
| `AIVAULTD_AUTOSTART_ONCE` | `0` | Set to `1` to auto-start `aivaultd` with `--once` (serve one request then exit). Enabled automatically when `AIVAULT_DIR` is set. |
| `AIVAULTD_SOCKET` | `~/.aivault/run/aivaultd.sock` | Override the daemon unix socket path (default is `$AIVAULT_DIR/run/aivaultd.sock` when `AIVAULT_DIR` is set) |
| `AIVAULTD_SOCKET_MODE` | `0600` | Override the daemon unix socket file mode (octal), e.g. `0660` to allow group access |
| `AIVAULTD_SOCKET_DIR_MODE` | `0700` | Override the daemon unix socket directory mode (octal), e.g. `0750` to allow group traversal |

## Development / testing

These variables are for local and e2e testing only. Do not use them in production.

In release builds, the dev-only escape hatches are disabled to avoid foot-guns. If any of these are set, `aivault` will fail closed with an error:
- `AIVAULT_DEV_ALLOW_HTTP_LOCAL`
- `AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS`
- `AIVAULT_DEV_ALLOW_REMOTE_CLIENTS`
- `AIVAULT_DEV_HTTP1_ONLY`
- `AIVAULT_DEV_CA_CERT_PATH`
- `AIVAULT_DEV_RESOLVE`

| Variable | Description |
|----------|-------------|
| `AIVAULT_DEV_RESOLVE` | Override DNS resolution with `host=ip:port` pairs (comma-separated) |
| `AIVAULT_DEV_CA_CERT_PATH` | Path to a PEM CA/root certificate for local TLS testing |
| `AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS` | Set to `1` to allow explicit `host:port` authorities |
| `AIVAULT_DEV_HTTP1_ONLY` | Set to `1` to force HTTP/1.1 for simple local listeners |
| `AIVAULT_DEV_ALLOW_HTTP_LOCAL` | Set to `1` to allow `http://localhost`-style upstreams for local testing (debug builds only) |
| `AIVAULT_DEV_ALLOW_REMOTE_CLIENTS` | Set to `1` to allow non-loopback `--client-ip` values (debug builds only) |
| `AIVAULT_DEV_FORCE_DEFAULT_FILE_PROVIDER` | Set to `1` to force vault auto-init to use the file provider (useful for CI/headless macOS) |
| `AIVAULT_E2E_NETWORK` | Set to `1` to enable e2e tests that hit real upstream APIs |

## Example: isolated test environment

```bash
export AIVAULT_DIR="$(mktemp -d)"
export AIVAULTD_DISABLE=1
aivault status
aivault secrets create --name OPENAI_API_KEY --value sk-test --scope global
aivault invoke openai/chat-completions --body '...'
```

Next: [Storage](/ops/storage)
