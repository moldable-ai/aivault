---
title: Testing
description: Running tests and CI for aivault.
---

## Quick commands

```bash
# Lint (clippy with -D warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Type check
cargo check

# Format
cargo fmt

# All tests (local only, no network)
cargo test --all-targets --all-features
```

## Test suites

### Local CLI e2e (always runs)

Tests the full CLI workflow — init, create secret, invoke — without touching external networks. Uses temporary directories for isolation.

```bash
cargo test --test e2e_cli_local
```

### Local TLS listener e2e (always runs)

Tests real proxy round-trips against a deterministic in-process HTTPS listener. Validates TLS, auth injection, and response handling end-to-end.

```bash
cargo test --test e2e_cli_local_tls
```

### Network CLI e2e (opt-in)

Tests real upstream HTTPS calls to actual provider APIs. Requires real API keys and explicit opt-in:

```bash
AIVAULT_E2E_NETWORK=1 cargo test --test e2e_cli_invoke
```

### Daemon e2e

Tests daemon communication, auto-launch, and unix socket handling:

```bash
cargo test --test e2e_daemon
```

### Broker unit tests

Comprehensive tests for the broker validation pipeline — policy checks, host matching, auth injection, path normalization:

```bash
cargo test broker::tests
```

## Dev-only HTTP client overrides

For local TLS testing, the CLI supports development-only overrides:

| Variable | Description |
|----------|-------------|
| `AIVAULT_DEV_RESOLVE` | `host=ip:port` pairs for DNS override (comma-separated) |
| `AIVAULT_DEV_CA_CERT_PATH` | PEM CA/root certificate path |
| `AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS` | Allow explicit `host:port` authorities |
| `AIVAULT_DEV_HTTP1_ONLY` | Force HTTP/1.1 for simple local listeners |

These are intended for local/e2e testing only.

## CI

GitHub Actions runs the same checks on push and pull requests via `.github/workflows/ci.yml`:
- `cargo clippy` with `-D warnings`
- `cargo test` (all local suites)
- `cargo check`
- `cargo fmt --check`
