---
title: Daemon
description: The aivaultd background process for secret isolation.
---

On unix platforms (macOS/Linux), `aivault invoke` connects to a background daemon (`aivaultd`) over a unix socket. Secret decryption and auth injection happen inside the daemon process, not the CLI process — adding an extra isolation layer.

## Why this exists

The daemon boundary is an extra hardening step for agent-heavy environments:
- The CLI stays a thin client that sends an invocation envelope.
- Decryption + auth injection happen in the daemon process, not the caller process.
- **Operational flexibility**: you can run the daemon under a different execution context later (different user, tighter filesystem permissions, supervisor-managed lifecycle), without changing the invoke contract.

## How it works

```
CLI process                           Daemon process (aivaultd)
  │                                     │
  │  invoke openai/chat-completions     │
  │  ─────────────────────────────────▶ │
  │  (unix socket)                      │
  │                                     ├─ Decrypt secret from vault
  │                                     ├─ Validate capability policy
  │                                     ├─ Inject auth into request
  │                                     ├─ Proxy to upstream provider
  │                                     ├─ Sanitize response
  │  ◀───────────────────────────────── │
  │  response                           │
  ▼                                     ▼
```

The CLI process never touches decrypted secrets — it sends the invocation envelope to the daemon and receives the sanitized response.

## Auto-start

By default, `aivault invoke` auto-starts the daemon if it's not already running. The daemon runs in the background and listens on a unix socket.

**Socket path**:
- Default: `~/.aivault/run/aivaultd.sock`
- If `AIVAULT_DIR` is set: `$AIVAULT_DIR/run/aivaultd.sock`
- Override: `$AIVAULTD_SOCKET`

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AIVAULTD_DISABLE` | `0` | Set to `1` to skip the daemon and run the broker in-process |
| `AIVAULTD_AUTOSTART` | `1` | Set to `0` to require the daemon already running (no auto-start) |
| `AIVAULTD_AUTOSTART_ONCE` | `0` | Set to `1` to auto-start the daemon in `--once` mode (serve one request then exit). Enabled automatically when `AIVAULT_DIR` is set. |
| `AIVAULTD_SOCKET` | `~/.aivault/run/aivaultd.sock` | Override the unix socket path |
| `AIVAULTD_SOCKET_MODE` | `0600` | Override the unix socket file mode (octal). Useful for allowing group access (e.g. `0660`). |
| `AIVAULTD_SOCKET_DIR_MODE` | `0700` | Override the unix socket directory mode (octal). Useful for allowing group traversal (e.g. `0750`). |

When using a non-default `AIVAULTD_SOCKET` directory, aivault avoids changing permissions on arbitrary existing directories. You should ensure the socket directory permissions are appropriately restrictive for your environment.

## Running the daemon manually

```bash
# Use the default socket path
aivaultd

# Or specify a socket explicitly
aivaultd --socket ~/.aivault/run/aivaultd.sock

# Serve a single request and exit (useful for tests)
aivaultd --once
```

This starts the daemon in the foreground, useful for debugging. In normal operation, the CLI auto-starts it in the background.

## When to disable the daemon

Set `AIVAULTD_DISABLE=1` to run the broker in-process:
- **Development/debugging**: easier to attach a debugger or see logs
- **Single-process deployments**: when the extra isolation isn't needed
- **Environments without unix sockets**: (not common)

```bash
AIVAULTD_DISABLE=1 aivault invoke openai/chat-completions --body '...'
```

Next: [Environment variables](/ops/environment)
