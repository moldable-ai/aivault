# Daemon Isolation — Cross-User Agent Access via Shared Socket

## The problem

aivault exists so that untrusted code (AI agents, skills, generated scripts) can invoke API capabilities without seeing secrets. The recommended macOS hardening is to run agents under a separate user account so they can't read the operator's Keychain or vault files.

But the current docs describe the cross-user setup as a "tradeoff" requiring manual group creation, directory permissions, and env var configuration on the agent account. That framing is backwards — cross-user daemon invocation is the primary use case, not an edge case. The ergonomics should reflect that.

Today's setup requires:

1. Manually creating a shared group with `dseditgroup`
2. Adding both users to it
3. Creating a shared socket directory with correct ownership and permissions
4. Setting `AIVAULTD_SOCKET` and `AIVAULTD_SOCKET_MODE` and `AIVAULTD_SOCKET_DIR_MODE` env vars on the operator side
5. Setting `AIVAULTD_SOCKET` and `AIVAULTD_AUTOSTART=0` env vars on the agent side

That's six manual steps spread across two accounts. It should be one command and zero agent-side configuration.

## Design

### Threat model inversion

In the traditional security model, "another user can talk to your daemon" is a vulnerability. In aivault's model, it's the entire point. The daemon is the control plane.

| Traditional app | aivault |
|---|---|
| Socket access = data access | Socket access = policy-gated invocation |
| Sharing a socket leaks secrets | Sharing a socket is how you avoid leaking secrets |
| Cross-user access = privilege escalation | Cross-user access = intended delegation |

The socket gives the agent **capability invocation**, not **key access**. The operator controls the blast radius:

- **Which capabilities exist** — the agent can only invoke what the operator configured
- **What hosts/methods/paths are allowed** — policy-enforced per capability
- **Rate limits** — cost and DoS control per capability
- **Audit trail** — every invocation by every caller is logged
- **Group membership** — only users in the `aivault` group can connect to the socket

The real access control isn't "can you reach the socket" — it's "what can you do once you're there." That's entirely under the operator's control via capabilities, policies, and proxy tokens.

This is the same pattern as `ssh-agent`: the agent connects to a socket, and the daemon on the other side holds the keys and enforces policy. In aivault's case it's stronger than ssh-agent because invocations are capability-scoped, rate-limited, host/method/path policy-enforced, and audit-logged.

### Well-known shared socket location

Define a platform-specific shared socket path:

- **macOS**: `/Users/Shared/aivault/run/aivaultd.sock`
- **Linux**: `/var/run/aivault/aivaultd.sock`

### Socket auto-discovery (client side)

When the `aivault` CLI needs to connect to the daemon, it resolves the socket path in this order:

1. `AIVAULTD_SOCKET` env var (explicit override — same as today)
2. `~/.aivault/run/aivaultd.sock` (per-user default)
3. Shared socket path (see above)

On the agent account, steps 1 and 2 miss, step 3 hits, and invocation "just works" with zero configuration.

When connecting via the shared socket (step 3), autostart is automatically suppressed — the agent account can't and shouldn't start a daemon as a different user.

### `aivaultd --shared` flag (operator side)

A single flag that is sugar for:

- Socket path = shared socket path
- Socket mode = `0660` (group-readable)
- Socket dir mode = `0750` (group-traversable)

One flag instead of three env vars.

### `aivault setup agent-access` command

A single command that handles all OS plumbing. Same UX on both platforms, different commands under the hood.

```bash
sudo aivault setup agent-access --agent-user agent
```

This command:

1. Creates the `aivault` shared group (idempotent)
2. Adds the current user to the group
3. Adds the specified agent user to the group
4. Creates the shared socket directory with `0750`, group `aivault`
5. Prints confirmation and next steps

Requires `sudo` but only once, during initial setup.

**macOS** (developer laptop — operator runs vault on their own account, agent is a separate macOS user):

| Step | Command |
|---|---|
| Create group | `dseditgroup -o create aivault` |
| Add users | `dseditgroup -o edit -a <user> -t user aivault` |
| Socket dir | `/Users/Shared/aivault/run/` |

**Linux** (server — dedicated `aivault` OS user owns the vault, agent is a separate OS user):

| Step | Command |
|---|---|
| Create group | `groupadd aivault` |
| Add users | `usermod -aG aivault <user>` |
| Socket dir | `/var/run/aivault/` |

The Linux case is the primary server deployment model. The current `docs/linux-servers.md` Pattern A ("dedicated OS user for aivault") describes the same six manual steps that this command replaces.

## User experience

### macOS (developer laptop)

Setup (once, as the operator):

```bash
sudo aivault setup agent-access --agent-user agent
aivaultd --shared
```

Agent usage (zero config on the agent account):

```bash
aivault invoke openai/chat-completions --path /v1/chat/completions --body '...'
```

### Linux (server)

Setup (once, as root or the aivault user):

```bash
sudo aivault setup agent-access --agent-user agent
sudo -u aivault -H aivaultd --shared
```

Agent usage (zero config on the agent account):

```bash
sudo -u agent -H aivault invoke openai/chat-completions --path /v1/chat/completions --body '...'
```

### How it works (both platforms)

The CLI auto-discovers the shared socket. The daemon running as the operator/aivault user decrypts, injects auth, enforces policy, audits, and proxies. The agent never sees any keys.

### What the operator controls

The agent account can invoke any capability the operator has configured, subject to the policies the operator defined. For finer-grained control (e.g., the agent can use `openai/chat-completions` but not `stripe/charges`), the operator can:

- Only configure the capabilities the agent should have access to
- Mint scoped proxy tokens for specific agent sessions
- Set per-capability rate limits and body size limits

For the common case of "I have an AI coding agent that needs to call OpenAI and GitHub," group-level socket access with capability policies is the right granularity.

## Implementation

### Changes required

| File | Change |
|---|---|
| `src/daemon.rs` | Add `shared_socket_path()` constant (platform-specific) |
| `src/app.rs` | Add shared socket fallback to daemon connection logic; suppress autostart when using shared path |
| `src/bin/aivaultd.rs` | Add `--shared` CLI flag |
| `src/cli.rs` | Add `setup agent-access` subcommand |
| `docs/macos.md` | Rewrite to present shared daemon as the primary agent pattern |
| `docs/linux-servers.md` | Rewrite Pattern A to use `setup agent-access` + `--shared`; simplify shared socket section |

### Shared socket path

```rust
// src/daemon.rs
pub fn shared_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    { PathBuf::from("/Users/Shared/aivault/run/aivaultd.sock") }
    #[cfg(not(target_os = "macos"))]
    { PathBuf::from("/var/run/aivault/aivaultd.sock") }
}
```

### Client-side fallback

In `src/app.rs`, after the initial connection attempt to the per-user socket fails:

1. Check if the shared socket exists and is connectable
2. If yes, use it (no autostart)
3. If no, fall through to existing autostart logic for the per-user socket

### `aivaultd --shared`

In `src/bin/aivaultd.rs`:

```rust
#[arg(long)]
shared: bool,
```

When `--shared` is set:
- Socket path defaults to `shared_socket_path()` (unless `--socket` also provided)
- Socket mode = `0660`
- Socket dir mode = `0750`

### `aivault setup agent-access`

Shells out to platform-native system commands. This is intentionally a thin wrapper — the commands are well-understood, idempotent, and the operator can inspect exactly what happened.

macOS example:

```
$ sudo aivault setup agent-access --agent-user agent

Created group 'aivault'
Added user 'rob' to group 'aivault'
Added user 'agent' to group 'aivault'
Created /Users/Shared/aivault/run/ (mode 0750, group aivault)

Next steps:
  1. Start the shared daemon:  aivaultd --shared
  2. On the agent account, aivault invoke will auto-discover the shared daemon.
```

Linux example:

```
$ sudo aivault setup agent-access --agent-user agent

Created group 'aivault'
Added user 'aivault' to group 'aivault'
Added user 'agent' to group 'aivault'
Created /var/run/aivault/ (mode 0750, group aivault)

Next steps:
  1. Start the shared daemon:  sudo -u aivault -H aivaultd --shared
  2. On the agent account, aivault invoke will auto-discover the shared daemon.
```

## Docs narrative (revised)

Both `docs/macos.md` and `docs/linux-servers.md` should lead their agent-isolation sections with:

> **How it works:** The operator runs the vault and daemon on their account. Agents run under a separate OS user. When an agent runs `aivault invoke`, the CLI automatically discovers the operator's daemon via a shared socket. The agent never sees API keys — all secret injection, policy enforcement, and auditing happen in the operator's daemon process.

The manual group/directory/env-var steps remain documented as the "manual setup" alternative for users who want full control, but they're no longer the primary path.

### Linux-specific notes

The Linux docs currently have a "Fly.io Machine" example that uses `unset AIVAULT_KEY` as best-effort isolation within a single user. That pattern is complementary — it's for environments where you can't have two OS users (single-user containers). The shared socket pattern is strictly better when two OS users are available, and the docs should make that hierarchy clear.
