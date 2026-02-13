---
title: macOS setup
description: Recommended macOS setup for aivault when untrusted agents may have filesystem/process access.
---

This page focuses on hardening `aivault` on macOS when you expect AI agents, plugins, or generated code to run locally with broad access.

## Human-Only Secret Entry (Do This By Default)

By default, the only “actor” that should ever enter secret values into aivault is a **human**, manually.

Do not ask an AI agent or coding LLM to “set the secret for you” (for example by pasting API keys into a chat). Many agent frameworks log conversations, tool calls, and intermediate context. If you paste a key into an agent chat, assume it may be stored, indexed, or exfiltrated.

Recommended workflow:
- Human obtains the secret from the provider dashboard.
- Human runs `aivault secrets create ...` locally and never shares the secret value with the agent.
- Agents only run `aivault invoke ...` (capability invocations), never `secrets create`.

## Security goal (be explicit)

aivault’s core promise is: **callers never see secrets**. That promise holds best when untrusted code:
- cannot access your vault key provider (macOS Keychain / passphrase / key file), and
- cannot impersonate an operator who can create/rotate/delete secrets or relax policy.

If untrusted code runs as the same macOS user with full terminal and Keychain access, no tooling can give perfect secrecy. In that case, treat this as a hardening exercise: reduce blast radius and make misuse auditable.

## Pattern A: Separate macOS user accounts (recommended when running local agents)

macOS has strong per-user boundaries:
- Keychain items are per-user.
- Home directories and app data are typically only readable by that user.

If you run untrusted agents as the same macOS user that owns the aivault Keychain entry and vault files, those agents may be able to access the same Keychain items and local files.

The simplest hardening step is to run agents under a different macOS user account than the one that owns your aivault vault + Keychain entry.

### Step-by-step tutorial

1. Create a dedicated “agent” macOS user in System Settings (Users & Groups).
2. Keep aivault under your human/operator account (the account that will enter secrets).
3. Run agent frameworks/tools only under the agent account.

What this gets you:
- An agent running under the agent account cannot trivially read your operator account’s Keychain items or home directory files.

### Letting agents invoke without exposing keys (shared daemon, “just works”)

This is the primary “same machine” setup:
- Your human/operator account owns the vault + Keychain entry and runs `aivaultd`.
- Your agent account runs untrusted tools and only connects to the operator daemon over a shared unix socket.
- The agent never sees provider API keys.

**Goal:** on the agent account, `aivault invoke ...` should work with **zero flags** and **no environment variables**.

#### Step-by-step (recommended)

0. Ensure `aivault` and `aivaultd` are installed somewhere both accounts can execute (for example `/usr/local/bin`).

1. One-time: configure cross-user socket access (run as your operator account):

```bash
sudo aivault setup agent-access --agent-user agent
```

This creates/updates a shared group (`aivault`), adds both users, and creates the shared socket directory with restrictive permissions.

2. Start the shared daemon (operator side):

```bash
aivaultd --shared
```

Or install a LaunchAgent so it starts automatically at login:

```bash
aivault setup launchd
```

3. Agent usage (agent account):

```bash
aivault invoke openai/chat-completions --method POST --path /v1/chat/completions --body '...'
```

No `--shared`, no `AIVAULTD_SOCKET`, no `AIVAULTD_AUTOSTART=0`.

How it works:
- The `aivault` CLI auto-discovers a shared daemon socket at `/Users/Shared/aivault/run/aivaultd.sock`.
- When invoking via the shared socket, autostart is suppressed (the agent account cannot and should not try to start its own daemon).

Important:
- Socket access grants “ability to invoke configured capabilities”, so treat membership in the `aivault` group as sensitive.
- This does not make an untrusted agent “safe” if it can become root or otherwise escape OS boundaries.

## Recommended baseline (developer laptop)

1. Install both binaries (`aivault` and `aivaultd`) and verify:

```bash
aivault status
```

2. Keep the canonical data location (recommended):
- Vault dir: `~/.aivault/data/vault`
- Daemon socket: `~/.aivault/run/aivaultd.sock`

3. Use the default key provider for the canonical install:
- By default, macOS uses **Keychain** (service `aivault`, account `kek`).

## Key provider choices on macOS

### macOS Keychain (best UX)

Pros:
- No passphrase to manage for daily use.
- KEK is not stored in the vault directory.

Cons:
- If untrusted code can read your Keychain item (or run as you), it can defeat the vault boundary.

Initialize explicitly (optional):

```bash
aivault init --provider macos-keychain
```

### Passphrase (strongest separation if agents cannot prompt you)

Pros:
- You can keep the passphrase out of the agent runtime.
- After reboot/restart, the vault stays locked until you unlock it.

Cons:
- Interactive operational overhead (you must unlock before use).

```bash
aivault init --provider passphrase --passphrase "your-passphrase"
aivault unlock --passphrase "your-passphrase"
```

### File provider (not recommended when untrusted code can read your home directory)

If the KEK lives in a readable key file, any code with filesystem access to that file can decrypt the vault.

Default key file location for the canonical install:
- `~/.aivault/keys/kek.key`

## Hardening checklist (agent-heavy environments)

- Run untrusted agents in a different macOS user account, container, or VM when possible.
- Prefer a passphrase vault if you can keep the passphrase out of the agent runtime.
- Keep capabilities tight: only enable what you need, and prefer least-privileged capability IDs.
- Add rate limits and size limits for cost/DoS control:

```bash
aivault capability policy set \
  --capability openai/chat-completions \
  --rate-limit-per-minute 60 \
  --max-request-body-bytes 1048576 \
  --max-response-body-bytes 10485760
```

- Use `aivault audit` as your primary detection tool:

```bash
aivault audit --limit 200
```

## Notes On `aivaultd` (daemon boundary)

On macOS, `aivault invoke` uses `aivaultd` by default so decrypted secrets and auth injection happen in the daemon process rather than the CLI process.

If you only installed `aivault` (without `aivaultd`), you can force in-process execution:

```bash
export AIVAULTD_DISABLE=1
```

Next: [Linux / servers setup](/linux-servers)
