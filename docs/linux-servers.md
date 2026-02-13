---
title: Linux / servers setup
description: Recommended Linux/server setup for aivault when untrusted agents may have filesystem/process access.
---

This page focuses on production-ish setups (Linux workstations, servers, CI runners) where untrusted code may run locally and you want to keep secrets out of that runtime.

## Human-Only Secret Entry (Do This By Default)

By default, the only “actor” that should ever enter secret values into aivault is a **human**, manually.

Do not ask an AI agent or coding LLM to “set the secret for you” (for example by pasting API keys into a chat). Many agent frameworks log conversations, tool calls, and intermediate context. If you paste a key into an agent chat, assume it may be stored, indexed, or exfiltrated.

Recommended workflow:
- Human obtains the secret from the provider dashboard.
- Human runs `aivault secrets create ...` on the target machine and never shares the secret value with the agent.
- Agents only run `aivault invoke ...` (capability invocations), never `secrets create`.

## Security goal (be explicit)

aivault protects secrets best when the untrusted runtime:
- cannot read the vault KEK (file/env/passphrase) and
- cannot act as an operator who can create/rotate/delete secrets or loosen capability policy.

If the same Linux user can read both the vault directory and the KEK source, the vault can be decrypted. Plan your OS-level boundaries accordingly.

## Default behavior on Linux

On first run, a canonical install auto-initializes using the **file** provider:
- Vault dir: `~/.aivault/data/vault`
- KEK file: `~/.aivault/keys/kek.key` (outside the vault dir)
- Daemon socket (when using `aivaultd`): `~/.aivault/run/aivaultd.sock`

Verify:

```bash
aivault status
```

## Recommended patterns

### Pattern A: Dedicated OS user for aivault (recommended for servers)

Run aivault under a dedicated unix user (for example `aivault`) and run untrusted agents under a different user. This protects the vault because Linux filesystem access is governed by unix permissions: a process running as one user generally cannot read files owned `0600` by another user.

Practical notes:
- Keep the KEK source (file/env/passphrase) available only to the `aivault` user.
- Keep the vault directory readable/writable only by the `aivault` user.
- Do not run untrusted agent code as the `aivault` user.

#### Step-by-step tutorial (minimal hardened setup)

1. Create two unix users (one for aivault, one for agents):

```bash
sudo useradd -m -s /bin/bash aivault
sudo useradd -m -s /bin/bash agent
```

2. Install `aivault` and `aivaultd` somewhere root-owned (example):

```bash
sudo install -m 0755 aivault /usr/local/bin/aivault
sudo install -m 0755 aivaultd /usr/local/bin/aivaultd
```

3. Initialize the vault and enter secrets as a human (run as the `aivault` user). Do this once per provider:

```bash
sudo -u aivault -H aivault status
sudo -u aivault -H aivault secrets create --name OPENAI_API_KEY --value "sk-..." --scope global
```

4. Verify the key file and vault files are not readable by the `agent` user.

If using the default file-provider on Linux, the key is typically stored at:
- `~aivault/.aivault/keys/kek.key`

You should see restrictive perms (for example `-rw-------`):

```bash
sudo -u aivault -H ls -la /home/aivault/.aivault/keys
sudo -u aivault -H ls -la /home/aivault/.aivault/keys/kek.key
```

And as the `agent` user, this should fail:

```bash
sudo -u agent -H cat /home/aivault/.aivault/keys/kek.key
```

If the agent user can read the KEK file, the separation is not working and you should fix ownership/permissions before proceeding.

#### Letting agents invoke without exposing keys (shared socket pattern)

The usual goal is:
- secrets + KEK live with the `aivault` unix user
- agents can invoke capabilities by connecting to `aivaultd`
- agents still cannot read the KEK source or decrypt secrets

To do that on the same machine, expose only the **unix socket** to the agent user (not the vault key). This requires group-based permissions on the socket directory and socket file.

1. Create an `aivault` group and add both users:

```bash
sudo groupadd aivault || true
sudo usermod -aG aivault aivault
sudo usermod -aG aivault agent
```

2. Create a shared runtime directory for the socket (example: `/var/run/aivault`):

```bash
sudo mkdir -p /var/run/aivault
sudo chown aivault:aivault /var/run/aivault
sudo chmod 0750 /var/run/aivault
```

3. Run `aivaultd` as the `aivault` user with a group-readable socket:

```bash
sudo -u aivault -H env \\
  AIVAULTD_SOCKET=/var/run/aivault/aivaultd.sock \\
  AIVAULTD_SOCKET_DIR_MODE=0750 \\
  AIVAULTD_SOCKET_MODE=0660 \\
  aivaultd
```

4. Configure the agent runtime to use that socket and avoid autostarting its own daemon:

```bash
export AIVAULTD_SOCKET=/var/run/aivault/aivaultd.sock
export AIVAULTD_AUTOSTART=0
```

Now the agent can run `aivault invoke ...` against capabilities that the daemon knows about, without ever seeing the provider API keys.

Notes:
- This works best with registry-backed capabilities. For custom capabilities, prefer invoking via `--request` / `--request-file` and include `--method` + `--path` explicitly.
- Install `aivault` system-wide (or otherwise on the agent user's `PATH`). With the thin-client invoke path, the agent does not need local read access to the vault files to invoke via the daemon socket.
- If the agent can become `root`, it can defeat OS-level isolation. Treat “no root” as a prerequisite.

### Pattern B: Passphrase vault (when you can unlock interactively)

If you can tolerate manual unlock after restarts, passphrase mode can reduce unattended exposure:

```bash
aivault init --provider passphrase --passphrase "your-passphrase"
aivault unlock --passphrase "your-passphrase"
```

### Pattern C: Env provider (only if you have a secure secret source)

The env provider reads a base64-encoded 32-byte KEK from an environment variable. This is only safe if your process supervisor provides the variable securely (and untrusted code cannot read it).

```bash
aivault init --provider env --env-var AIVAULT_KEY
```

## Hardening checklist (agent-heavy environments)

- Prefer separate unix users: operator/aivault user vs agent user.
- Keep capabilities tight and add rate limits/size limits:

```bash
aivault capability policy set \
  --capability openai/chat-completions \
  --rate-limit-per-minute 60 \
  --max-request-body-bytes 1048576 \
  --max-response-body-bytes 10485760
```

- Watch the audit log for misuse:

```bash
aivault audit --limit 200
```

- Treat `AIVAULT_DIR` as a foot-gun in shared environments: it changes where the vault (and sometimes daemon socket) lives. Prefer leaving it unset in production unless you have an explicit ops reason.

## Running with `aivaultd`

On Linux, `aivault invoke` uses `aivaultd` by default (unix socket). For server deployments, you’ll typically want the daemon to already be running:

```bash
export AIVAULTD_AUTOSTART=0
```

Then run `aivaultd` under your process supervisor and point the CLI at its socket (optional):

```bash
aivaultd --socket ~/.aivault/run/aivaultd.sock
```

## Example: Fly.io Machine (Best-Effort Hardening)

Fly Machines are great for running a small Linux VM, but the core rule still applies:
keep **secret entry** human-only, and keep the **vault key (KEK)** out of any untrusted/agent runtime.

This is a practical pattern when you have an app that may run “agent-like” code and you want to reduce the chance that code can ever access the vault key.

### Goal

- `aivaultd` can decrypt and inject auth (it has access to the KEK).
- Your app/agent process can invoke capabilities, but does not have the KEK in its environment.

### Pattern: env-provider KEK only for the daemon process

1. Store a random KEK as a Fly secret (do this as a human, not via an agent):

```bash
# Example: generate a 32-byte base64 key (KEK)
openssl rand -base64 32

# Then set it as a Fly secret (example name matches aivault docs/code)
fly secrets set AIVAULT_KEY="<base64-32-byte-key>"
```

2. Initialize the vault explicitly to use the env provider (so the KEK is never written to disk):

```bash
aivault init --provider env --env-var AIVAULT_KEY
```

3. Start `aivaultd` with access to `AIVAULT_KEY`, then start your app with `AIVAULT_KEY` removed from its environment:

```bash
# Start daemon (has AIVAULT_KEY)
aivaultd --socket ~/.aivault/run/aivaultd.sock &

# Start app/agent runtime without the KEK in its environment
unset AIVAULT_KEY
exec ./your-app
```

Notes:
- This doesn’t magically sandbox your app. It is a “keep the KEK out of the agent runtime” best-effort step.
- On Linux, a process running as the same unix user can often read `/proc/<pid>/environ` for sibling processes. If your agent and daemon run as the same user, assume the agent may be able to read `AIVAULT_KEY` unless you add OS hardening (or separate users/VMs).
- If your app can run as root (or escape its sandbox), you still need stronger OS-level isolation.

Next: [Operations](/ops)
