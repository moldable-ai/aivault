---
title: CLI reference
description: Complete command reference for the aivault CLI.
---

Commands default to colored human-readable output. Many list/status commands accept `--verbose` / `-v` for full JSON; `invoke` also has dedicated `json` and `markdown` subcommands for structured output.

## Command groups

| Group | Purpose |
|-------|---------|
| [Vault lifecycle](/cli/vault-lifecycle) | `status`, `init`, `unlock`, `lock`, `rotate-master`, `audit` |
| [Secrets](/cli/secrets) | `secrets create`, `list`, `update`, `rotate`, `delete`, `import` |
| [Credentials](/cli/credentials) | `credential create`, `list`, `delete` |
| [Capabilities](/cli/capabilities) | `capability list`, `describe`, `create`, `delete`, `policy`, `bind`, `unbind`, `bindings` |
| [Invoke](/cli/invoke) | `invoke`, `json`, `markdown` |
| [OAuth](/cli/oauth) | `oauth setup` |

## Top-level shortcuts

These shortcuts avoid typing `capability invoke ...` for the most common operation:

```bash
aivault invoke <id> ...       # same as: aivault capability invoke <id>
aivault json <id> ...         # same as: aivault capability json <id>
aivault markdown <id> ...     # same as: aivault capability markdown <id>
aivault md <id> ...           # alias for markdown
```

## Global behavior

- **Auto-initialization**: if no vault exists, the first command that needs it will auto-initialize with safe defaults
- **Daemon boundary**: on unix platforms, `invoke` commands connect to the `aivaultd` daemon (auto-started) for secret isolation. See [Daemon](/ops/daemon)
- **Output modes**: human-readable (default); JSON via `--verbose` / `-v` on commands that support it; or structured JSON/markdown via the `json`/`markdown` subcommands
