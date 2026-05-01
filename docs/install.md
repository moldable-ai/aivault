---
title: Install
description: Install the aivault CLI on macOS or Linux.
---

## Install script (recommended)

```bash
curl -fsSL https://aivault.moldable.sh/install.sh | sh
```

This installs prebuilt `aivault` and `aivaultd` binaries for macOS/Linux to `~/.local/bin` by default.
It also copies bundled official provider plugin binaries, such as Postgres, under
`~/.local/bin/providers/`.

Script URL: https://aivault.moldable.sh/install.sh

## From crates.io

```bash
cargo install aivault --locked
```

This installs both binaries:
- `aivault`
- `aivaultd`

It does not install optional provider plugin binaries. Use the install script or release artifacts
when you need bundled providers such as Postgres.

Crate page: https://crates.io/crates/aivault

## From source (Rust)

From the repo root:

```bash
cargo install --path . --locked
```

Or build without installing:

```bash
cargo build --release
# Binary at target/release/aivault
```

For local development where you want to replace your active CLI, daemon, and bundled providers
after a code change:

```bash
pnpm install:local
```

This builds release binaries, updates local `aivault`/`aivaultd` symlinks, installs and enables
the bundled Postgres provider, restarts the per-user daemon, restarts the macOS shared LaunchAgent
when present, and runs a smoke check. Use `pnpm install:local -- --help` for options such as
`--install-dir`, `--no-postgres`, `--no-shared`, and `--no-smoke`.

## From release artifacts

Download the latest release from the GitHub releases page. Artifacts are available for macOS (arm64, x86_64) and Linux (x86_64).

macOS releases are signed and notarized. Linux releases include cosign keyless signatures for CI-driven verification.

Release artifacts include:

- `aivault`
- `aivaultd`
- `providers/postgres/aivault-provider-postgres`

### Verify downloads

Check checksums against the published `.sha256` files:

```bash
shasum -a 256 -c aivault-*.sha256
```

macOS signature inspection:

```bash
codesign -dv --verbose=4 aivault
spctl --assess --verbose aivault
```

Linux cosign verification:

```bash
cosign verify-blob \
  --certificate aivault-*.cert \
  --signature aivault-*.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity 'https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/cli-vX.Y.Z' \
  aivault-*.tar.gz
```

## Verify installation

```bash
aivault status
aivaultd --version
aivault provider list -v
```

This auto-initializes the vault with safe defaults (macOS Keychain on macOS) if no vault exists yet.

To activate an optional provider:

```bash
aivault provider install postgres --enable
```

Next: [Getting started](/getting-started)
