---
title: Install
description: Install the aivault CLI on macOS or Linux.
---

## From source (Rust)

```bash
cargo install --path .
```

Or build without installing:

```bash
cargo build --release
# Binary at target/release/aivault
```

## From release artifacts

Download the latest release from the GitHub releases page. Artifacts are available for macOS (arm64, x86_64) and Linux (x86_64).

macOS releases are signed and notarized. Linux releases include cosign keyless signatures for CI-driven verification.

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
```

This auto-initializes the vault with safe defaults (macOS Keychain on macOS) if no vault exists yet.

Next: [Getting started](/getting-started)
