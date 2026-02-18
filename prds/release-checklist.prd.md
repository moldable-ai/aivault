# Release Checklist (CLI)

This checklist is the operator runbook for releasing the `aivault` CLI via GitHub Actions.

## One-Time Setup

- [ ] Confirm GitHub Actions are enabled for the repo.
- [ ] In repo settings, ensure `GITHUB_TOKEN` has sufficient permissions to create releases and upload assets.
  - [ ] Settings: Actions -> General -> Workflow permissions -> `Read and write permissions`
- [ ] Add GitHub Actions secrets for macOS codesigning + notarization:
  - [ ] `APPLE_CERTIFICATE`: base64-encoded `.p12` (Developer ID Application cert + private key)
  - [ ] `APPLE_CERTIFICATE_PASSWORD`: password for the `.p12`
  - [ ] `APPLE_SIGNING_IDENTITY`: identity string used by `codesign` (must match the `.p12` contents)
  - [ ] `APPLE_ID`: Apple ID email for notarization
  - [ ] `APPLE_PASSWORD`: Apple app-specific password for notarization
  - [ ] `APPLE_TEAM_ID`: Apple Developer Team ID
- [ ] Add GitHub Actions secret for crates.io publishing:
  - [ ] `CARGO_REGISTRY_TOKEN`: crates.io API token with publish permissions
- [ ] Confirm Linux cosign keyless signing requirements:
  - [ ] GitHub Actions workflow has `permissions: id-token: write` (required for keyless signing via OIDC)
  - [ ] No additional secrets are required for Linux artifact signing (cosign keyless)
- [ ] Update verification docs for your repo identity:
  - [ ] Replace the placeholder `<owner>/<repo>` in `README.md` under “Release verification” with your real org/repo.

## Pre-Release (Each Time)

- [ ] Ensure `main` CI is green.
- [ ] Ensure your local checkout is clean:
  - [ ] `git status --porcelain` is empty
- [ ] Decide the release version bump:
  - [ ] `patch` (X.Y.(Z+1))
  - [ ] `minor` (X.(Y+1).0)
  - [ ] `major` ((X+1).0.0)
  - [ ] or an explicit `X.Y.Z`

## Release (Each Time)

- [ ] Run the release script (creates commit + tag and pushes):
  - [ ] `pnpm release:cli patch`
  - [ ] `pnpm release:cli minor`
  - [ ] `pnpm release:cli major`
  - [ ] `pnpm release:cli X.Y.Z`
- [ ] Confirm the tag exists in GitHub:
  - [ ] Tag format is `cli-vX.Y.Z`
- [ ] Confirm GitHub Actions “Release” workflow ran on the tag and completed successfully.

## Post-Release Verification (What To Check In The GitHub Release)

- [ ] macOS artifacts exist (both architectures):
  - [ ] `aivault-aarch64-apple-darwin.zip` + `.sha256`
  - [ ] `aivault-x86_64-apple-darwin.zip` + `.sha256`
- [ ] Linux artifacts exist:
  - [ ] `aivault-x86_64-unknown-linux-gnu.tar.gz` + `.sha256`
  - [ ] `aivault-x86_64-unknown-linux-gnu.tar.gz.sig`
  - [ ] `aivault-x86_64-unknown-linux-gnu.tar.gz.cert`
- [ ] macOS signing/notarization spot check (on a macOS machine):
  - [ ] `codesign -dv --verbose=4 aivault`
  - [ ] `spctl --assess --verbose aivault`
- [ ] Linux authenticity spot check (on a Linux machine with `cosign` installed):
  - [ ] Verify checksum: `sha256sum -c aivault-...tar.gz.sha256`
  - [ ] Verify signature (keyless):
    - [ ] `cosign verify-blob --certificate aivault-...tar.gz.cert --signature aivault-...tar.gz.sig --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity 'https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/cli-vX.Y.Z' aivault-...tar.gz`

## Gateway / Fly.io Notes

If a deployment image downloads `aivault` from GitHub Releases at build time:

- [ ] Download the tarball and its `.cert` + `.sig` next to it.
- [ ] Verify the tarball before extracting/installing:
  - [ ] `cosign verify-blob ... aivault-...tar.gz`
- [ ] Extract/install only after verification passes.

If a deployment image builds `aivault` from source instead of downloading a release artifact:

- [ ] Pin the git ref used for the build (tag or commit SHA).
- [ ] Treat the build pipeline + pinned source as the trust boundary (release artifact signing is not involved).
