# Provider Plugins

## Problem

Some aivault capabilities need non-HTTP client libraries. Postgres is the first concrete case:
the broker must use database credentials, but agents must never receive those credentials.
Compiling every provider client into the core binary would make aivault heavier over time and
turn optional integrations into mandatory dependencies.

## Current Shape

Provider-specific implementations live in separate provider binaries. For Postgres,
`providers/postgres` owns the Rust `postgres` client dependency and the default aivault binary
does not compile or link it.

The core binary ships only provider metadata and the provider manager. The provider binary can
be bundled beside aivault by installers, then installed into `$AIVAULT_DIR/providers` and enabled
only when the operator needs those capabilities.

## Codex Plugin Patterns To Reuse

The Codex plugin implementation has several patterns that map well to aivault:

- Plugin IDs are stable namespaced IDs, not arbitrary paths.
- Plugins declare a manifest in a fixed metadata directory.
- Installation happens into a controlled root, not wherever the caller points.
- Git/local sources are staged first, validated, and then atomically activated.
- Git sources can be pinned by ref and resolved SHA.
- Sparse checkout keeps installs narrow when a repository contains many plugins.
- Marketplace metadata separates discovery from installation policy.

## aivault-Specific Constraints

Provider plugins run inside the trusted broker boundary. A plugin may receive decrypted
provider credentials from the vault, so it cannot be arbitrary agent-editable code.

Minimum rules:

- Core aivault owns vault decryption, workspace/group scoping, policy selection, and audit.
- Provider plugin code must be installed under an aivault-controlled provider root.
- The installed provider artifact must be pinned by version and content digest or signature.
- Agents may invoke provider capabilities, but may not install, update, or modify providers
  without operator authority.
- Capability policy remains data controlled by aivault, not caller-provided SQL or host data.

## Proposed Runtime

Install providers under:

```text
$AIVAULT_DIR/providers/
  postgres/
    provider.json
    bin/aivault-provider-postgres
```

`provider.json` should declare:

- provider ID, version, and entrypoint
- supported capability IDs
- secret schema accepted by the provider
- provider-specific policy schema
- expected artifact digest or signing identity

Core invocation flow:

1. Caller invokes `postgres/query`.
2. Core resolves the workspace/group-scoped credential and host allow-list.
3. Core resolves the secret from the vault.
4. Core validates the installed provider artifact before launch/reuse.
5. Core sends a minimal JSON request to the provider over stdio or a local Unix socket.
6. Provider returns sanitized JSON rows/metadata.
7. Core writes the normal aivault audit event and response envelope.

## Install UX

```bash
aivault provider list
aivault provider install postgres
aivault provider enable postgres
aivault provider disable postgres
aivault provider remove postgres
```

Auto-install can be layered on later, but should require an operator-controlled policy such as
`providerInstall = on-demand` and should never be triggered by an untrusted proxy token alone.

## Postgres Contract

The Postgres provider keeps this public capability contract:

- `postgres/test-connection`
- `postgres/list-schemas`
- `postgres/list-tables`
- `postgres/describe-table`
- `postgres/preview-table`
- `postgres/query`
