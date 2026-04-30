---
title: Provider plugins
description: Official optional provider binaries for non-HTTP capabilities.
---

Provider plugins are official optional binaries for capabilities that need a client library or
protocol implementation outside normal HTTP proxying.

They solve two constraints at once:

- The main `aivault` binary stays small and does not link every provider client library.
- Credentials still stay inside the aivault trust boundary; agents invoke capabilities and never
  receive provider secrets.

## Install and activation model

Release artifacts can include bundled provider binaries under `providers/<id>/`. The install script
copies those bundled providers beside `aivault`, but they are not activated automatically.

Operators activate a provider explicitly:

```bash
aivault provider list -v
aivault provider install postgres --enable
```

After that, provider capabilities are invoked like any other aivault capability.

## Security model

- Provider install/enable/disable/remove commands are operator operations.
- Proxy tokens and untrusted callers can invoke enabled capabilities, but cannot install or enable
  provider binaries.
- aivault copies the provider binary into the vault provider directory and stores a manifest with a
  content digest.
- Runtime verifies the installed binary digest before invoking the provider.
- Core aivault still owns secret resolution, workspace/group scoping, host allowlists, limits, and
  audit logging.

## Providers

- [Postgres](/providers/postgres) — read-only database metadata and query capabilities.

