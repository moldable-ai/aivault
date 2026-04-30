---
title: Provider plugins CLI
description: Install and manage optional official provider plugin binaries.
---

Provider plugins are optional official binaries for capabilities that need a client library or
protocol implementation outside normal HTTP proxying.

## List providers

```bash
aivault provider list
aivault provider list -v
```

Verbose output includes install status, bundled binary path, installed executable path, and
declared capabilities.

## Install

Install an official provider from the bundled release artifact:

```bash
aivault provider install postgres
```

Install and enable in one step:

```bash
aivault provider install postgres --enable
```

Install from an explicit binary path, useful for source builds or local testing:

```bash
aivault provider install postgres \
  --from ./providers/postgres/target/debug/aivault-provider-postgres \
  --enable
```

## Enable or disable

```bash
aivault provider enable postgres
aivault provider disable postgres
```

Disabling a provider keeps the installed binary and manifest, but capability invocation fails until
it is enabled again.

## Remove

```bash
aivault provider remove postgres
```

Removal deletes the installed provider directory from the vault provider root.

## Provider-specific setup

- [Postgres provider](/providers/postgres)

