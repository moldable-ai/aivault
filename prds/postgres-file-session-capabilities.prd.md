# Postgres File And Session Capabilities PRD

## Goal

Extend the Postgres provider beyond query/write/admin statements without weakening the aivault boundary. Bulk import, arbitrary file export, and multi-step transactions must be separate capabilities with explicit policies. They must never be smuggled through `postgres/query`, `postgres/execute`, or `postgres/admin`.

## Current Baseline

- `postgres/query` supports one bounded read-only statement.
- `postgres/export-query` returns bounded CSV or JSONL content to the caller.
- `postgres/export-file` writes bounded CSV or JSONL content to the aivault-controlled
  Postgres export root.
- `postgres/import-rows` imports bounded CSV or JSONL rows from the aivault-controlled
  Postgres import root.
- `postgres/execute` supports one guarded `INSERT`, `UPDATE`, or `DELETE`.
- `postgres/admin` supports one guarded schema, permission, or maintenance statement.
- Generic SQL paths reject `COPY`, file import/export, transaction/session commands, `CALL`, `DO`, prepared statements, and multi-statement payloads.

## Non-Goals

- No raw credential access for apps or agents.
- No caller-selected arbitrary output path without destination policy.
- No long-lived transaction emulation through independent stateless invocations.
- No direct `COPY ... TO/FROM '/path'` SQL passthrough.

## Capability Set

### `postgres/export-file` (Implemented)

Exports a bounded read-only query result to an aivault-controlled file destination.

Required request fields:

- `sql`: one `SELECT`, `WITH`, or `VALUES` statement.
- `format`: `csv` or `jsonl`.
- `destination`: logical destination id, not an arbitrary absolute path. The initial
  implementation supports `default`.

Optional request fields:

- `limit`, `offset`
- `timeoutMs`
- `maxExportBytes`
- `filename`

Policy requirements:

- Credential max policy mode: `read-only` or above.
- Destination allowlist resolves to `<vault>/postgres/exports` for the initial `default`
  destination.
- File name must be sanitized and extension must match `format`.
- Atomic write: create temp file in destination directory, fsync best-effort, then rename.
- Response returns path metadata only after successful write.

Audit fields:

- capability
- credential id
- workspace/group scope
- destination id
- final byte count
- row count
- query command type

### `postgres/import-rows` (Implemented)

Imports rows from an approved local file into a specific table using parameterized inserts or database-native copy only inside the provider.

Required request fields:

- `sourcePath`: relative path under `<vault>/postgres/imports` or an absolute path that
  canonicalizes under that same root.
- `schema`
- `table`
- `format`: `csv` or `jsonl`
- `columns`

Optional request fields:

- `maxRows`
- `maxImportBytes`
- `timeoutMs`
- `onConflict`: initially omitted; future explicit enum only.

Policy requirements:

- Credential max policy mode: `write` or `admin`.
- Source file must be under `<vault>/postgres/imports` in the initial implementation.
- Table target must be explicit; no target inferred from file names.
- Import runs in one transaction.
- Roll back if `maxRows` or `maxImportBytes` is exceeded.
- No triggers/constraints bypass unless a future admin-only capability explicitly supports it.

Audit fields:

- capability
- credential id
- workspace/group scope
- source id
- schema/table
- byte count
- inserted row count

### `postgres/transaction-session`

Supports an interactive transaction only after aivault has a safe session model.

Current blocker:

- The official provider plugin runtime is intentionally one-shot today:
  `src/provider_plugins.rs::invoke_provider` spawns the provider binary, writes one JSON request,
  waits for output, and exits.
- A SQL transaction is bound to one live database connection. It cannot be represented by
  separate one-shot provider invocations without either committing each statement independently or
  leaving an unowned backend connection behind.
- Therefore `postgres/transaction-session` must wait for a provider-session runtime, not another
  stateless capability branch in `providers/postgres/src/main.rs`.

Required design before implementation:

- Session ownership and TTL.
- Workspace/group binding for the full session lifetime.
- Credential binding immutable for the full session lifetime.
- Explicit begin/commit/rollback operations.
- Idle timeout and hard timeout.
- Audit event for begin, every statement, commit, rollback, timeout, and abort.
- Crash recovery behavior that guarantees rollback on daemon/provider failure.

Initial mode:

- `read-only` transaction sessions only.
- Write/admin transaction sessions require a second design review because they increase blast radius
  and must coordinate policy mode plus cumulative affected-row budgets.

## DB Browser Integration

- DB Browser exports currently use `postgres/export-query` and browser downloads, which keeps
  user-facing download paths app-side while aivault owns query execution and byte caps.
- File exports can use `postgres/export-file` for aivault-controlled destinations. User-selected
  arbitrary filesystem paths still require a destination policy or app-side download flow.
- DB Browser imports use a dedicated import dialog with file preview, column mapping, row caps,
  byte caps.
- Transaction sessions should not be surfaced until the generic aivault provider-session model
  exists. See `prds/provider-sessions.prd.md`.

## Transaction Session Acceptance Criteria

Do not mark `postgres/transaction-session` implemented until all of these are true:

- `postgres/transaction-session/begin` returns an opaque session id, not a backend PID or raw
  connection detail.
- Session ids are scoped to workspace, optional group, credential id, and local caller identity.
- `statement`, `commit`, and `rollback` reject calls when any scope or credential binding differs
  from the begin request.
- Every statement still uses the same SQL classifier as the stateless capabilities and is gated by
  the session policy mode.
- Idle timeout rolls back the transaction without requiring a client cleanup call.
- Daemon/provider crash or process exit rolls back the transaction.
- Audit records include begin, every statement, commit, rollback, timeout, and abort.
- DB Browser shows explicit in-session state and never runs normal editor shortcuts against an
  open transaction accidentally.

## Provider-Session Runtime Plan

This section is superseded by the generic provider-session design in
`prds/provider-sessions.prd.md`. The important invariant is that `aivaultd` owns generic session
lifecycle, scope binding, policy enforcement, timeout cleanup, and audit, while the Postgres
provider owns Postgres-specific transaction behavior.

Implement transaction sessions in this order:

1. Add a core provider session manager owned by `aivaultd`.
   - Session state must live in the daemon process, not the CLI process.
   - CLI invocations may proxy session operations to the daemon, but direct `AIVAULTD_DISABLE=1`
     invocations should reject transaction sessions with a clear error.
   - Session ids must be random opaque ids stored server-side with credential id, workspace id,
     group id, policy mode, provider id, creation time, idle deadline, and hard deadline.

2. Extend provider plugins with a long-lived protocol.
   - Keep the existing one-shot protocol for normal capabilities.
   - Add a session protocol where core starts a provider process and exchanges framed JSON
     messages over stdin/stdout until commit, rollback, timeout, or crash.
   - Core, not the app, owns the provider process handle.
   - Provider stdout must be framed so result JSON and logs cannot be confused.

3. Add Postgres session operations.
   - `postgres/transaction-session/begin`
   - `postgres/transaction-session/statement`
   - `postgres/transaction-session/commit`
   - `postgres/transaction-session/rollback`
   - Initial implementation should be read-only only.
   - Write/admin sessions require a second PRD update covering
     affected-row budgets across the full transaction.

4. Add daemon cleanup.
   - Periodic idle timeout sweep.
   - Hard timeout sweep.
   - Rollback on provider process exit.
   - Rollback all open sessions during daemon shutdown.

5. Add tests.
   - Unit tests for session scope binding and timeout bookkeeping.
   - Provider protocol tests for framed message parsing and crash handling.
   - Docker-backed Postgres e2e proving begin -> statement -> rollback leaves no committed state.
   - Docker-backed e2e proving scope/credential mismatch cannot use another session id.

6. Only then add DB Browser UI.
   - Explicit transaction state in the SQL workspace header.
   - Separate begin/commit/rollback controls.
   - Disable normal run-all shortcuts while a session is open unless the action targets the
     session intentionally.
   - Clear timeout/error messaging when a transaction expires.

## Open Questions

- Should file destinations be global aivault policy, workspace policy, or both?
- Should DB Browser own user-facing download paths while aivault owns only query execution?
- Should import support app-uploaded file handles in addition to files already present in the
  aivault import root?
- What is the right default export byte cap for local-only versus remote databases?
