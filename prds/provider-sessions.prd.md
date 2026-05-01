# Provider Sessions PRD

## Problem

Some providers need state that lives longer than one capability invocation. Postgres
transactions are the first concrete case: a transaction is tied to one live database
connection, so it cannot be represented by independent one-shot provider executions.

The current provider runtime is intentionally stateless:

1. aivault resolves credential, scope, host policy, request policy mode, and audit context.
2. aivault starts the provider binary.
3. aivault sends one JSON request over stdin.
4. aivault reads one JSON response from stdout.
5. the provider exits.

That model is correct for normal capabilities. It is not enough for transactions, cursors,
interactive shells, or any provider workflow that must keep server-side state between calls.

## Goals

- Add a generic provider-session runtime owned by `aivaultd`.
- Keep provider-specific behavior inside provider plugins, not aivault core.
- Preserve the zero-trust boundary: apps and agents never receive credentials, connection
  handles, backend PIDs, or provider process details.
- Support Postgres read-only transaction sessions as the first consumer.
- Keep existing one-shot provider invocation unchanged for normal capabilities.

## Non-Goals

- Do not hardcode Postgres transaction mechanics into `aivaultd`.
- Do not add Postgres client dependencies to the aivault core binary.
- Do not emulate transactions through separate stateless invocations.
- Do not persist live sessions across daemon restarts.
- Do not support write/admin transaction sessions in the first version.

## Core Model

`aivaultd` owns provider-session lifecycle. Providers own domain behavior.

Core knows:

- provider id
- installed provider manifest and digest/signature status
- credential id
- workspace id and optional group id
- requested policy mode
- local caller identity when available
- session creation time, idle deadline, and hard deadline
- provider process handle and framed transport
- audit metadata

Provider knows:

- how to open and close its upstream connection
- what a session operation means
- how to classify provider-specific statements
- how to format sanitized results
- how to rollback/cleanup when the session ends unexpectedly

## Public Capability Shape

Provider-owned capabilities remain namespaced:

```text
postgres/transaction-session/begin
postgres/transaction-session/statement
postgres/transaction-session/commit
postgres/transaction-session/rollback
```

Those capabilities use generic daemon machinery internally. `aivaultd` does not need to know
what `begin`, `statement`, `commit`, or `rollback` mean for Postgres.

Future providers can expose their own session capabilities, for example:

```text
ssh/session/open
ssh/session/write
ssh/session/close
```

## Provider Manifest Extension

Providers that support sessions declare that support in `provider.json`.

Example:

```json
{
  "id": "postgres",
  "version": "0.5.0",
  "sessionProtocol": {
    "version": 1,
    "capabilities": [
      "postgres/transaction-session/begin",
      "postgres/transaction-session/statement",
      "postgres/transaction-session/commit",
      "postgres/transaction-session/rollback"
    ],
    "maxSessions": 8,
    "defaultIdleTimeoutMs": 30000,
    "maxIdleTimeoutMs": 300000,
    "defaultHardTimeoutMs": 600000,
    "maxHardTimeoutMs": 3600000
  }
}
```

Core validates this metadata the same way it validates normal provider capabilities: official
provider metadata, installed manifest, binary digest/signature, and enabled status must match.

## Daemon API

The daemon receives normal capability envelopes, then routes session capabilities through a
generic session manager.

Initial internal operations:

- `ProviderSessionOpen`
- `ProviderSessionCall`
- `ProviderSessionClose`
- `ProviderSessionAbort`

These do not need to be exposed as user-facing capability ids. They are implementation
primitives behind provider-owned capability ids.

## Session State

Each session record stores:

- opaque random session id
- provider id
- credential id
- workspace id
- group id
- policy mode
- allowed capability ids for this session
- provider process child handle
- framed stdin/stdout transport
- created timestamp
- last-used timestamp
- idle deadline
- hard deadline
- terminal state: active, committed, rolled back, timed out, aborted, crashed

The session id must be high-entropy and opaque. It must not encode backend PIDs, database names,
hostnames, credential ids, or process ids.

## Scope And Policy Enforcement

Every session call after open must match the begin/open context:

- same provider id
- same credential id
- same workspace id
- same group id
- same policy mode or a stricter provider-declared mode
- same local caller identity when peer identity is available

If any binding differs, aivault rejects the call before forwarding anything to the provider.

`AIVAULTD_DISABLE=1` must reject provider-session capabilities with a clear error. Sessions are
daemon-owned; a one-shot CLI process is not an acceptable owner.

## Framed Provider Protocol

The existing one-shot provider protocol stays as-is.

Session providers use a separate framed protocol. Each frame is length-prefixed or newline-delimited
JSON with an explicit type. Provider logs must never share the result channel.

Example request frames:

```json
{"type":"session.open","requestId":"...","capability":"postgres/transaction-session/begin","secret":{...},"request":{...}}
{"type":"session.call","requestId":"...","sessionId":"...","capability":"postgres/transaction-session/statement","request":{...}}
{"type":"session.close","requestId":"...","sessionId":"...","capability":"postgres/transaction-session/commit","request":{...}}
{"type":"session.abort","requestId":"...","sessionId":"...","reason":"idle-timeout"}
```

Example response frames:

```json
{"type":"session.opened","requestId":"...","providerSessionId":"...","result":{...}}
{"type":"session.result","requestId":"...","result":{...}}
{"type":"session.closed","requestId":"...","result":{...}}
{"type":"session.error","requestId":"...","error":"...","details":{...}}
```

The provider may have its own provider-local session id, but aivault returns only the aivault
session id to callers.

## Timeout And Cleanup

`aivaultd` must clean up sessions without trusting clients to call rollback/close.

Required cleanup behavior:

- idle timeout sends `session.abort` and then kills the provider if it does not exit promptly
- hard timeout sends `session.abort` and then kills the provider if it does not exit promptly
- daemon shutdown aborts all active sessions
- provider process exit marks the session crashed/aborted
- broken transport marks the session crashed/aborted

Providers must ensure upstream state is safe on process exit. For Postgres, closing the connection
with an open transaction rolls back the transaction.

## Audit

Core writes audit records for:

- session open
- every session call
- session close
- explicit rollback/abort
- idle timeout
- hard timeout
- provider crash
- daemon shutdown abort

Audit records include:

- capability id
- provider id
- credential id
- workspace/group scope
- policy mode
- session id hash or short opaque reference
- timeout values
- row/byte/affected-row counts when provided by the provider

Audit must not include raw SQL secrets, database passwords, connection URLs, backend PIDs, or
raw result data.

## Postgres First Implementation

Initial Postgres session support is read-only only.

Provider behavior:

1. `begin` opens one Postgres connection and runs
   `BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ`.
2. `statement` accepts the same read-only statement set as `postgres/query`:
   `SELECT`, `WITH`, `VALUES`, `SHOW`, and non-`ANALYZE` `EXPLAIN`.
3. Results remain bounded by limit, offset, timeout, row caps, and byte caps.
4. `commit` commits and exits.
5. `rollback` rolls back and exits.
6. Provider crash or daemon abort closes the connection, causing database rollback.

Write/admin transaction sessions require a separate PRD update covering cumulative affected-row
budgets, escalation prompts, and UI state.

## Confirmation Semantics

Provider sessions do not use caller-supplied booleans such as `confirm: true` as security
boundaries.

Policy mode is the authorization boundary:

- credential `maxPolicyMode` defines the maximum allowed mode
- request `policyMode` selects the active mode for the invocation
- capability id defines the operation family
- aivault enforces all of those before provider invocation

Apps should not add an extra confirmation step by default when the active policy mode already
allows the operation. Policy mode is the trust decision. If a future workflow truly needs
cryptographic or daemon-mediated human consent, it should use a real consent token or interactive
operator approval flow, not a caller-provided boolean.

## Acceptance Criteria

- Normal one-shot providers continue to work unchanged.
- Session-capable providers declare session support in manifest metadata.
- `aivaultd` can open, call, close, timeout, and abort provider sessions without provider-specific
  code paths.
- Direct in-process invocation rejects session capabilities.
- Session ids are opaque and scoped server-side.
- Scope, credential, and policy mismatches are rejected before provider calls.
- Idle and hard timeouts clean up provider processes.
- Daemon shutdown aborts active sessions.
- Provider crash is reported and audited.
- Postgres read-only transaction sessions prove repeatable-read behavior against the local e2e
  fixture.
