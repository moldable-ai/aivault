---
title: Postgres provider
description: Install, configure, and invoke Postgres capabilities through aivault.
---

The Postgres provider lets agents inspect database metadata, run bounded read-only queries,
export bounded result sets, and, when explicitly enabled, run guarded writes, admin statements,
and controlled row imports without ever receiving Postgres credentials.

The provider is an optional binary. The main `aivault` binary does not link the Rust Postgres
client dependency.

## Install and enable

If you installed aivault from the official release installer, the Postgres provider binary is
bundled beside the CLI. Install and enable it:

```bash
aivault provider list -v
aivault provider install postgres --enable
```

If you built from source, build the provider first:

```bash
pnpm provider:build:postgres
aivault provider install postgres --enable
```

Verify:

```bash
aivault provider list -v
aivault capability describe postgres/query
```

## Store credentials

Store the Postgres connection details as a JSON secret. Use a workspace scope when the database
belongs to a specific Moldable workspace or project.

```bash
aivault secrets create \
  --name POSTGRES_URL \
  --value '{"url":"postgresql://user:pass@db.example.com:5432/app?sslmode=require"}' \
  --scope workspace \
  --workspace-id my-workspace
```

Then bind a Postgres credential to that secret and lock it to the allowed database host:

```bash
aivault credential create app-db \
  --provider postgres \
  --secret-ref vault:secret:<secret-id> \
  --workspace-id my-workspace \
  --host db.example.com:5432 \
  --max-policy-mode read-only
```

The `--host` value is a credential allowlist. It can be a hostname or `host:port`. Runtime
connection attempts fail closed if the secret points anywhere else.

`--max-policy-mode` is a per-credential ceiling. It accepts `read-only`, `write`, or `admin`.
Omitting it defaults to `read-only`. A request cannot raise itself above this credential ceiling.

## Secret JSON formats

Connection URL:

```json
{
  "url": "postgresql://user:pass@db.example.com:5432/app?sslmode=require"
}
```

Discrete fields:

```json
{
  "host": "db.example.com",
  "port": 5432,
  "database": "app",
  "user": "app_user",
  "password": "secret",
  "sslMode": "require"
}
```

Supported SSL modes:

- `disable`
- `prefer`
- `require`
- `verify-ca`
- `verify-full`

## Capabilities

| Capability | Purpose |
|------------|---------|
| `postgres/test-connection` | Verify connectivity and return database/user/version metadata |
| `postgres/list-schemas` | List non-system schemas |
| `postgres/list-tables` | List tables, optionally within one schema |
| `postgres/describe-table` | Return columns, nullability, defaults, and primary key flags |
| `postgres/preview-table` | Return bounded rows from a specific table |
| `postgres/query` | Run a bounded read-only SQL query |
| `postgres/export-query` | Return bounded CSV or JSONL for a read-only query |
| `postgres/export-file` | Write a bounded read-only export to an aivault-controlled export root |
| `postgres/import-rows` | Import bounded CSV or JSONL rows from an aivault-controlled import root |
| `postgres/execute` | Run one guarded common write statement |
| `postgres/admin` | Run one guarded admin statement |

## Examples

Test the connection:

```bash
aivault json postgres/test-connection \
  --credential app-db \
  --workspace-id my-workspace
```

List tables:

```bash
aivault json postgres/list-tables \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"schema":"public"}'
```

Describe a table:

```bash
aivault json postgres/describe-table \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"schema":"public","table":"users"}'
```

Preview rows:

```bash
aivault json postgres/preview-table \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"schema":"public","table":"users","limit":20,"offset":0}'
```

Run a read-only query:

```bash
aivault json postgres/query \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"sql":"select id, email from public.users order by id","limit":20,"offset":0}'
```

Export a bounded read-only query result:

```bash
aivault json postgres/export-query \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"sql":"select id, email from public.users order by id","format":"csv","limit":1000,"maxExportBytes":1048576}'
```

Export a bounded read-only query result to the default aivault export root:

```bash
aivault json postgres/export-file \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"sql":"select id, email from public.users order by id","format":"jsonl","limit":1000,"filename":"users-export"}'
```

Import rows from the default aivault import root:

```bash
aivault json postgres/import-rows \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"policyMode":"write","schema":"public","table":"users","columns":["id","email"],"format":"csv","sourcePath":"users.csv","maxRows":1000,"maxImportBytes":1048576}'
```

Run a guarded write:

```bash
aivault json postgres/execute \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"policyMode":"write","sql":"update public.users set archived = true where id = 42","maxAffectedRows":1}'
```

Run a guarded admin statement:

```bash
aivault json postgres/admin \
  --credential app-db \
  --workspace-id my-workspace \
  --body '{"policyMode":"admin","sql":"refresh materialized view public.daily_rollup"}'
```

## Limits and safety

- Query execution uses `BEGIN READ ONLY`.
- `postgres/query` accepts `SELECT`, `WITH`, `VALUES`, `SHOW`, and non-`ANALYZE`
  `EXPLAIN` statements only.
- Postgres credentials may additionally set `maxPolicyMode`; requests above the credential
  ceiling are rejected before provider execution. Missing credential ceilings default to
  `read-only`.
- `postgres/export-query` accepts `SELECT`, `WITH`, and `VALUES` only and returns content in
  `jsonl` or `csv` format. The default `maxExportBytes` is `1048576`; maximum is `10485760`.
- `postgres/export-file` uses the same read-only query/export limits, writes only under the
  aivault-controlled Postgres export root (`<vault>/postgres/exports`), and currently supports
  destination `default`.
- `postgres/import-rows` requires explicit `policyMode` of `write` or `admin`,
  an explicit schema/table/column list, and a UTF-8 `csv` or `jsonl` source file under the
  aivault-controlled Postgres import root (`<vault>/postgres/imports`). The default
  `maxImportBytes` is `1048576`; maximum is `10485760`. The default `maxRows` is `1000`;
  maximum is `10000`.
- Imports run inside a single transaction and use provider-internal `COPY FROM STDIN`; callers
  cannot pass raw `COPY` SQL or arbitrary source paths.
- `postgres/execute` requires explicit `policyMode` of `write` or `admin`, and the credential
  `maxPolicyMode` must allow that mode.
- `postgres/execute` currently allows one `INSERT`, `UPDATE`, or `DELETE` statement only.
  `UPDATE` and `DELETE` must include a `WHERE` clause.
- `postgres/execute` rejects `RETURNING` and rolls back when the affected row count exceeds
  `maxAffectedRows`. The default `maxAffectedRows` is `100`; maximum is `1000`.
- `postgres/admin` requires explicit `policyMode: "admin"`.
- `postgres/admin` allows one guarded schema, permission, or maintenance statement. It rejects
  instance-level targets such as databases, roles/users, tablespaces, servers, subscriptions,
  and publications.
- Mutation/admin statements such as `INSERT`, `UPDATE`, `DELETE`, `ALTER`, `DROP`, `COPY`,
  `VACUUM`, `CALL`, and `DO` are rejected before execution by `postgres/query`.
- Raw `COPY`, arbitrary source/destination paths, and long-lived transaction/session workflows
  are not exposed through generic SQL capabilities. File import/export must use the dedicated
  aivault-controlled roots above. Transaction sessions still need a dedicated session model.
- `EXPLAIN ANALYZE` is rejected because it executes the underlying statement.
- Multiple statements are rejected.
- Default row limit is `100`; maximum is `1000`.
- `offset` defaults to `0` and can be used with `limit` for paging. There is no
  artificial maximum offset; large offsets are still constrained by the query timeout.
- Default timeout is `5000ms`; maximum is `30000ms`.
- Read-only invocation and file export are audited as `postgres.invoke`; `postgres/import-rows`,
  `postgres/execute`, and `postgres/admin` are audited as `postgres.write`.

Future transaction-session work is tracked in `prds/postgres-file-session-capabilities.prd.md`.
That workflow requires dedicated session policy before it should be exposed.
