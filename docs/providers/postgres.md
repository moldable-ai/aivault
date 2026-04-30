---
title: Postgres provider
description: Install, configure, and invoke read-only Postgres capabilities through aivault.
---

The Postgres provider lets agents inspect database metadata and run bounded read-only queries
without ever receiving Postgres credentials.

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
  --host db.example.com:5432
```

The `--host` value is a credential allowlist. It can be a hostname or `host:port`. Runtime
connection attempts fail closed if the secret points anywhere else.

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

## Limits and safety

- Query execution uses `BEGIN READ ONLY`.
- `postgres/query` accepts `SELECT`, `WITH`, and `VALUES` statements only.
- Mutation/admin statements such as `INSERT`, `UPDATE`, `DELETE`, `ALTER`, `DROP`, `COPY`,
  `VACUUM`, `CALL`, and `DO` are rejected before execution.
- Multiple statements are rejected.
- Default row limit is `100`; maximum is `1000`.
- `offset` defaults to `0` and can be used with `limit` for paging. There is no
  artificial maximum offset; large offsets are still constrained by the query timeout.
- Default timeout is `5000ms`; maximum is `30000ms`.
- Invocation is audited as `postgres.invoke`.
