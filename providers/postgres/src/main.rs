use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use native_tls::TlsConnector;
use percent_encoding::percent_decode_str;
use postgres::types::Type;
use postgres::{Client as PgClient, Config as PgConfig, Error as PgError, NoTls, Row};
use postgres_native_tls::MakeTlsConnector;
use serde::Deserialize;
use serde_json::{Map, Value};
use sqlparser::ast::{ObjectType, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderInvokeRequest {
    protocol_version: u32,
    capability: String,
    secret: PostgresSecret,
    request: PostgresRequest,
    limit: u32,
    #[serde(default)]
    offset: u64,
    timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PostgresSecret {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    database: Option<String>,
    #[serde(default, alias = "username")]
    user: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    ssl: Option<bool>,
    #[serde(default, alias = "sslmode", alias = "ssl_mode")]
    ssl_mode: Option<String>,
}

#[derive(Debug)]
struct PostgresConnection {
    host: String,
    port: u16,
    database: String,
    user: String,
    password: Option<String>,
    ssl_mode: SslMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PostgresRequest {
    #[serde(default)]
    schema: Option<String>,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    sql: Option<String>,
    #[serde(default)]
    max_affected_rows: Option<u64>,
    #[serde(default)]
    max_export_bytes: Option<usize>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    source_content: Option<String>,
    #[serde(default)]
    columns: Option<Vec<String>>,
    #[serde(default)]
    max_rows: Option<u64>,
    #[serde(default)]
    header: Option<bool>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut input = Vec::new();
    io::stdin()
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())?;
    let request: ProviderInvokeRequest =
        serde_json::from_slice(&input).map_err(|e| format!("invalid provider request: {}", e))?;
    if request.protocol_version != 1 {
        return Err(format!(
            "unsupported provider protocol version {}",
            request.protocol_version
        ));
    }

    let connection = PostgresConnection::from_secret(request.secret)?;
    let mut client = connect(&connection, request.timeout_ms)?;
    let result = match request.capability.as_str() {
        "postgres/test-connection" => run_read_only(&mut client, request.timeout_ms, |client| {
            let row = client
                .query_one(
                    "SELECT current_database() AS database, current_user AS user, version() AS version",
                    &[],
                )
                .map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "database": row.get::<_, String>("database"),
                "user": row.get::<_, String>("user"),
                "version": row.get::<_, String>("version"),
            }))
        })?,
        "postgres/list-schemas" => run_read_only(&mut client, request.timeout_ms, |client| {
            let rows = client
                .query(
                    "
                    SELECT schema_name
                    FROM information_schema.schemata
                    WHERE schema_name <> 'information_schema'
                      AND schema_name NOT LIKE 'pg_%'
                    ORDER BY schema_name
                    ",
                    &[],
                )
                .map_err(|e| e.to_string())?;
            Ok(serde_json::json!({
                "schemas": rows
                    .into_iter()
                    .map(|row| row.get::<_, String>("schema_name"))
                    .collect::<Vec<_>>()
            }))
        })?,
        "postgres/list-tables" => {
            run_list_tables(&mut client, &request.request, request.timeout_ms)?
        }
        "postgres/describe-table" => {
            run_describe_table(&mut client, &request.request, request.timeout_ms)?
        }
        "postgres/preview-table" => run_preview_table(
            &mut client,
            &request.request,
            request.timeout_ms,
            request.limit,
            request.offset,
        )?,
        "postgres/query" => run_query(
            &mut client,
            &request.request,
            request.timeout_ms,
            request.limit,
            request.offset,
        )?,
        "postgres/export-query" => run_export_query(
            &mut client,
            &request.request,
            request.timeout_ms,
            request.limit,
            request.offset,
        )?,
        "postgres/import-rows" => {
            run_import_rows(&mut client, &request.request, request.timeout_ms)?
        }
        "postgres/execute" => run_execute(&mut client, &request.request, request.timeout_ms)?,
        "postgres/admin" => run_admin(&mut client, &request.request, request.timeout_ms)?,
        _ => {
            return Err(format!(
                "unknown postgres capability '{}'",
                request.capability
            ))
        }
    };

    println!(
        "{}",
        serde_json::to_string(&result).map_err(|e| e.to_string())?
    );
    Ok(())
}

impl PostgresConnection {
    fn from_secret(secret: PostgresSecret) -> Result<Self, String> {
        if let Some(url) = secret
            .url
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            let parsed =
                url::Url::parse(url).map_err(|e| format!("invalid postgres url: {}", e))?;
            if parsed.scheme() != "postgresql" && parsed.scheme() != "postgres" {
                return Err("postgres url must use postgres:// or postgresql://".to_string());
            }
            let database = percent_decode(parsed.path().trim_start_matches('/'))?;
            if database.is_empty() {
                return Err("postgres url database is required".to_string());
            }
            let host = parsed
                .host_str()
                .ok_or_else(|| "postgres url host is required".to_string())?
                .to_string();
            let query_ssl_mode = parsed
                .query_pairs()
                .find(|(key, _)| key.eq_ignore_ascii_case("sslmode"))
                .map(|(_, value)| value.to_string());
            return Ok(Self {
                host,
                port: parsed.port().unwrap_or(5432),
                database,
                user: percent_decode(parsed.username())?,
                password: parsed.password().map(percent_decode).transpose()?,
                ssl_mode: SslMode::from_parts(secret.ssl, secret.ssl_mode.or(query_ssl_mode))?,
            });
        }

        let host = required(secret.host, "host")?;
        let database = required(secret.database, "database")?;
        let user = required(secret.user, "user")?;
        Ok(Self {
            host,
            port: secret.port.unwrap_or(5432),
            database,
            user,
            password: secret.password,
            ssl_mode: SslMode::from_parts(secret.ssl, secret.ssl_mode)?,
        })
    }
}

impl SslMode {
    fn from_parts(ssl: Option<bool>, ssl_mode: Option<String>) -> Result<Self, String> {
        if let Some(value) = ssl_mode
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Self::parse(value);
        }
        Ok(if ssl.unwrap_or(false) {
            Self::Require
        } else {
            Self::Prefer
        })
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "disable" | "disabled" | "false" | "0" => Ok(Self::Disable),
            "prefer" | "preferred" => Ok(Self::Prefer),
            "require" | "required" | "true" | "1" => Ok(Self::Require),
            "verify-ca" | "verify_ca" => Ok(Self::VerifyCa),
            "verify-full" | "verify_full" => Ok(Self::VerifyFull),
            other => Err(format!("unsupported postgres sslmode '{}'", other)),
        }
    }
}

fn required(value: Option<String>, label: &str) -> Result<String, String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("postgres secret {} is required", label))
}

fn percent_decode(value: &str) -> Result<String, String> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.to_string())
        .map_err(|e| format!("invalid percent encoding: {}", e))
}

fn connect(connection: &PostgresConnection, timeout_ms: u64) -> Result<PgClient, String> {
    let mut config = PgConfig::new();
    config
        .host(&connection.host)
        .port(connection.port)
        .dbname(&connection.database)
        .user(&connection.user)
        .connect_timeout(Duration::from_millis(timeout_ms.max(1)))
        .application_name("aivault postgres provider");
    if let Some(password) = connection.password.as_deref() {
        config.password(password);
    }
    match connection.ssl_mode {
        SslMode::Disable => config.connect(NoTls).map_err(|e| e.to_string()),
        SslMode::Prefer => connect_tls(&config, true, true)
            .or_else(|_| config.connect(NoTls).map_err(|e| e.to_string())),
        SslMode::Require => connect_tls(&config, true, true),
        SslMode::VerifyCa => connect_tls(&config, false, true),
        SslMode::VerifyFull => connect_tls(&config, false, false),
    }
}

fn connect_tls(
    config: &PgConfig,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
) -> Result<PgClient, String> {
    let mut builder = TlsConnector::builder();
    builder.danger_accept_invalid_certs(accept_invalid_certs);
    builder.danger_accept_invalid_hostnames(accept_invalid_hostnames);
    let connector = builder.build().map_err(|e| e.to_string())?;
    config
        .connect(MakeTlsConnector::new(connector))
        .map_err(|e| e.to_string())
}

fn run_read_only<T, F>(client: &mut PgClient, timeout_ms: u64, f: F) -> Result<T, String>
where
    F: FnOnce(&mut PgClient) -> Result<T, String>,
{
    client
        .batch_execute(&format!(
            "BEGIN READ ONLY; SET LOCAL statement_timeout = {}; SET LOCAL idle_in_transaction_session_timeout = {};",
            timeout_ms, timeout_ms.saturating_add(1_000)
        ))
        .map_err(|e| e.to_string())?;
    let result = f(client);
    match result {
        Ok(value) => {
            client.batch_execute("COMMIT").map_err(|e| e.to_string())?;
            Ok(value)
        }
        Err(err) => {
            let _ = client.batch_execute("ROLLBACK");
            Err(err)
        }
    }
}

fn run_write<T, F>(client: &mut PgClient, timeout_ms: u64, f: F) -> Result<T, String>
where
    F: FnOnce(&mut PgClient) -> Result<T, String>,
{
    client
        .batch_execute(&format!(
            "BEGIN; SET LOCAL statement_timeout = {}; SET LOCAL idle_in_transaction_session_timeout = {};",
            timeout_ms,
            timeout_ms.saturating_add(1_000)
        ))
        .map_err(|e| e.to_string())?;
    let result = f(client);
    match result {
        Ok(value) => {
            client.batch_execute("COMMIT").map_err(|e| e.to_string())?;
            Ok(value)
        }
        Err(err) => {
            let _ = client.batch_execute("ROLLBACK");
            Err(err)
        }
    }
}

fn run_list_tables(
    client: &mut PgClient,
    request: &PostgresRequest,
    timeout_ms: u64,
) -> Result<Value, String> {
    let schema = request
        .schema
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    run_read_only(client, timeout_ms, |client| {
        let rows = if let Some(schema) = schema {
            client.query(
                "
                SELECT table_schema, table_name, table_type
                FROM information_schema.tables
                WHERE table_schema = $1
                ORDER BY table_schema, table_name
                ",
                &[&schema],
            )
        } else {
            client.query(
                "
                SELECT table_schema, table_name, table_type
                FROM information_schema.tables
                WHERE table_schema <> 'information_schema'
                  AND table_schema NOT LIKE 'pg_%'
                ORDER BY table_schema, table_name
                ",
                &[],
            )
        }
        .map_err(|e| e.to_string())?;

        Ok(serde_json::json!({
            "tables": rows.into_iter().map(|row| serde_json::json!({
                "schema": row.get::<_, String>("table_schema"),
                "name": row.get::<_, String>("table_name"),
                "type": row.get::<_, String>("table_type"),
            })).collect::<Vec<_>>()
        }))
    })
}

fn run_describe_table(
    client: &mut PgClient,
    request: &PostgresRequest,
    timeout_ms: u64,
) -> Result<Value, String> {
    let schema = required_body_field(request.schema.as_deref(), "schema")?;
    let table = required_body_field(request.table.as_deref(), "table")?;

    run_read_only(client, timeout_ms, |client| {
        let columns = client
            .query(
                "
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = $1 AND table_name = $2
                ORDER BY ordinal_position
                ",
                &[&schema, &table],
            )
            .map_err(|e| e.to_string())?;
        if columns.is_empty() {
            return Err("table not found".to_string());
        }

        let primary_keys = client
            .query(
                "
                SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY'
                  AND tc.table_schema = $1
                  AND tc.table_name = $2
                ORDER BY kcu.ordinal_position
                ",
                &[&schema, &table],
            )
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|row| row.get::<_, String>("column_name"))
            .collect::<HashSet<_>>();

        Ok(serde_json::json!({
            "schema": schema,
            "table": table,
            "columns": columns.into_iter().map(|row| {
                let name = row.get::<_, String>("column_name");
                serde_json::json!({
                    "name": name,
                    "dataType": row.get::<_, String>("data_type"),
                    "nullable": row.get::<_, String>("is_nullable") == "YES",
                    "default": row.get::<_, Option<String>>("column_default"),
                    "primaryKey": primary_keys.contains(&name),
                })
            }).collect::<Vec<_>>()
        }))
    })
}

fn run_preview_table(
    client: &mut PgClient,
    request: &PostgresRequest,
    timeout_ms: u64,
    limit: u32,
    offset: u64,
) -> Result<Value, String> {
    let schema = required_body_field(request.schema.as_deref(), "schema")?;
    let table = required_body_field(request.table.as_deref(), "table")?;
    let sql = format!(
        "SELECT * FROM {}.{}",
        quote_identifier(&schema),
        quote_identifier(&table)
    );
    run_select_json(client, timeout_ms, &sql, limit, offset, "SELECT").map(|mut value| {
        if let Some(obj) = value.as_object_mut() {
            obj.insert("schema".to_string(), Value::String(schema));
            obj.insert("table".to_string(), Value::String(table));
        }
        value
    })
}

fn run_query(
    client: &mut PgClient,
    request: &PostgresRequest,
    timeout_ms: u64,
    limit: u32,
    offset: u64,
) -> Result<Value, String> {
    let sql = request
        .sql
        .as_deref()
        .map(normalize_read_only_sql)
        .transpose()?
        .ok_or_else(|| "sql is required".to_string())?;
    match sql.kind {
        ReadOnlyStatementKind::SelectLike => {
            run_select_json(client, timeout_ms, &sql.sql, limit, offset, "SELECT")
        }
        ReadOnlyStatementKind::Show => {
            run_direct_text_json(client, timeout_ms, &sql.sql, limit, "SHOW")
        }
        ReadOnlyStatementKind::Explain => {
            run_direct_text_json(client, timeout_ms, &sql.sql, limit, "EXPLAIN")
        }
    }
}

fn run_export_query(
    client: &mut PgClient,
    request: &PostgresRequest,
    timeout_ms: u64,
    limit: u32,
    offset: u64,
) -> Result<Value, String> {
    let sql = request
        .sql
        .as_deref()
        .map(normalize_read_only_sql)
        .transpose()?
        .ok_or_else(|| "sql is required".to_string())?;
    if sql.kind != ReadOnlyStatementKind::SelectLike {
        return Err("export mode only allows SELECT, WITH, and VALUES statements".to_string());
    }

    let format = ExportFormat::parse(request.format.as_deref())?;
    let max_bytes = request.max_export_bytes.unwrap_or(1_048_576).max(1);
    let result = run_select_json(client, timeout_ms, &sql.sql, limit, offset, "SELECT")?;
    let columns = result
        .get("columns")
        .and_then(Value::as_array)
        .ok_or_else(|| "export query result missing columns".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "export query result column must be a string".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let rows = result
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| "export query result missing rows".to_string())?;
    let content = serialize_export_rows(format, &columns, rows, max_bytes)?;
    let byte_count = content.len();

    Ok(serde_json::json!({
        "columns": columns,
        "rowCount": rows.len(),
        "limit": limit,
        "offset": offset,
        "format": format.as_str(),
        "content": content,
        "bytes": byte_count,
        "maxBytes": max_bytes,
        "executionMs": result.get("executionMs").cloned().unwrap_or(Value::Null),
        "command": "EXPORT",
        "readOnly": true
    }))
}

fn run_execute(
    client: &mut PgClient,
    request: &PostgresRequest,
    timeout_ms: u64,
) -> Result<Value, String> {
    let sql = request
        .sql
        .as_deref()
        .map(normalize_write_sql)
        .transpose()?
        .ok_or_else(|| "sql is required".to_string())?;
    let max_affected_rows = request.max_affected_rows.unwrap_or(100).max(1);

    run_write(client, timeout_ms, |client| {
        let started = Instant::now();
        if sql.returns_rows {
            let prepared = client
                .prepare(&sql.sql)
                .map_err(|e| format!("write planning failed: {}", format_pg_error(&e)))?;
            let columns = prepared
                .columns()
                .iter()
                .map(|column| column.name().to_string())
                .collect::<Vec<_>>();
            let rows = client
                .query(&prepared, &[])
                .map_err(|e| format!("write failed: {}", format_pg_error(&e)))?
                .into_iter()
                .map(|row| postgres_row_to_json(&row))
                .collect::<Result<Vec<_>, _>>()?;
            if rows.len() as u64 > max_affected_rows {
                return Err(format!(
                    "write returned more than maxAffectedRows {}",
                    max_affected_rows
                ));
            }

            return Ok(serde_json::json!({
                "columns": columns,
                "rows": rows,
                "rowCount": rows.len(),
                "affectedRows": rows.len(),
                "maxAffectedRows": max_affected_rows,
                "executionMs": started.elapsed().as_millis(),
                "command": sql.kind.as_str(),
                "readOnly": false
            }));
        }

        let affected_rows = client
            .execute(&sql.sql, &[])
            .map_err(|e| format!("write failed: {}", format_pg_error(&e)))?;
        if affected_rows > max_affected_rows {
            return Err(format!(
                "write affected {} rows, exceeding maxAffectedRows {}",
                affected_rows, max_affected_rows
            ));
        }

        Ok(serde_json::json!({
            "affectedRows": affected_rows,
            "maxAffectedRows": max_affected_rows,
            "executionMs": started.elapsed().as_millis(),
            "command": sql.kind.as_str(),
            "readOnly": false
        }))
    })
}

fn run_import_rows(
    client: &mut PgClient,
    request: &PostgresRequest,
    timeout_ms: u64,
) -> Result<Value, String> {
    let schema = required_body_field(request.schema.as_deref(), "schema")?;
    let table = required_body_field(request.table.as_deref(), "table")?;
    let columns = normalize_columns(request.columns.as_deref())?;
    let format = ExportFormat::parse(request.format.as_deref())?;
    let max_rows = request.max_rows.unwrap_or(1_000).max(1);
    let source = request
        .source_content
        .as_deref()
        .ok_or_else(|| "sourceContent is required".to_string())?;
    let source_bytes = source.len();
    let prepared = prepare_import_csv(
        format,
        source,
        &columns,
        request.header.unwrap_or(true),
        max_rows,
    )?;

    run_write(client, timeout_ms, |client| {
        let copy_sql = format!(
            "COPY {}.{} ({}) FROM STDIN WITH (FORMAT csv, HEADER true)",
            quote_identifier(&schema),
            quote_identifier(&table),
            columns
                .iter()
                .map(|column| quote_identifier(column))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let started = Instant::now();
        let mut writer = client
            .copy_in(&copy_sql)
            .map_err(|e| format!("import failed: {}", format_pg_error(&e)))?;
        writer
            .write_all(prepared.csv.as_bytes())
            .map_err(|e| format!("import failed: {}", e))?;
        let affected_rows = writer
            .finish()
            .map_err(|e| format!("import failed: {}", format_pg_error(&e)))?;

        Ok(serde_json::json!({
            "affectedRows": affected_rows,
            "rowCount": prepared.row_count,
            "sourceBytes": source_bytes,
            "executionMs": started.elapsed().as_millis(),
            "command": "IMPORT",
            "readOnly": false
        }))
    })
}

fn run_admin(
    client: &mut PgClient,
    request: &PostgresRequest,
    timeout_ms: u64,
) -> Result<Value, String> {
    let sql = request
        .sql
        .as_deref()
        .map(normalize_admin_sql)
        .transpose()?
        .ok_or_else(|| "sql is required".to_string())?;

    client
        .batch_execute(&format!("SET statement_timeout = {};", timeout_ms))
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    let affected_rows = client
        .execute(&sql.sql, &[])
        .map_err(|e| format!("admin command failed: {}", format_pg_error(&e)))?;

    Ok(serde_json::json!({
        "affectedRows": affected_rows,
        "executionMs": started.elapsed().as_millis(),
        "command": sql.kind.as_str(),
        "readOnly": false,
        "admin": true
    }))
}

fn run_select_json(
    client: &mut PgClient,
    timeout_ms: u64,
    sql: &str,
    limit: u32,
    offset: u64,
    command: &str,
) -> Result<Value, String> {
    run_read_only(client, timeout_ms, |client| {
        let columns = client
            .prepare(sql)
            .map_err(|e| format!("query planning failed: {}", format_pg_error(&e)))?
            .columns()
            .iter()
            .map(|column| column.name().to_string())
            .collect::<Vec<_>>();

        let rows_sql = format!(
            "SELECT row_to_json(aivault_query)::text AS row_json FROM ({}) AS aivault_query LIMIT {} OFFSET {}",
            sql, limit, offset
        );
        let started = Instant::now();
        let rows = client
            .query(&rows_sql, &[])
            .map_err(|e| format!("query failed: {}", format_pg_error(&e)))?
            .into_iter()
            .map(|row| {
                let raw = row.get::<_, String>("row_json");
                serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(serde_json::json!({
            "columns": columns,
            "rows": rows,
            "rowCount": rows.len(),
            "limit": limit,
            "offset": offset,
            "executionMs": started.elapsed().as_millis(),
            "command": command,
            "readOnly": true
        }))
    })
}

fn run_direct_text_json(
    client: &mut PgClient,
    timeout_ms: u64,
    sql: &str,
    limit: u32,
    command: &str,
) -> Result<Value, String> {
    run_read_only(client, timeout_ms, |client| {
        let prepared = client
            .prepare(sql)
            .map_err(|e| format!("query planning failed: {}", format_pg_error(&e)))?;
        let columns = prepared
            .columns()
            .iter()
            .map(|column| column.name().to_string())
            .collect::<Vec<_>>();
        let started = Instant::now();
        let rows = client
            .query(&prepared, &[])
            .map_err(|e| format!("query failed: {}", format_pg_error(&e)))?
            .into_iter()
            .take(limit as usize)
            .map(|row| {
                let mut object = Map::new();
                for (idx, column) in columns.iter().enumerate() {
                    let value = row
                        .try_get::<_, Option<String>>(idx)
                        .map_err(|e| e.to_string())?
                        .map(Value::String)
                        .unwrap_or(Value::Null);
                    object.insert(column.clone(), value);
                }
                Ok(Value::Object(object))
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(serde_json::json!({
            "columns": columns,
            "rows": rows,
            "rowCount": rows.len(),
            "limit": limit,
            "offset": 0,
            "executionMs": started.elapsed().as_millis(),
            "command": command,
            "readOnly": true
        }))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    Jsonl,
    Csv,
}

impl ExportFormat {
    fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("jsonl")
            .to_ascii_lowercase()
            .as_str()
        {
            "jsonl" | "ndjson" => Ok(Self::Jsonl),
            "csv" => Ok(Self::Csv),
            other => Err(format!("unsupported export format '{}'", other)),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
        }
    }
}

fn serialize_export_rows(
    format: ExportFormat,
    columns: &[String],
    rows: &[Value],
    max_bytes: usize,
) -> Result<String, String> {
    let content = match format {
        ExportFormat::Jsonl => serialize_jsonl_rows(rows)?,
        ExportFormat::Csv => serialize_csv_rows(columns, rows),
    };
    if content.len() > max_bytes {
        return Err(format!(
            "export result is {} bytes, exceeding maxExportBytes {}",
            content.len(),
            max_bytes
        ));
    }
    Ok(content)
}

fn serialize_jsonl_rows(rows: &[Value]) -> Result<String, String> {
    rows.iter()
        .map(|row| serde_json::to_string(row).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| {
            if lines.is_empty() {
                String::new()
            } else {
                format!("{}\n", lines.join("\n"))
            }
        })
}

fn serialize_csv_rows(columns: &[String], rows: &[Value]) -> String {
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(
        columns
            .iter()
            .map(|column| csv_escape(column))
            .collect::<Vec<_>>()
            .join(","),
    );
    for row in rows {
        let object = row.as_object();
        lines.push(
            columns
                .iter()
                .map(|column| {
                    object
                        .and_then(|object| object.get(column))
                        .map(csv_value)
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    format!("{}\n", lines.join("\n"))
}

fn postgres_row_to_json(row: &Row) -> Result<Value, String> {
    let mut object = Map::new();
    for (idx, column) in row.columns().iter().enumerate() {
        object.insert(column.name().to_string(), postgres_cell_to_json(row, idx)?);
    }
    Ok(Value::Object(object))
}

fn postgres_cell_to_json(row: &Row, idx: usize) -> Result<Value, String> {
    let column_type = row.columns()[idx].type_();
    match *column_type {
        Type::BOOL => optional_cell::<bool>(row, idx),
        Type::INT2 => optional_cell::<i16>(row, idx),
        Type::INT4 => optional_cell::<i32>(row, idx),
        Type::INT8 => optional_cell::<i64>(row, idx),
        Type::FLOAT4 => optional_cell::<f32>(row, idx),
        Type::FLOAT8 => optional_cell::<f64>(row, idx),
        Type::JSON | Type::JSONB => optional_cell::<Value>(row, idx),
        Type::UUID => optional_cell::<Uuid>(row, idx),
        Type::TIMESTAMP => optional_cell::<NaiveDateTime>(row, idx),
        Type::TIMESTAMPTZ => optional_cell::<DateTime<Utc>>(row, idx),
        Type::DATE => optional_cell::<NaiveDate>(row, idx),
        Type::TIME => optional_cell::<NaiveTime>(row, idx),
        _ => optional_cell::<String>(row, idx),
    }
    .map(|value| value.unwrap_or(Value::Null))
    .map_err(|e| {
        format!(
            "could not serialize returned column '{}' of type {}: {}",
            row.columns()[idx].name(),
            column_type.name(),
            e
        )
    })
}

fn optional_cell<T>(row: &Row, idx: usize) -> Result<Option<Value>, PgError>
where
    T: postgres::types::FromSqlOwned,
    Value: FromPostgresCell<T>,
{
    row.try_get::<_, Option<T>>(idx)
        .map(|value| value.map(Value::from_postgres_cell))
}

trait FromPostgresCell<T> {
    fn from_postgres_cell(value: T) -> Value;
}

impl FromPostgresCell<bool> for Value {
    fn from_postgres_cell(value: bool) -> Value {
        Value::Bool(value)
    }
}

impl FromPostgresCell<i16> for Value {
    fn from_postgres_cell(value: i16) -> Value {
        Value::Number(value.into())
    }
}

impl FromPostgresCell<i32> for Value {
    fn from_postgres_cell(value: i32) -> Value {
        Value::Number(value.into())
    }
}

impl FromPostgresCell<i64> for Value {
    fn from_postgres_cell(value: i64) -> Value {
        Value::Number(value.into())
    }
}

impl FromPostgresCell<f32> for Value {
    fn from_postgres_cell(value: f32) -> Value {
        serde_json::Number::from_f64(value as f64)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

impl FromPostgresCell<f64> for Value {
    fn from_postgres_cell(value: f64) -> Value {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

impl FromPostgresCell<Value> for Value {
    fn from_postgres_cell(value: Value) -> Value {
        value
    }
}

impl FromPostgresCell<Uuid> for Value {
    fn from_postgres_cell(value: Uuid) -> Value {
        Value::String(value.to_string())
    }
}

impl FromPostgresCell<NaiveDateTime> for Value {
    fn from_postgres_cell(value: NaiveDateTime) -> Value {
        Value::String(value.to_string())
    }
}

impl FromPostgresCell<DateTime<Utc>> for Value {
    fn from_postgres_cell(value: DateTime<Utc>) -> Value {
        Value::String(value.to_rfc3339())
    }
}

impl FromPostgresCell<NaiveDate> for Value {
    fn from_postgres_cell(value: NaiveDate) -> Value {
        Value::String(value.to_string())
    }
}

impl FromPostgresCell<NaiveTime> for Value {
    fn from_postgres_cell(value: NaiveTime) -> Value {
        Value::String(value.to_string())
    }
}

impl FromPostgresCell<String> for Value {
    fn from_postgres_cell(value: String) -> Value {
        Value::String(value)
    }
}

struct PreparedImport {
    csv: String,
    row_count: u64,
}

fn normalize_columns(columns: Option<&[String]>) -> Result<Vec<String>, String> {
    let columns = columns.ok_or_else(|| "columns is required".to_string())?;
    if columns.is_empty() {
        return Err("columns must include at least one column".to_string());
    }
    let mut seen = HashSet::new();
    let normalized = columns
        .iter()
        .map(|column| {
            let column = column.trim();
            if column.is_empty() {
                return Err("columns cannot include empty names".to_string());
            }
            if !seen.insert(column.to_ascii_lowercase()) {
                return Err(format!("duplicate import column '{}'", column));
            }
            Ok(column.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(normalized)
}

fn prepare_import_csv(
    format: ExportFormat,
    source: &str,
    columns: &[String],
    header: bool,
    max_rows: u64,
) -> Result<PreparedImport, String> {
    match format {
        ExportFormat::Csv => prepare_import_csv_from_csv(source, columns, header, max_rows),
        ExportFormat::Jsonl => prepare_import_csv_from_jsonl(source, columns, max_rows),
    }
}

fn prepare_import_csv_from_csv(
    source: &str,
    columns: &[String],
    header: bool,
    max_rows: u64,
) -> Result<PreparedImport, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(header)
        .from_reader(source.as_bytes());
    let column_order = if header {
        let headers = reader
            .headers()
            .map_err(|e| format!("invalid csv header: {}", e))?
            .clone();
        columns
            .iter()
            .map(|column| {
                headers
                    .iter()
                    .position(|header| header == column)
                    .ok_or_else(|| format!("csv header missing import column '{}'", column))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        (0..columns.len()).collect()
    };

    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record(columns)
        .map_err(|e| format!("invalid csv import: {}", e))?;
    let mut row_count = 0_u64;
    for record in reader.records() {
        let record = record.map_err(|e| format!("invalid csv import: {}", e))?;
        row_count += 1;
        if row_count > max_rows {
            return Err(format!("import has more than maxRows {} rows", max_rows));
        }
        let values = column_order
            .iter()
            .map(|idx| {
                record
                    .get(*idx)
                    .ok_or_else(|| "csv row has fewer fields than requested columns".to_string())
                    .map(str::to_string)
            })
            .collect::<Result<Vec<_>, _>>()?;
        writer
            .write_record(values)
            .map_err(|e| format!("invalid csv import: {}", e))?;
    }
    let bytes = writer
        .into_inner()
        .map_err(|e| format!("invalid csv import: {}", e))?;
    let csv = String::from_utf8(bytes).map_err(|e| format!("invalid csv import: {}", e))?;
    Ok(PreparedImport { csv, row_count })
}

fn prepare_import_csv_from_jsonl(
    source: &str,
    columns: &[String],
    max_rows: u64,
) -> Result<PreparedImport, String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record(columns)
        .map_err(|e| format!("invalid jsonl import: {}", e))?;
    let mut row_count = 0_u64;
    for (index, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        row_count += 1;
        if row_count > max_rows {
            return Err(format!("import has more than maxRows {} rows", max_rows));
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|e| format!("invalid jsonl import at line {}: {}", index + 1, e))?;
        let object = value
            .as_object()
            .ok_or_else(|| format!("jsonl import line {} must be an object", index + 1))?;
        let values = columns
            .iter()
            .map(|column| {
                object
                    .get(column)
                    .map(import_field_value)
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        writer
            .write_record(values)
            .map_err(|e| format!("invalid jsonl import: {}", e))?;
    }
    let bytes = writer
        .into_inner()
        .map_err(|e| format!("invalid jsonl import: {}", e))?;
    let csv = String::from_utf8(bytes).map_err(|e| format!("invalid jsonl import: {}", e))?;
    Ok(PreparedImport { csv, row_count })
}

fn import_field_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => other.to_string(),
    }
}

fn csv_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => csv_escape(value),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => csv_escape(&other.to_string()),
    }
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn format_pg_error(error: &PgError) -> String {
    if let Some(db_error) = error.as_db_error() {
        let mut parts = vec![db_error.message().to_string()];

        if let Some(detail) = db_error.detail() {
            parts.push(format!("detail: {}", detail));
        }

        if let Some(hint) = db_error.hint() {
            parts.push(format!("hint: {}", hint));
        }

        if let Some(position) = db_error.position() {
            parts.push(format!("position: {}", format_pg_position(position)));
        }

        return parts.join("; ");
    }

    error.to_string()
}

fn format_pg_position(position: &postgres::error::ErrorPosition) -> String {
    match position {
        postgres::error::ErrorPosition::Original(position) => position.to_string(),
        postgres::error::ErrorPosition::Internal { position, query } => {
            format!("{} in internally generated query: {}", position, query)
        }
    }
}

fn required_body_field(value: Option<&str>, label: &str) -> Result<String, String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{} is required", label))
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadOnlyStatementKind {
    SelectLike,
    Show,
    Explain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedReadOnlySql {
    sql: String,
    kind: ReadOnlyStatementKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStatementKind {
    Insert,
    Update,
    Delete,
}

impl WriteStatementKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedWriteSql {
    sql: String,
    kind: WriteStatementKind,
    returns_rows: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminStatementKind {
    Create,
    Alter,
    Drop,
    Truncate,
    Grant,
    Revoke,
    Vacuum,
    Analyze,
    Reindex,
    RefreshMaterializedView,
    Comment,
    Other,
}

impl AdminStatementKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::Alter => "ALTER",
            Self::Drop => "DROP",
            Self::Truncate => "TRUNCATE",
            Self::Grant => "GRANT",
            Self::Revoke => "REVOKE",
            Self::Vacuum => "VACUUM",
            Self::Analyze => "ANALYZE",
            Self::Reindex => "REINDEX",
            Self::RefreshMaterializedView => "REFRESH MATERIALIZED VIEW",
            Self::Comment => "COMMENT",
            Self::Other => "ADMIN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedAdminSql {
    sql: String,
    kind: AdminStatementKind,
}

fn normalize_read_only_sql(raw_sql: &str) -> Result<NormalizedReadOnlySql, String> {
    let sql = raw_sql.trim().trim_end_matches(';').trim().to_string();
    if sql.is_empty() {
        return Err("sql is required".to_string());
    }
    if contains_semicolon_outside_literals(&sql) {
        return Err("only one read-only statement can be executed at a time".to_string());
    }

    if let Some(statement) = parse_single_statement(&sql)? {
        let kind =
            match statement {
                Statement::Query(_) => ReadOnlyStatementKind::SelectLike,
                Statement::ShowVariable { .. }
                | Statement::ShowStatus { .. }
                | Statement::ShowVariables { .. }
                | Statement::ShowCreate { .. }
                | Statement::ShowColumns { .. }
                | Statement::ShowDatabases { .. }
                | Statement::ShowSchemas { .. }
                | Statement::ShowCharset(_)
                | Statement::ShowCollation { .. }
                | Statement::ShowObjects(_)
                | Statement::ShowTables { .. }
                | Statement::ShowViews { .. }
                | Statement::ShowFunctions { .. } => ReadOnlyStatementKind::Show,
                Statement::Explain {
                    analyze, statement, ..
                } => {
                    if analyze {
                        return Err("read-only mode rejects EXPLAIN ANALYZE".to_string());
                    }
                    if !matches!(*statement, Statement::Query(_)) {
                        return Err(
                            "read-only mode only allows EXPLAIN for read-only queries".to_string()
                        );
                    }
                    ReadOnlyStatementKind::Explain
                }
                _ => return Err(
                    "read-only mode only allows SELECT, WITH, SHOW, EXPLAIN, and VALUES statements"
                        .to_string(),
                ),
            };
        return Ok(NormalizedReadOnlySql { sql, kind });
    }

    let tokens = sql_tokens(&sql);
    let first = tokens
        .first()
        .map(|token| token.to_ascii_lowercase())
        .ok_or_else(|| "sql is required".to_string())?;
    let kind = match first.as_str() {
        "select" | "with" | "values" => ReadOnlyStatementKind::SelectLike,
        "show" => ReadOnlyStatementKind::Show,
        "explain" => ReadOnlyStatementKind::Explain,
        _ => {
            return Err(
                "read-only mode only allows SELECT, WITH, SHOW, EXPLAIN, and VALUES statements"
                    .to_string(),
            )
        }
    };

    if matches!(kind, ReadOnlyStatementKind::Explain)
        && tokens
            .iter()
            .any(|token| token.eq_ignore_ascii_case("analyze"))
    {
        return Err("read-only mode rejects EXPLAIN ANALYZE".to_string());
    }

    let denied = [
        "insert",
        "update",
        "delete",
        "merge",
        "create",
        "alter",
        "drop",
        "truncate",
        "grant",
        "revoke",
        "copy",
        "vacuum",
        "analyze",
        "refresh",
        "reindex",
        "cluster",
        "call",
        "do",
        "execute",
        "prepare",
        "deallocate",
        "listen",
        "notify",
        "unlisten",
        "reset",
        "begin",
        "commit",
        "rollback",
        "savepoint",
        "release",
        "lock",
    ];
    if let Some(token) = tokens
        .iter()
        .map(|token| token.to_ascii_lowercase())
        .find(|token| denied.contains(&token.as_str()))
    {
        return Err(format!("read-only mode rejects '{}' statements", token));
    }

    Ok(NormalizedReadOnlySql { sql, kind })
}

fn normalize_write_sql(raw_sql: &str) -> Result<NormalizedWriteSql, String> {
    let sql = raw_sql.trim().trim_end_matches(';').trim().to_string();
    if sql.is_empty() {
        return Err("sql is required".to_string());
    }
    if contains_semicolon_outside_literals(&sql) {
        return Err("only one write statement can be executed at a time".to_string());
    }

    let tokens = sql_tokens(&sql);
    let first = tokens
        .first()
        .map(|token| token.to_ascii_lowercase())
        .ok_or_else(|| "sql is required".to_string())?;
    if first == "with" {
        let kind = write_statement_kind_from_tokens(&tokens, first.as_str())?;
        return Ok(NormalizedWriteSql {
            returns_rows: tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case("returning")),
            sql,
            kind,
        });
    }

    if let Some(statement) = parse_single_statement(&sql)? {
        let (kind, returns_rows) = match statement {
            Statement::Insert(insert) => (WriteStatementKind::Insert, insert.returning.is_some()),
            Statement::Update(update) => (WriteStatementKind::Update, update.returning.is_some()),
            Statement::Delete(delete) => (WriteStatementKind::Delete, delete.returning.is_some()),
            _ => {
                return Err(
                    "write mode only allows INSERT, UPDATE, and DELETE statements".to_string(),
                )
            }
        };
        return Ok(NormalizedWriteSql {
            sql,
            kind,
            returns_rows,
        });
    }

    let kind = write_statement_kind_from_tokens(&tokens, first.as_str())?;

    Ok(NormalizedWriteSql {
        returns_rows: tokens
            .iter()
            .any(|token| token.eq_ignore_ascii_case("returning")),
        sql,
        kind,
    })
}

fn write_statement_kind_from_tokens(
    tokens: &[String],
    first: &str,
) -> Result<WriteStatementKind, String> {
    match first {
        "insert" => return Ok(WriteStatementKind::Insert),
        "update" => return Ok(WriteStatementKind::Update),
        "delete" => return Ok(WriteStatementKind::Delete),
        _ => {}
    }

    if first == "with" {
        if let Some(token) = tokens.iter().find(|token| {
            token.eq_ignore_ascii_case("insert")
                || token.eq_ignore_ascii_case("update")
                || token.eq_ignore_ascii_case("delete")
        }) {
            return match token.to_ascii_lowercase().as_str() {
                "insert" => Ok(WriteStatementKind::Insert),
                "update" => Ok(WriteStatementKind::Update),
                "delete" => Ok(WriteStatementKind::Delete),
                _ => unreachable!(),
            };
        }
    }

    Err("write mode only allows INSERT, UPDATE, and DELETE statements".to_string())
}

fn normalize_admin_sql(raw_sql: &str) -> Result<NormalizedAdminSql, String> {
    let sql = raw_sql.trim().trim_end_matches(';').trim().to_string();
    if sql.is_empty() {
        return Err("sql is required".to_string());
    }
    if contains_semicolon_outside_literals(&sql) {
        return Err("only one admin statement can be executed at a time".to_string());
    }

    if let Some(statement) = parse_single_statement(&sql)? {
        let kind = match statement {
            Statement::CreateTable(_)
            | Statement::CreateIndex(_)
            | Statement::CreateView(_)
            | Statement::CreateSchema { .. }
            | Statement::CreatePolicy(_)
            | Statement::CreateExtension(_)
            | Statement::CreateTrigger(_)
            | Statement::CreateOperator(_)
            | Statement::CreateOperatorClass(_)
            | Statement::CreateOperatorFamily(_) => AdminStatementKind::Create,
            Statement::AlterTable(_)
            | Statement::AlterIndex { .. }
            | Statement::AlterView { .. }
            | Statement::AlterSchema(_)
            | Statement::AlterType(_)
            | Statement::AlterPolicy(_)
            | Statement::AlterOperator(_)
            | Statement::AlterOperatorClass(_)
            | Statement::AlterOperatorFamily(_) => AdminStatementKind::Alter,
            Statement::Drop { object_type, .. } => {
                ensure_allowed_drop_object(object_type)?;
                AdminStatementKind::Drop
            }
            Statement::DropFunction(_)
            | Statement::DropDomain(_)
            | Statement::DropProcedure { .. }
            | Statement::DropPolicy(_)
            | Statement::DropExtension(_)
            | Statement::DropOperator(_)
            | Statement::DropOperatorClass(_)
            | Statement::DropOperatorFamily(_)
            | Statement::DropTrigger(_) => AdminStatementKind::Drop,
            Statement::Truncate(_) => AdminStatementKind::Truncate,
            Statement::Grant(_) => AdminStatementKind::Grant,
            Statement::Revoke(_) => AdminStatementKind::Revoke,
            Statement::Vacuum(_) => AdminStatementKind::Vacuum,
            Statement::Analyze(_) => AdminStatementKind::Analyze,
            Statement::Comment { .. } => AdminStatementKind::Comment,
            Statement::Query(_)
            | Statement::Insert(_)
            | Statement::Update(_)
            | Statement::Delete(_)
            | Statement::Merge(_) => {
                return Err("admin mode does not run read/write statements".to_string())
            }
            Statement::StartTransaction { .. }
            | Statement::Commit { .. }
            | Statement::Rollback { .. }
            | Statement::Savepoint { .. } => {
                return Err("admin mode does not run transaction control statements".to_string())
            }
            _ => AdminStatementKind::Other,
        };
        return Ok(NormalizedAdminSql { sql, kind });
    }

    let tokens = sql_tokens(&sql);
    let first = tokens
        .first()
        .map(|token| token.to_ascii_lowercase())
        .ok_or_else(|| "sql is required".to_string())?;
    let kind = match first.as_str() {
        "create" => {
            ensure_schema_object_target(&tokens, "create")?;
            AdminStatementKind::Create
        }
        "alter" => {
            ensure_schema_object_target(&tokens, "alter")?;
            AdminStatementKind::Alter
        }
        "drop" => {
            ensure_schema_object_target(&tokens, "drop")?;
            AdminStatementKind::Drop
        }
        "truncate" => AdminStatementKind::Truncate,
        "grant" => AdminStatementKind::Grant,
        "revoke" => AdminStatementKind::Revoke,
        "vacuum" => AdminStatementKind::Vacuum,
        "analyze" => AdminStatementKind::Analyze,
        "reindex" => AdminStatementKind::Reindex,
        "refresh" => {
            let is_materialized_view = tokens
                .get(1)
                .is_some_and(|token| token.eq_ignore_ascii_case("materialized"))
                && tokens
                    .get(2)
                    .is_some_and(|token| token.eq_ignore_ascii_case("view"));
            if !is_materialized_view {
                return Err(
                    "admin mode only allows REFRESH MATERIALIZED VIEW for refresh commands"
                        .to_string(),
                );
            }
            AdminStatementKind::RefreshMaterializedView
        }
        _ => {
            return Err(
                "admin mode only allows schema, permission, and maintenance statements".to_string(),
            )
        }
    };

    let denied = [
        "copy",
        "call",
        "do",
        "execute",
        "prepare",
        "deallocate",
        "listen",
        "notify",
        "unlisten",
        "set",
        "reset",
        "begin",
        "commit",
        "rollback",
        "savepoint",
        "release",
        "lock",
        "database",
        "role",
        "user",
        "tablespace",
        "server",
        "subscription",
        "publication",
    ];
    if let Some(token) = tokens
        .iter()
        .skip(1)
        .map(|token| token.to_ascii_lowercase())
        .find(|token| denied.contains(&token.as_str()))
    {
        return Err(format!("admin mode rejects '{}' statements", token));
    }

    Ok(NormalizedAdminSql { sql, kind })
}

fn parse_single_statement(sql: &str) -> Result<Option<Statement>, String> {
    let dialect = PostgreSqlDialect {};
    match Parser::parse_sql(&dialect, sql) {
        Ok(mut statements) => {
            if statements.len() != 1 {
                return Err("only one SQL statement can be executed at a time".to_string());
            }
            Ok(statements.pop())
        }
        Err(_) => Ok(None),
    }
}

fn ensure_allowed_drop_object(object_type: ObjectType) -> Result<(), String> {
    match object_type {
        ObjectType::Table
        | ObjectType::View
        | ObjectType::MaterializedView
        | ObjectType::Index
        | ObjectType::Schema
        | ObjectType::Database
        | ObjectType::Role
        | ObjectType::Sequence
        | ObjectType::Type
        | ObjectType::User
        | ObjectType::Stage
        | ObjectType::Stream => Ok(()),
    }
}

fn ensure_schema_object_target(tokens: &[String], command: &str) -> Result<(), String> {
    let allowed = [
        "table",
        "index",
        "view",
        "materialized",
        "schema",
        "sequence",
        "trigger",
        "function",
        "procedure",
        "type",
        "policy",
    ];
    let Some(target) = schema_object_target_token(tokens, command) else {
        return Err(format!("admin mode requires a {} target", command));
    };
    if allowed
        .iter()
        .any(|allowed| target.eq_ignore_ascii_case(allowed))
    {
        return Ok(());
    }
    Err(format!(
        "admin mode rejects {} target '{}'",
        command, target
    ))
}

fn schema_object_target_token<'a>(tokens: &'a [String], command: &str) -> Option<&'a str> {
    let mut index = 1;

    if command.eq_ignore_ascii_case("create") {
        if tokens
            .get(index)
            .is_some_and(|token| token.eq_ignore_ascii_case("or"))
            && tokens
                .get(index + 1)
                .is_some_and(|token| token.eq_ignore_ascii_case("replace"))
        {
            index += 2;
        }

        while let Some(token) = tokens.get(index) {
            let is_modifier = [
                "global",
                "local",
                "temporary",
                "temp",
                "unlogged",
                "unique",
                "concurrently",
            ]
            .iter()
            .any(|modifier| token.eq_ignore_ascii_case(modifier));
            if !is_modifier {
                break;
            }
            index += 1;
        }
    }

    if matches!(command, "alter" | "drop")
        && tokens
            .get(index)
            .is_some_and(|token| token.eq_ignore_ascii_case("if"))
    {
        index += 1;
        if tokens
            .get(index)
            .is_some_and(|token| token.eq_ignore_ascii_case("exists"))
        {
            index += 1;
        }
    }

    tokens.get(index).map(String::as_str)
}

fn contains_semicolon_outside_literals(sql: &str) -> bool {
    scan_sql(sql, |ch| ch == ';')
}

fn sql_tokens(sql: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    scan_sql_chars(sql, |ch| {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    });
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn scan_sql<F>(sql: &str, mut predicate: F) -> bool
where
    F: FnMut(char) -> bool,
{
    let mut found = false;
    scan_sql_chars(sql, |ch| {
        if predicate(ch) {
            found = true;
        }
    });
    found
}

fn scan_sql_chars<F>(sql: &str, mut on_code_char: F)
where
    F: FnMut(char),
{
    let chars = sql.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();

        if ch == '-' && next == Some('-') {
            index += 2;
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if ch == '/' && next == Some('*') {
            index += 2;
            while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
                index += 1;
            }
            index = (index + 2).min(chars.len());
            continue;
        }
        if ch == '\'' {
            index += 1;
            while index < chars.len() {
                if chars[index] == '\'' {
                    if chars.get(index + 1) == Some(&'\'') {
                        index += 2;
                        continue;
                    }
                    index += 1;
                    break;
                }
                index += 1;
            }
            continue;
        }
        if ch == '"' {
            index += 1;
            while index < chars.len() {
                if chars[index] == '"' {
                    if chars.get(index + 1) == Some(&'"') {
                        index += 2;
                        continue;
                    }
                    index += 1;
                    break;
                }
                index += 1;
            }
            continue;
        }

        on_code_char(ch);
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_sql_accepts_select_and_rejects_mutation_tokens() {
        let normalized = normalize_read_only_sql(" select * from projects; ").unwrap();
        assert_eq!(normalized.sql, "select * from projects");
        assert_eq!(normalized.kind, ReadOnlyStatementKind::SelectLike);
        assert!(normalize_read_only_sql("select ';' as value").is_ok());
        assert!(normalize_read_only_sql("select * from x; select * from y").is_err());
        assert!(normalize_read_only_sql("update projects set name = 'x'").is_err());
        assert!(normalize_read_only_sql("select * from x where note = 'drop table ok'").is_ok());
        assert!(normalize_read_only_sql("begin read only").is_err());
        assert!(normalize_read_only_sql("commit").is_err());
        assert!(normalize_read_only_sql("copy public.widgets to stdout").is_err());
    }

    #[test]
    fn read_only_sql_accepts_show_and_safe_explain() {
        assert_eq!(
            normalize_read_only_sql("show search_path;").unwrap().kind,
            ReadOnlyStatementKind::Show
        );
        assert_eq!(
            normalize_read_only_sql("explain select * from projects;")
                .unwrap()
                .kind,
            ReadOnlyStatementKind::Explain
        );
        assert!(normalize_read_only_sql("explain analyze select * from projects").is_err());
    }

    #[test]
    fn write_sql_accepts_guarded_common_writes_only() {
        let insert = normalize_write_sql("insert into projects (name) values ('a');").unwrap();
        assert_eq!(insert.kind, WriteStatementKind::Insert);
        assert_eq!(insert.sql, "insert into projects (name) values ('a')");

        assert!(normalize_write_sql("update projects set name = 'b' where id = 1").is_ok());
        assert!(normalize_write_sql("delete from projects where id = 1").is_ok());
        assert!(normalize_write_sql("update projects set name = 'b'").is_ok());
        assert!(normalize_write_sql("delete from projects").is_ok());
        assert!(normalize_write_sql("insert into x default values returning id").is_ok());
        assert!(
            normalize_write_sql("update projects set name = 'b' where id = 1 returning id").is_ok()
        );
        assert!(normalize_write_sql("delete from projects where id = 1 returning id").is_ok());
        assert!(normalize_write_sql("truncate projects").is_err());
        assert!(normalize_write_sql("update x set note = 'drop table ok' where id = 1").is_ok());
        assert!(normalize_write_sql("update x set note = 'a'; delete from x").is_err());
        assert!(normalize_write_sql("begin").is_err());
        assert!(normalize_write_sql("insert into x select * from copy_source").is_ok());
        assert!(normalize_write_sql("copy public.widgets from stdin").is_err());
    }

    #[test]
    fn admin_sql_accepts_guarded_schema_permission_and_maintenance_only() {
        assert_eq!(
            normalize_admin_sql("create table public.audit_log (id int);")
                .unwrap()
                .kind,
            AdminStatementKind::Create
        );
        assert!(normalize_admin_sql("create temp table public.audit_log_temp (id int);").is_ok());
        assert!(
            normalize_admin_sql("create temporary table public.audit_log_temp (id int);").is_ok()
        );
        assert!(
            normalize_admin_sql("create unlogged table public.audit_log_unlogged (id int);")
                .is_ok()
        );
        assert!(normalize_admin_sql(
            "create unique index public.audit_log_idx on public.audit_log (id);"
        )
        .is_ok());
        assert!(normalize_admin_sql(
            "create or replace view public.audit_log_view as select 1 as id;"
        )
        .is_ok());
        assert!(normalize_admin_sql("drop table if exists public.audit_log;").is_ok());
        assert!(normalize_admin_sql(
            "alter table if exists public.audit_log add column note text;"
        )
        .is_ok());
        assert_eq!(
            normalize_admin_sql("refresh materialized view public.rollup;")
                .unwrap()
                .kind,
            AdminStatementKind::RefreshMaterializedView
        );
        assert!(normalize_admin_sql("grant select on table public.widgets to app_user").is_ok());
        assert!(normalize_admin_sql("vacuum public.widgets").is_ok());
        assert!(normalize_admin_sql("create database app_prod").is_ok());
        assert!(normalize_admin_sql("drop role app_user").is_ok());
        assert!(normalize_admin_sql("refresh table public.widgets").is_err());
        assert!(normalize_admin_sql("copy public.widgets to '/tmp/widgets.csv'").is_ok());
        assert!(normalize_admin_sql("create table x (id int); drop table x").is_err());
        assert!(normalize_admin_sql("begin").is_err());
        assert!(normalize_admin_sql("commit").is_err());
    }

    #[test]
    fn export_rows_are_bounded_and_formatted() {
        let columns = vec!["id".to_string(), "name".to_string(), "metadata".to_string()];
        let rows = vec![serde_json::json!({
            "id": 1,
            "name": "Ada, Lovelace",
            "metadata": {"role":"admin"}
        })];

        let csv = serialize_export_rows(ExportFormat::Csv, &columns, &rows, 1_000).unwrap();
        assert_eq!(
            csv,
            "id,name,metadata\n1,\"Ada, Lovelace\",\"{\"\"role\"\":\"\"admin\"\"}\"\n"
        );

        let jsonl = serialize_export_rows(ExportFormat::Jsonl, &columns, &rows, 1_000).unwrap();
        assert_eq!(
            jsonl,
            "{\"id\":1,\"metadata\":{\"role\":\"admin\"},\"name\":\"Ada, Lovelace\"}\n"
        );
        assert!(serialize_export_rows(ExportFormat::Jsonl, &columns, &rows, 8).is_err());
        assert!(ExportFormat::parse(Some("xlsx")).is_err());
    }

    #[test]
    fn import_rows_prepare_csv_and_jsonl_with_limits() {
        let columns = vec!["id".to_string(), "name".to_string(), "active".to_string()];
        let csv = "name,id,active\nGamma,3,true\nDelta,4,false\n";
        let prepared = prepare_import_csv(ExportFormat::Csv, csv, &columns, true, 10).unwrap();
        assert_eq!(prepared.row_count, 2);
        assert_eq!(
            prepared.csv,
            "id,name,active\n3,Gamma,true\n4,Delta,false\n"
        );

        let jsonl = "{\"id\":5,\"name\":\"Epsilon\",\"active\":true}\n";
        let prepared = prepare_import_csv(ExportFormat::Jsonl, jsonl, &columns, true, 10).unwrap();
        assert_eq!(prepared.row_count, 1);
        assert_eq!(prepared.csv, "id,name,active\n5,Epsilon,true\n");

        assert!(prepare_import_csv(ExportFormat::Csv, csv, &columns, true, 1).is_err());
        assert!(
            prepare_import_csv(ExportFormat::Csv, "id,name\n1,Ada\n", &columns, true, 10).is_err()
        );
        assert!(normalize_columns(Some(&["id".to_string(), "ID".to_string()])).is_err());
    }

    #[test]
    fn postgres_url_secret_parses_remote_hosts_and_sslmode() {
        let conn = PostgresConnection::from_secret(PostgresSecret {
            url: Some(
                "postgresql://app%40user:p%40ss@db.example.com:6543/app_prod?sslmode=require"
                    .to_string(),
            ),
            host: None,
            port: None,
            database: None,
            user: None,
            password: None,
            ssl: None,
            ssl_mode: None,
        })
        .unwrap();

        assert_eq!(conn.host, "db.example.com");
        assert_eq!(conn.port, 6543);
        assert_eq!(conn.database, "app_prod");
        assert_eq!(conn.user, "app@user");
        assert_eq!(conn.password.as_deref(), Some("p@ss"));
        assert_eq!(conn.ssl_mode, SslMode::Require);
    }

    #[test]
    fn postgres_url_secret_parses_connection_without_query_metadata() {
        let conn = PostgresConnection::from_secret(PostgresSecret {
            url: Some(
                "postgresql://postgres:postgres@localhost:5434/shippy?statusColor=DAEBC2"
                    .to_string(),
            ),
            host: None,
            port: None,
            database: None,
            user: None,
            password: None,
            ssl: None,
            ssl_mode: None,
        })
        .unwrap();

        assert_eq!(conn.host, "localhost");
        assert_eq!(conn.port, 5434);
        assert_eq!(conn.database, "shippy");
        assert_eq!(conn.user, "postgres");
        assert_eq!(conn.password.as_deref(), Some("postgres"));
        assert_eq!(conn.ssl_mode, SslMode::Prefer);
    }
}
