use std::collections::HashSet;
use std::io::{self, Read};
use std::time::{Duration, Instant};

use native_tls::TlsConnector;
use percent_encoding::percent_decode_str;
use postgres::{Client as PgClient, Config as PgConfig, Error as PgError, NoTls};
use postgres_native_tls::MakeTlsConnector;
use serde::Deserialize;
use serde_json::Value;

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
    run_select_json(client, timeout_ms, &sql, limit, offset).map(|mut value| {
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
    run_select_json(client, timeout_ms, &sql, limit, offset)
}

fn run_select_json(
    client: &mut PgClient,
    timeout_ms: u64,
    sql: &str,
    limit: u32,
    offset: u64,
) -> Result<Value, String> {
    run_read_only(client, timeout_ms, |client| {
        let columns_sql = format!("SELECT * FROM ({}) AS aivault_query LIMIT 0", sql);
        let columns = client
            .prepare(&columns_sql)
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
            "readOnly": true
        }))
    })
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
            parts.push(format!("position: {:?}", position));
        }

        return parts.join("; ");
    }

    error.to_string()
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

fn normalize_read_only_sql(raw_sql: &str) -> Result<String, String> {
    let sql = raw_sql.trim().trim_end_matches(';').trim().to_string();
    if sql.is_empty() {
        return Err("sql is required".to_string());
    }
    if contains_semicolon_outside_literals(&sql) {
        return Err("only one read-only statement can be executed at a time".to_string());
    }

    let tokens = sql_tokens(&sql);
    let first = tokens
        .first()
        .map(|token| token.to_ascii_lowercase())
        .ok_or_else(|| "sql is required".to_string())?;
    if !matches!(first.as_str(), "select" | "with" | "values") {
        return Err("read-only mode only allows SELECT, WITH, and VALUES statements".to_string());
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
        "set",
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

    Ok(sql)
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
        assert_eq!(
            normalize_read_only_sql(" select * from projects; ").unwrap(),
            "select * from projects"
        );
        assert!(normalize_read_only_sql("select ';' as value").is_ok());
        assert!(normalize_read_only_sql("select * from x; select * from y").is_err());
        assert!(normalize_read_only_sql("update projects set name = 'x'").is_err());
        assert!(normalize_read_only_sql("select * from x where note = 'drop table ok'").is_ok());
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
