use std::fs;
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

const DEFAULT_POSTGRES_URL: &str =
    "postgresql://postgres:postgres@localhost:55432/aivault_postgres_test?sslmode=disable";

fn run_aivault(dir: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aivault"))
        .env("AIVAULT_DIR", dir.path())
        .env("AIVAULTD_DISABLE", "1")
        .args(args)
        .output()
        .expect("failed to run aivault binary")
}

fn run_ok_json(dir: &TempDir, args: &[&str]) -> Value {
    let output = run_aivault(dir, args);
    assert!(
        output.status.success(),
        "command failed: aivault {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON")
}

fn run_err_text(dir: &TempDir, args: &[&str]) -> String {
    let output = run_aivault(dir, args);
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded: aivault {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn invoke_ok(dir: &TempDir, capability: &str, credential: &str, body: Value) -> Value {
    let body = body.to_string();
    run_ok_json(
        dir,
        &[
            "json",
            capability,
            "--credential",
            credential,
            "--workspace-id",
            "e2e",
            "--body",
            &body,
        ],
    )
}

fn invoke_err(dir: &TempDir, capability: &str, credential: &str, body: Value) -> String {
    let body = body.to_string();
    run_err_text(
        dir,
        &[
            "json",
            capability,
            "--credential",
            credential,
            "--workspace-id",
            "e2e",
            "--body",
            &body,
        ],
    )
}

fn host_authority(url: &str) -> String {
    let parsed = reqwest::Url::parse(url).expect("valid postgres url");
    format!(
        "{}:{}",
        parsed.host_str().expect("postgres url host"),
        parsed.port().unwrap_or(5432)
    )
}

#[test]
fn e2e_postgres_capabilities_query_fixture_database() {
    if std::env::var("AIVAULT_E2E_POSTGRES").ok().as_deref() != Some("1") {
        eprintln!("skipping postgres e2e; set AIVAULT_E2E_POSTGRES=1");
        return;
    }

    let postgres_url =
        std::env::var("AIVAULT_E2E_POSTGRES_URL").unwrap_or_else(|_| DEFAULT_POSTGRES_URL.into());
    let dir = TempDir::new().expect("temp dir");
    let secret_value = serde_json::json!({ "url": postgres_url }).to_string();

    let created = run_ok_json(
        &dir,
        &[
            "secrets",
            "create",
            "--name",
            "POSTGRES_E2E_URL",
            "--value",
            &secret_value,
            "--scope",
            "workspace",
            "--workspace-id",
            "e2e",
        ],
    );
    let secret_ref = format!("vault:secret:{}", created["secretId"].as_str().unwrap());
    let authority = host_authority(&postgres_url);

    run_ok_json(&dir, &["provider", "install", "postgres", "--enable"]);

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "postgres-e2e",
            "--provider",
            "postgres",
            "--secret-ref",
            &secret_ref,
            "--workspace-id",
            "e2e",
            "--host",
            &authority,
            "--max-policy-mode",
            "write",
        ],
    );

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "postgres-e2e-readonly",
            "--provider",
            "postgres",
            "--secret-ref",
            &secret_ref,
            "--workspace-id",
            "e2e",
            "--host",
            &authority,
        ],
    );

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "postgres-e2e-admin",
            "--provider",
            "postgres",
            "--secret-ref",
            &secret_ref,
            "--workspace-id",
            "e2e",
            "--host",
            &authority,
            "--max-policy-mode",
            "admin",
        ],
    );

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "postgres-e2e-wrong-host",
            "--provider",
            "postgres",
            "--secret-ref",
            &secret_ref,
            "--workspace-id",
            "e2e",
            "--host",
            "example.com:5432",
        ],
    );

    let connection = invoke_ok(
        &dir,
        "postgres/test-connection",
        "postgres-e2e",
        serde_json::json!({}),
    );
    assert_eq!(
        connection["response"]["json"]["result"]["database"].as_str(),
        Some("aivault_postgres_test")
    );

    invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"delete from public.widgets",
            "maxAffectedRows":100
        }),
    );
    invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"insert into public.widgets (id, name, active) values (1, 'alpha', true), (2, 'beta', false), (3, 'gamma', true)",
            "maxAffectedRows":100
        }),
    );

    let schemas = invoke_ok(
        &dir,
        "postgres/list-schemas",
        "postgres-e2e",
        serde_json::json!({}),
    );
    assert!(schemas["response"]["json"]["result"]["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .any(|schema| schema.as_str() == Some("public")));

    let describe = invoke_ok(
        &dir,
        "postgres/describe-table",
        "postgres-e2e",
        serde_json::json!({"schema":"public","table":"widgets"}),
    );
    let columns = describe["response"]["json"]["result"]["columns"]
        .as_array()
        .unwrap();
    assert!(columns.iter().any(|column| {
        column["name"].as_str() == Some("id") && column["primaryKey"].as_bool() == Some(true)
    }));

    let preview = invoke_ok(
        &dir,
        "postgres/preview-table",
        "postgres-e2e",
        serde_json::json!({"schema":"public","table":"widgets","limit":1,"offset":1}),
    );
    assert_eq!(
        preview["response"]["json"]["result"]["rows"][0]["name"].as_str(),
        Some("beta")
    );

    let query = invoke_ok(
        &dir,
        "postgres/query",
        "postgres-e2e",
        serde_json::json!({"sql":"select name from public.widgets order by id","limit":5}),
    );
    assert_eq!(
        query["response"]["json"]["result"]["rows"][0]["name"].as_str(),
        Some("alpha")
    );

    let show = invoke_ok(
        &dir,
        "postgres/query",
        "postgres-e2e",
        serde_json::json!({"sql":"show server_version","limit":1}),
    );
    assert_eq!(
        show["response"]["json"]["result"]["command"].as_str(),
        Some("SHOW")
    );

    let explain = invoke_ok(
        &dir,
        "postgres/query",
        "postgres-e2e",
        serde_json::json!({"sql":"explain select * from public.widgets","limit":10}),
    );
    assert_eq!(
        explain["response"]["json"]["result"]["command"].as_str(),
        Some("EXPLAIN")
    );

    let values = invoke_ok(
        &dir,
        "postgres/query",
        "postgres-e2e",
        serde_json::json!({"sql":"values (1, 'one')","limit":1}),
    );
    assert_eq!(
        values["response"]["json"]["result"]["rowCount"].as_u64(),
        Some(1)
    );

    let paged_query = invoke_ok(
        &dir,
        "postgres/query",
        "postgres-e2e",
        serde_json::json!({"sql":"select name from public.widgets order by id","limit":1,"offset":1}),
    );
    assert_eq!(
        paged_query["response"]["json"]["result"]["rows"][0]["name"].as_str(),
        Some("beta")
    );
    assert_eq!(
        paged_query["response"]["json"]["result"]["offset"].as_u64(),
        Some(1)
    );

    let export = invoke_ok(
        &dir,
        "postgres/export-query",
        "postgres-e2e",
        serde_json::json!({
            "sql":"select id, name from public.widgets order by id",
            "format":"csv",
            "limit":2,
            "maxExportBytes":1024
        }),
    );
    assert_eq!(
        export["response"]["json"]["result"]["format"].as_str(),
        Some("csv")
    );
    assert_eq!(
        export["response"]["json"]["result"]["content"].as_str(),
        Some("id,name\n1,alpha\n2,beta\n")
    );

    let export_file = invoke_ok(
        &dir,
        "postgres/export-file",
        "postgres-e2e",
        serde_json::json!({
            "sql":"select id, name from public.widgets order by id",
            "format":"jsonl",
            "limit":2,
            "filename":"widgets-export"
        }),
    );
    let export_path = export_file["response"]["json"]["result"]["path"]
        .as_str()
        .expect("export file path");
    assert!(export_path.ends_with("widgets-export.jsonl"));
    let exported = fs::read_to_string(export_path).expect("read export file");
    assert!(exported.contains("\"name\":\"alpha\""));

    let export_rejects_show = invoke_err(
        &dir,
        "postgres/export-query",
        "postgres-e2e",
        serde_json::json!({"sql":"show server_version","format":"csv"}),
    );
    assert!(export_rejects_show.contains("export mode only allows"));

    let tables = invoke_ok(
        &dir,
        "postgres/list-tables",
        "postgres-e2e",
        serde_json::json!({"schema":"public"}),
    );
    assert!(tables["response"]["json"]["result"]["tables"]
        .as_array()
        .unwrap()
        .iter()
        .any(|table| table["name"].as_str() == Some("widgets")));

    let host_denied = invoke_err(
        &dir,
        "postgres/query",
        "postgres-e2e-wrong-host",
        serde_json::json!({"sql":"select 1"}),
    );
    assert!(host_denied.contains("is not allowed by credential"));

    let err = invoke_err(
        &dir,
        "postgres/query",
        "postgres-e2e",
        serde_json::json!({"sql":"delete from public.widgets"}),
    );
    assert!(err.contains("read-only mode"));

    let read_only_ceiling = invoke_err(
        &dir,
        "postgres/execute",
        "postgres-e2e-readonly",
        serde_json::json!({
            "policyMode":"write",
            "sql":"update public.widgets set active = true where id = 2",
            "maxAffectedRows":1
        }),
    );
    assert!(read_only_ceiling.contains("allows policy mode"));

    let missing_policy = invoke_err(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "sql":"update public.widgets set active = true where id = 2",
            "maxAffectedRows":1
        }),
    );
    assert!(missing_policy.contains("requires explicit policyMode"));

    let write_without_where = invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({"policyMode":"write","sql":"update public.widgets set active = true"}),
    );
    assert_eq!(
        write_without_where["response"]["json"]["result"]["command"].as_str(),
        Some("UPDATE")
    );

    invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"delete from public.widgets where id = 4",
            "maxAffectedRows":1
        }),
    );
    let insert = invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"insert into public.widgets (id, name, active) values (4, 'delta', true)",
            "maxAffectedRows":1
        }),
    );
    assert_eq!(
        insert["response"]["json"]["result"]["command"].as_str(),
        Some("INSERT")
    );

    let returning_insert = invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"update public.widgets set name = 'delta updated' where id = 4 returning id, name",
            "maxAffectedRows":1
        }),
    );
    assert_eq!(
        returning_insert["response"]["json"]["result"]["rows"][0]["name"].as_str(),
        Some("delta updated")
    );
    assert_eq!(
        returning_insert["response"]["json"]["result"]["columns"][0].as_str(),
        Some("id")
    );

    let cte_returning_insert = invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"with seed as (select 'epsilon'::text as name, true::boolean as active) insert into public.widgets (id, name, active) select 5, name, active from seed returning *",
            "maxAffectedRows":1
        }),
    );
    assert_eq!(
        cte_returning_insert["response"]["json"]["result"]["rows"][0]["name"].as_str(),
        Some("epsilon")
    );
    assert_eq!(
        cte_returning_insert["response"]["json"]["result"]["rows"][0]["active"].as_bool(),
        Some(true)
    );

    let write = invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"update public.widgets set active = true where id = 2",
            "maxAffectedRows":1
        }),
    );
    assert_eq!(
        write["response"]["json"]["result"]["affectedRows"].as_u64(),
        Some(1)
    );

    invoke_ok(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"delete from public.widgets where id = 3",
            "maxAffectedRows":1
        }),
    );

    let import_dir = dir.path().join("postgres").join("imports");
    fs::create_dir_all(&import_dir).expect("create import dir");
    let import_path = import_dir.join("widgets.csv");
    fs::write(&import_path, "id,name,active\n3,gamma,true\n").expect("write import source");
    let import_body = serde_json::json!({
        "policyMode": "write",
        "schema": "public",
        "table": "widgets",
        "columns": ["id", "name", "active"],
        "format": "csv",
        "sourcePath": import_path.display().to_string(),
        "maxRows": 10,
        "maxImportBytes": 1024
    });

    let import = invoke_ok(&dir, "postgres/import-rows", "postgres-e2e", import_body);
    assert_eq!(
        import["response"]["json"]["result"]["affectedRows"].as_u64(),
        Some(1)
    );
    let import_check = invoke_ok(
        &dir,
        "postgres/query",
        "postgres-e2e",
        serde_json::json!({"sql":"select name from public.widgets where id = 3"}),
    );
    assert_eq!(
        import_check["response"]["json"]["result"]["rows"][0]["name"].as_str(),
        Some("gamma")
    );

    let admin_write_ceiling = invoke_err(
        &dir,
        "postgres/admin",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"vacuum public.widgets"
        }),
    );
    assert!(admin_write_ceiling.contains("allows policy mode"));

    invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"drop database if exists aivault_admin_e2e_db"
        }),
    );

    invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"create database aivault_admin_e2e_db"
        }),
    );

    invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"drop database aivault_admin_e2e_db"
        }),
    );

    let create_admin_table = invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"create table if not exists public.aivault_admin_e2e (id integer primary key)"
        }),
    );
    assert_eq!(
        create_admin_table["response"]["json"]["result"]["command"].as_str(),
        Some("CREATE")
    );

    invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"create temp table aivault_admin_temp_e2e (id integer)"
        }),
    );

    invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"alter table public.aivault_admin_e2e add column if not exists note text"
        }),
    );

    invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"truncate table public.aivault_admin_e2e"
        }),
    );

    invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"vacuum public.widgets"
        }),
    );

    invoke_ok(
        &dir,
        "postgres/admin",
        "postgres-e2e-admin",
        serde_json::json!({
            "policyMode":"admin",
            "sql":"drop table if exists public.aivault_admin_e2e"
        }),
    );

    let over_limit = invoke_err(
        &dir,
        "postgres/execute",
        "postgres-e2e",
        serde_json::json!({
            "policyMode":"write",
            "sql":"update public.widgets set active = false where id in (1,2)",
            "maxAffectedRows":1
        }),
    );
    assert!(over_limit.contains("exceeding maxAffectedRows"));

    let rollback_check = invoke_ok(
        &dir,
        "postgres/query",
        "postgres-e2e",
        serde_json::json!({"sql":"select count(*)::int as inactive_count from public.widgets where active = false"}),
    );
    assert_eq!(
        rollback_check["response"]["json"]["result"]["rows"][0]["inactive_count"].as_i64(),
        Some(0)
    );
}
