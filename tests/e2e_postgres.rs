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
        ],
    );

    let query = run_ok_json(
        &dir,
        &[
            "json",
            "postgres/query",
            "--credential",
            "postgres-e2e",
            "--workspace-id",
            "e2e",
            "--body",
            "{\"sql\":\"select name from public.widgets order by id\",\"limit\":5}",
        ],
    );
    assert_eq!(
        query["response"]["json"]["result"]["rows"][0]["name"].as_str(),
        Some("alpha")
    );

    let paged_query = run_ok_json(
        &dir,
        &[
            "json",
            "postgres/query",
            "--credential",
            "postgres-e2e",
            "--workspace-id",
            "e2e",
            "--body",
            "{\"sql\":\"select name from public.widgets order by id\",\"limit\":1,\"offset\":1}",
        ],
    );
    assert_eq!(
        paged_query["response"]["json"]["result"]["rows"][0]["name"].as_str(),
        Some("beta")
    );
    assert_eq!(
        paged_query["response"]["json"]["result"]["offset"].as_u64(),
        Some(1)
    );

    let tables = run_ok_json(
        &dir,
        &[
            "json",
            "postgres/list-tables",
            "--credential",
            "postgres-e2e",
            "--workspace-id",
            "e2e",
            "--body",
            "{\"schema\":\"public\"}",
        ],
    );
    assert!(tables["response"]["json"]["result"]["tables"]
        .as_array()
        .unwrap()
        .iter()
        .any(|table| table["name"].as_str() == Some("widgets")));

    let err = run_err_text(
        &dir,
        &[
            "json",
            "postgres/query",
            "--credential",
            "postgres-e2e",
            "--workspace-id",
            "e2e",
            "--body",
            "{\"sql\":\"delete from public.widgets\"}",
        ],
    );
    assert!(err.contains("read-only mode"));
}
