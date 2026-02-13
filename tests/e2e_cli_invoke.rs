use std::process::{Command, Output};

use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};

fn e2e_enabled() -> bool {
    std::env::var("AIVAULT_E2E_NETWORK")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn run_aivault(dir: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aivault"))
        .env("AIVAULT_DIR", dir.path())
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

fn create_secret(dir: &TempDir, name: &str, value: &str) -> String {
    let created = run_ok_json(
        dir,
        &[
            "secrets", "create", "--name", name, "--value", value, "--scope", "global",
        ],
    );
    created["secretId"]
        .as_str()
        .expect("secretId should be present")
        .to_string()
}

fn create_header_credential(
    dir: &TempDir,
    credential_id: &str,
    provider: &str,
    secret_ref: &str,
    host: &str,
) {
    run_ok_json(
        dir,
        &[
            "credential",
            "create",
            credential_id,
            "--provider",
            provider,
            "--secret-ref",
            secret_ref,
            "--auth",
            "header",
            "--host",
            host,
        ],
    );
}

fn create_capability(
    dir: &TempDir,
    capability_id: &str,
    credential_id: &str,
    methods: &[&str],
    paths: &[&str],
) {
    let mut args = vec![
        "capability",
        "create",
        capability_id,
        "--credential",
        credential_id,
    ];
    for method in methods {
        args.push("--method");
        args.push(method);
    }
    for path in paths {
        args.push("--path");
        args.push(path);
    }
    run_ok_json(dir, &args);
}

#[test]
fn e2e_invoke_injects_header_secret_and_executes_upstream() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_HEADER_SECRET", "sk-e2e-header-secret");
    let secret_ref = format!("vault:secret:{secret_id}");

    create_header_credential(
        &dir,
        "openai-header",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );

    create_capability(&dir, "openai/get", "openai-header", &["GET"], &["/get"]);

    let response = run_ok_json(&dir, &["invoke", "openai/get", "--path", "/get?e2e=header"]);
    let planned_url = response["planned"]["url"]
        .as_str()
        .expect("planned.url should be present");
    assert!(
        planned_url.starts_with("https://postman-echo.com/get"),
        "unexpected planned URL: {}",
        planned_url
    );

    let body = response["response"]["bodyUtf8"]
        .as_str()
        .expect("response.bodyUtf8 should be present");
    assert!(
        body.contains("Bearer sk-e2e-header-secret"),
        "upstream echo body should contain injected bearer header"
    );
    assert!(
        !body.contains("vault:secret:"),
        "secret references must not be forwarded upstream"
    );
}

#[test]
fn e2e_invoke_rejects_caller_owned_query_auth_param() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_QUERY_SECRET", "query-secret");
    let secret_ref = format!("vault:secret:{secret_id}");

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "legacy-query",
            "--provider",
            "legacy",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "query",
            "--query-param",
            "api_key",
            "--host",
            "postman-echo.com",
        ],
    );

    create_capability(&dir, "legacy/get", "legacy-query", &["GET"], &["/get"]);

    let err = run_err_text(
        &dir,
        &["invoke", "legacy/get", "--path", "/get?api_key=attacker"],
    );
    assert!(
        err.contains("query auth parameter is broker-managed"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_enforces_capability_method_policy() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_METHOD_SECRET", "sk-e2e-method-secret");
    let secret_ref = format!("vault:secret:{secret_id}");

    create_header_credential(
        &dir,
        "openai-method",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );

    create_capability(
        &dir,
        "openai/get-only",
        "openai-method",
        &["GET"],
        &["/get"],
    );

    let err = run_err_text(
        &dir,
        &[
            "capability",
            "invoke",
            "openai/get-only",
            "--method",
            "POST",
            "--path",
            "/post",
        ],
    );
    assert!(
        err.contains("method not allowed by capability"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_top_level_and_nested_aliases_reach_upstream() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_ALIAS_SECRET", "sk-e2e-alias");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "openai-alias",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(&dir, "openai/alias", "openai-alias", &["GET"], &["/get"]);

    for args in [
        vec!["invoke", "openai/alias", "--path", "/get?alias=top"],
        vec![
            "capability",
            "invoke",
            "openai/alias",
            "--path",
            "/get?alias=nested",
        ],
        vec![
            "capability",
            "call",
            "openai/alias",
            "--path",
            "/get?alias=call",
        ],
    ] {
        let response = run_ok_json(&dir, &args);
        assert_eq!(response["response"]["status"].as_u64(), Some(200));
    }
}

#[test]
fn e2e_invoke_query_auth_is_injected_when_param_not_supplied() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_QUERY_INJECT_SECRET", "query-injected");
    let secret_ref = format!("vault:secret:{secret_id}");

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "legacy-query-inject",
            "--provider",
            "legacy",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "query",
            "--query-param",
            "api_key",
            "--host",
            "postman-echo.com",
        ],
    );
    create_capability(
        &dir,
        "legacy/inject",
        "legacy-query-inject",
        &["GET"],
        &["/get"],
    );

    let response = run_ok_json(&dir, &["invoke", "legacy/inject", "--path", "/get?x=1"]);
    let body = response["response"]["bodyUtf8"]
        .as_str()
        .expect("response.bodyUtf8 should be present");
    assert!(
        body.contains("\"api_key\":\"query-injected\""),
        "query-auth parameter should be injected by broker, body: {}",
        body
    );
}

#[test]
fn e2e_invoke_rejects_caller_supplied_auth_header_even_with_upstream() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_AUTH_HEADER_SECRET", "sk-e2e-auth-header");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "openai-auth-header",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(
        &dir,
        "openai/auth-header",
        "openai-auth-header",
        &["GET"],
        &["/get"],
    );

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "openai/auth-header",
            "--path",
            "/get",
            "--header",
            "authorization=Bearer attacker",
        ],
    );
    assert!(
        err.contains("caller-supplied auth headers are not allowed"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_default_method_and_path_are_used_when_unambiguous() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_DEFAULTS_SECRET", "sk-e2e-defaults");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "openai-defaults",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(
        &dir,
        "openai/defaults",
        "openai-defaults",
        &["GET"],
        &["/get"],
    );

    let response = run_ok_json(&dir, &["invoke", "openai/defaults"]);
    let planned_url = response["planned"]["url"]
        .as_str()
        .expect("planned.url should be present");
    assert!(
        planned_url.starts_with("https://postman-echo.com/get"),
        "unexpected planned URL: {}",
        planned_url
    );
    assert_eq!(response["response"]["status"].as_u64(), Some(200));
}

#[test]
fn e2e_invoke_request_file_accepts_request_object_and_envelope_object() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_REQFILE_SECRET", "sk-e2e-req-file");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "openai-req-file",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(
        &dir,
        "openai/req-file",
        "openai-req-file",
        &["GET"],
        &["/get"],
    );

    let request_file = NamedTempFile::new().expect("request file");
    std::fs::write(
        request_file.path(),
        r#"{"method":"GET","path":"/get?mode=request"}"#,
    )
    .expect("write request file");
    let request_path = request_file.path().to_string_lossy().to_string();
    let response_request = run_ok_json(
        &dir,
        &["invoke", "openai/req-file", "--request-file", &request_path],
    );
    assert_eq!(response_request["response"]["status"].as_u64(), Some(200));

    let envelope_file = NamedTempFile::new().expect("envelope file");
    std::fs::write(
        envelope_file.path(),
        r#"{"capability":"openai/req-file","request":{"method":"GET","path":"/get?mode=envelope","headers":[]}}"#,
    )
    .expect("write envelope file");
    let envelope_path = envelope_file.path().to_string_lossy().to_string();
    let response_envelope = run_ok_json(
        &dir,
        &[
            "invoke",
            "openai/req-file",
            "--request-file",
            &envelope_path,
        ],
    );
    assert_eq!(response_envelope["response"]["status"].as_u64(), Some(200));
}

#[test]
fn e2e_invoke_multipart_content_type_is_broker_owned() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_MULTIPART_SECRET", "sk-e2e-multipart");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "openai-multipart",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(
        &dir,
        "openai/multipart",
        "openai-multipart",
        &["POST"],
        &["/post"],
    );

    let response = run_ok_json(
        &dir,
        &[
            "invoke",
            "openai/multipart",
            "--method",
            "POST",
            "--path",
            "/post",
            "--header",
            "content-type=application/json",
            "--multipart-field",
            "x=1",
        ],
    );
    let body = response["response"]["bodyUtf8"]
        .as_str()
        .expect("response.bodyUtf8 should be present");
    assert!(
        body.contains("multipart/form-data"),
        "expected multipart content-type in upstream echo body: {}",
        body
    );
    assert!(
        !body.contains("application/json"),
        "caller-supplied content-type should not be preserved for multipart"
    );
}

#[test]
fn e2e_invoke_applies_response_body_block_filtering_policy() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_FILTER_SECRET", "sk-e2e-filter");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "openai-filter",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(&dir, "openai/filter", "openai-filter", &["GET"], &["/get"]);
    run_ok_json(
        &dir,
        &[
            "capability",
            "policy",
            "set",
            "--capability",
            "openai/filter",
            "--response-block",
            "postman-echo.com",
        ],
    );

    let response = run_ok_json(&dir, &["invoke", "openai/filter", "--path", "/get?x=1"]);
    let body = response["response"]["bodyUtf8"]
        .as_str()
        .expect("response.bodyUtf8 should be present");
    assert!(
        body.contains("[REDACTED]"),
        "response should contain redacted marker, got: {}",
        body
    );
}

#[test]
fn e2e_invoke_blocks_oversized_response_body_by_policy() {
    if !e2e_enabled() {
        eprintln!("skipping network e2e: set AIVAULT_E2E_NETWORK=1");
        return;
    }

    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "E2E_RESP_SIZE_SECRET", "sk-e2e-resp-size");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "openai-resp-size",
        "openai",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(
        &dir,
        "openai/resp-size",
        "openai-resp-size",
        &["GET"],
        &["/get"],
    );
    run_ok_json(
        &dir,
        &[
            "capability",
            "policy",
            "set",
            "--capability",
            "openai/resp-size",
            "--max-response-body-bytes",
            "8",
        ],
    );

    let err = run_err_text(&dir, &["invoke", "openai/resp-size", "--path", "/get?x=1"]);
    assert!(
        err.contains("response body exceeds capability size limit"),
        "unexpected error output: {}",
        err
    );
}
