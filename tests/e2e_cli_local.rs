use std::process::{Command, Output};

use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};

fn run_aivault(dir: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aivault"))
        .env("AIVAULT_DIR", dir.path())
        .args(rewrite_invoke_to_json(args))
        .output()
        .expect("failed to run aivault binary")
}

fn rewrite_invoke_to_json<'a>(args: &'a [&'a str]) -> Vec<&'a str> {
    if args.first() == Some(&"invoke") {
        let mut updated = Vec::with_capacity(args.len());
        updated.push("json");
        updated.extend_from_slice(&args[1..]);
        return updated;
    }
    if args.first() == Some(&"capability") && matches!(args.get(1), Some(&"invoke") | Some(&"call"))
    {
        let mut updated = Vec::with_capacity(args.len());
        updated.push("capability");
        updated.push("json");
        updated.extend_from_slice(&args[2..]);
        return updated;
    }
    args.to_vec()
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

fn create_registry_credential(
    dir: &TempDir,
    credential_id: &str,
    provider: &str,
    secret_ref: &str,
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
fn e2e_describe_and_aliases_return_capability_shape() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_DESCRIBE_SECRET", "sk-local-describe");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-describe-cred",
        "local-describe-provider",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(
        &dir,
        "local/describe",
        "local-describe-cred",
        &["GET"],
        &["/v1/users"],
    );

    for subcommand in ["describe", "args", "shape", "inspect"] {
        let output = run_ok_json(&dir, &["capability", subcommand, "local/describe"]);
        assert_eq!(
            output["capability"].as_str(),
            Some("local/describe"),
            "unexpected capability name for alias {subcommand}"
        );
        assert_eq!(
            output["call"]["defaults"]["method"].as_str(),
            Some("GET"),
            "default method missing for alias {subcommand}"
        );
    }
}

#[test]
fn e2e_invoke_workspace_group_context_enforces_secret_attachments() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_GROUP_CONTEXT_SECRET", "sk-group-context");
    let secret_ref = format!("vault:secret:{secret_id}");

    create_header_credential(
        &dir,
        "group-context-cred",
        "local-group-context-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/group-context",
        "group-context-cred",
        &["GET"],
        &["/v1/items"],
    );

    // Group-context invocations should not be able to use global secrets unless explicitly attached.
    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/group-context",
            "--path",
            "/v1/items",
            "--credential",
            "group-context-cred",
            "--workspace-id",
            "default",
            "--group-id",
            "dev",
        ],
    );
    assert!(
        err.contains("secret not accessible"),
        "unexpected error output: {}",
        err
    );

    run_ok_json(
        &dir,
        &[
            "secrets",
            "attach-group",
            "--id",
            &secret_id,
            "--workspace-id",
            "default",
            "--group-id",
            "dev",
        ],
    );

    // Once attached, we should proceed far enough to hit the SSRF guard (no real network call).
    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/group-context",
            "--path",
            "/v1/items",
            "--credential",
            "group-context-cred",
            "--workspace-id",
            "default",
            "--group-id",
            "dev",
        ],
    );
    assert!(
        err.contains("upstream host blocked by SSRF guard"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_workspace_scoped_secret_isolated_by_workspace_id() {
    let dir = TempDir::new().expect("temp dir");
    let created = run_ok_json(
        &dir,
        &[
            "secrets",
            "create",
            "--name",
            "LOCAL_WS_SECRET",
            "--value",
            "sk-ws",
            "--scope",
            "workspace",
            "--workspace-id",
            "default",
        ],
    );
    let secret_id = created["secretId"]
        .as_str()
        .expect("secretId should be present")
        .to_string();
    let secret_ref = format!("vault:secret:{secret_id}");

    create_header_credential(
        &dir,
        "workspace-scope-cred",
        "local-workspace-scope-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/workspace-scope",
        "workspace-scope-cred",
        &["GET"],
        &["/v1/items"],
    );

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/workspace-scope",
            "--path",
            "/v1/items",
            "--credential",
            "workspace-scope-cred",
            "--workspace-id",
            "other",
            "--group-id",
            "dev",
        ],
    );
    assert!(
        err.contains("secret not accessible"),
        "unexpected error output: {}",
        err
    );

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/workspace-scope",
            "--path",
            "/v1/items",
            "--credential",
            "workspace-scope-cred",
            "--workspace-id",
            "default",
            "--group-id",
            "dev",
        ],
    );
    assert!(
        err.contains("upstream host blocked by SSRF guard"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_builtin_registry_activates_initial_transcription_capabilities() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_REGISTRY_SECRET", "sk-local-registry");
    let secret_ref = format!("vault:secret:{secret_id}");

    create_registry_credential(&dir, "openai-default", "openai", &secret_ref);
    create_registry_credential(&dir, "deepgram-default", "deepgram", &secret_ref);
    create_registry_credential(&dir, "elevenlabs-default", "elevenlabs", &secret_ref);

    // Capabilities with exactly one method and one path prefix get defaults for both.
    let single_method_expectations = [
        (
            "openai/transcription",
            "openai",
            Some("POST"),
            Some("/v1/audio/transcriptions"),
        ),
        (
            "openai/embeddings",
            "openai",
            Some("POST"),
            Some("/v1/embeddings"),
        ),
        (
            "openai/image-generation",
            "openai",
            Some("POST"),
            Some("/v1/images"),
        ),
        (
            "openai/moderation",
            "openai",
            Some("POST"),
            Some("/v1/moderations"),
        ),
        (
            "elevenlabs/transcription",
            "elevenlabs",
            Some("POST"),
            Some("/v1/speech-to-text"),
        ),
    ];

    for (capability, provider, method, path) in single_method_expectations {
        let described = run_ok_json(&dir, &["capability", "describe", capability]);
        assert_eq!(described["provider"].as_str(), Some(provider));
        assert_eq!(described["call"]["defaults"]["method"].as_str(), method);
        assert_eq!(described["call"]["defaults"]["path"].as_str(), path);
    }

    // Multi-method capabilities have null default method but still resolve the path.
    let multi_method_expectations = [
        (
            "openai/chat-completions",
            "openai",
            Some("/v1/chat/completions"),
        ),
        ("openai/responses", "openai", Some("/v1/responses")),
        ("openai/models", "openai", Some("/v1/models")),
        ("openai/files", "openai", Some("/v1/files")),
        ("openai/vector-stores", "openai", Some("/v1/vector_stores")),
        ("openai/realtime", "openai", Some("/v1/realtime")),
        ("deepgram/transcription", "deepgram", Some("/v1/listen")),
    ];

    for (capability, provider, path) in multi_method_expectations {
        let described = run_ok_json(&dir, &["capability", "describe", capability]);
        assert_eq!(described["provider"].as_str(), Some(provider));
        assert!(
            described["call"]["defaults"]["method"].is_null(),
            "multi-method capability '{}' should have null default method",
            capability
        );
        assert_eq!(described["call"]["defaults"]["path"].as_str(), path);
    }

    // Assistants has multiple path prefixes, so both defaults are null.
    let assistants = run_ok_json(&dir, &["capability", "describe", "openai/assistants"]);
    assert_eq!(assistants["provider"].as_str(), Some("openai"));
    assert!(assistants["call"]["defaults"]["method"].is_null());
    assert!(assistants["call"]["defaults"]["path"].is_null());
}

#[test]
fn e2e_credential_create_requires_explicit_auth_and_host_for_unknown_provider() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_UNKNOWN_PROVIDER_SECRET", "sk-local-custom");
    let secret_ref = format!("vault:secret:{secret_id}");

    let err = run_err_text(
        &dir,
        &[
            "credential",
            "create",
            "custom-cred",
            "--provider",
            "custom-provider",
            "--secret-ref",
            &secret_ref,
        ],
    );
    assert!(
        err.contains("--auth is required when provider is not in built-in registry"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_requires_method_when_capability_allows_multiple_methods() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_MULTI_METHOD_SECRET", "sk-local-methods");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-methods-cred",
        "local-methods-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/multi-method",
        "local-methods-cred",
        &["GET", "POST"],
        &["/v1/users"],
    );

    let err = run_err_text(
        &dir,
        &["invoke", "local/multi-method", "--path", "/v1/users"],
    );
    assert!(
        err.contains("--method is required because capability allows multiple methods"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_requires_path_when_capability_allows_multiple_paths() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_MULTI_PATH_SECRET", "sk-local-paths");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-paths-cred",
        "local-paths-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/multi-path",
        "local-paths-cred",
        &["GET"],
        &["/v1/a", "/v1/b"],
    );

    let err = run_err_text(
        &dir,
        &[
            "capability",
            "invoke",
            "local/multi-path",
            "--method",
            "GET",
        ],
    );
    assert!(
        err.contains("--path is required because capability allows multiple path prefixes"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_rejects_mixed_payload_and_manual_flags() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_MIXED_PAYLOAD_SECRET", "sk-local-mix");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-mixed-cred",
        "local-mixed-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/mixed",
        "local-mixed-cred",
        &["GET"],
        &["/v1/items"],
    );

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/mixed",
            "--request",
            r#"{"method":"GET","path":"/v1/items"}"#,
            "--path",
            "/v1/items",
        ],
    );
    assert!(
        err.contains("do not mix --request/--request-file with manual request flags"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_rejects_request_and_request_file_together() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_REQ_FILE_SECRET", "sk-local-req-file");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-req-file-cred",
        "local-req-file-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/req-file",
        "local-req-file-cred",
        &["GET"],
        &["/v1/items"],
    );

    let file = NamedTempFile::new().expect("temp request file");
    std::fs::write(file.path(), r#"{"method":"GET","path":"/v1/items"}"#)
        .expect("write request file");
    let request_file = file.path().to_string_lossy().to_string();

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/req-file",
            "--request",
            r#"{"method":"GET","path":"/v1/items"}"#,
            "--request-file",
            &request_file,
        ],
    );
    assert!(
        err.contains("provide only one of --request or --request-file"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_rejects_multiple_body_modes() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_MULTI_BODY_SECRET", "sk-local-bodies");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-bodies-cred",
        "local-bodies-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/bodies",
        "local-bodies-cred",
        &["POST"],
        &["/v1/items"],
    );

    let file = NamedTempFile::new().expect("temp body file");
    std::fs::write(file.path(), "payload").expect("write body file");
    let body_file_path = file.path().to_string_lossy().to_string();

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/bodies",
            "--method",
            "POST",
            "--path",
            "/v1/items",
            "--body",
            "hello",
            "--body-file-path",
            &body_file_path,
        ],
    );
    assert!(
        err.contains("only one of --body, --body-file-path, or multipart flags is allowed"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_request_file_shape_parses_then_enforces_ssrf_guard() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_SSRF_SECRET", "sk-local-ssrf");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-ssrf-cred",
        "local-ssrf-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(&dir, "local/ssrf", "local-ssrf-cred", &["GET"], &["/safe"]);

    let file = NamedTempFile::new().expect("temp request file");
    std::fs::write(file.path(), r#"{"method":"GET","path":"/safe"}"#).expect("write request file");
    let request_file = file.path().to_string_lossy().to_string();

    let err = run_err_text(
        &dir,
        &["invoke", "local/ssrf", "--request-file", &request_file],
    );
    assert!(
        err.contains("upstream host blocked by SSRF guard"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_rejects_request_payload_capability_mismatch() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_CAP_MISMATCH_SECRET", "sk-local-cap-mismatch");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-cap-mismatch-cred",
        "local-cap-mismatch-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/expected",
        "local-cap-mismatch-cred",
        &["GET"],
        &["/v1/items"],
    );

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/expected",
            "--request",
            r#"{"capability":"local/other","request":{"method":"GET","path":"/v1/items","headers":[]}}"#,
        ],
    );
    assert!(
        err.contains("does not match command capability"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_aliases_have_consistent_behavior() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_ALIAS_SECRET", "sk-local-alias");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-alias-cred",
        "local-alias-provider",
        &secret_ref,
        "localhost",
    );
    create_capability(
        &dir,
        "local/alias",
        "local-alias-cred",
        &["GET"],
        &["/v1/items"],
    );

    for args in [
        vec!["invoke", "local/alias", "--path", "/v1/items"],
        vec!["capability", "invoke", "local/alias", "--path", "/v1/items"],
        vec!["capability", "call", "local/alias", "--path", "/v1/items"],
    ] {
        let err = run_err_text(&dir, &args);
        assert!(
            err.contains("upstream host blocked by SSRF guard"),
            "unexpected error output for {:?}: {}",
            args,
            err
        );
    }
}

#[test]
fn e2e_credential_create_rejects_duplicate_id() {
    let dir = TempDir::new().expect("temp dir");
    let secret_a = create_secret(&dir, "LOCAL_DUP_CRED_A", "sk-a");
    let secret_b = create_secret(&dir, "LOCAL_DUP_CRED_B", "sk-b");
    let secret_ref_a = format!("vault:secret:{secret_a}");
    let secret_ref_b = format!("vault:secret:{secret_b}");

    create_header_credential(
        &dir,
        "duplicate-cred",
        "dup-provider",
        &secret_ref_a,
        "postman-echo.com",
    );
    let err = run_err_text(
        &dir,
        &[
            "credential",
            "create",
            "duplicate-cred",
            "--provider",
            "dup-provider",
            "--secret-ref",
            &secret_ref_b,
            "--auth",
            "header",
            "--host",
            "postman-echo.com",
        ],
    );
    assert!(
        err.contains("already exists"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_capability_create_rejects_duplicate_id() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_DUP_CAP_SECRET", "sk-local-dup-cap");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "dup-cap-cred",
        "dup-cap-provider",
        &secret_ref,
        "postman-echo.com",
    );

    create_capability(
        &dir,
        "duplicate/cap",
        "dup-cap-cred",
        &["GET"],
        &["/v1/users"],
    );
    let err = run_err_text(
        &dir,
        &[
            "capability",
            "create",
            "duplicate/cap",
            "--credential",
            "dup-cap-cred",
            "--method",
            "GET",
            "--path",
            "/v1/users",
        ],
    );
    assert!(
        err.contains("already exists"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_capability_delete_removes_policy_record() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_DELETE_POLICY_SECRET", "sk-local-del");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "local-delete-cred",
        "local-delete-provider",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(
        &dir,
        "local/delete-policy",
        "local-delete-cred",
        &["GET"],
        &["/v1/users"],
    );
    run_ok_json(
        &dir,
        &[
            "capability",
            "policy",
            "set",
            "--capability",
            "local/delete-policy",
            "--max-response-body-bytes",
            "128",
        ],
    );

    let deleted = run_ok_json(&dir, &["capability", "delete", "local/delete-policy"]);
    assert_eq!(deleted["removedCapability"].as_bool(), Some(true));
    assert_eq!(deleted["removedPolicy"].as_bool(), Some(true));

    let listed = run_ok_json(&dir, &["capability", "list"]);
    let policies = listed["policies"]
        .as_array()
        .expect("policies should be an array");
    assert!(
        policies.is_empty(),
        "policies should be empty after deleting capability, got {:?}",
        policies
    );
}

#[test]
fn e2e_invoke_fails_when_credential_is_deleted_after_capability_creation() {
    let dir = TempDir::new().expect("temp dir");
    let secret_id = create_secret(&dir, "LOCAL_DELETED_CRED_SECRET", "sk-local-del-cred");
    let secret_ref = format!("vault:secret:{secret_id}");
    create_header_credential(
        &dir,
        "deleted-cred",
        "deleted-provider",
        &secret_ref,
        "postman-echo.com",
    );
    create_capability(
        &dir,
        "local/deleted-cred",
        "deleted-cred",
        &["GET"],
        &["/v1/users"],
    );

    let deleted = run_ok_json(&dir, &["credential", "delete", "deleted-cred"]);
    assert_eq!(deleted["removed"].as_bool(), Some(true));

    let err = run_err_text(
        &dir,
        &["invoke", "local/deleted-cred", "--path", "/v1/users"],
    );
    assert!(
        err.contains("no credential for capability provider"),
        "unexpected error output: {}",
        err
    );
}
