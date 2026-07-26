#[test]
fn release_workflow_and_readme_expose_verifiable_artifact_signing() {
    let workflow = std::fs::read_to_string(".github/workflows/release.yml")
        .expect("release workflow must be readable");

    // Ensure the release pipeline continues to include core supply-chain protections.
    assert!(
        workflow.contains("Sign binaries (macOS)"),
        "release workflow missing macOS codesign step label"
    );
    assert!(
        workflow.contains("Notarize zip (macOS)"),
        "release workflow missing macOS notarization step label"
    );
    assert!(
        workflow.contains("cosign sign-blob"),
        "release workflow missing cosign sign-blob invocation"
    );

    let readme = std::fs::read_to_string("README.md").expect("README must be readable");
    assert!(
        readme.contains("## Release verification"),
        "README missing Release verification section"
    );
    assert!(
        readme.contains("codesign -dv"),
        "README missing codesign verification example"
    );
    assert!(
        readme.contains("cosign verify-blob"),
        "README missing cosign verification example"
    );
}

#[test]
fn local_build_and_install_sign_macos_runtime_artifacts() {
    let package = std::fs::read_to_string("package.json").expect("package.json must be readable");
    assert!(
        package.contains(
            "\"build:release\": \"cargo build --release --all-targets && bash scripts/sign-local-macos.sh\""
        ),
        "release builds must run the local macOS signing helper"
    );

    let install = std::fs::read_to_string("scripts/install-local.sh")
        .expect("local install must be readable");
    assert!(
        install.contains("bash \"$ROOT/scripts/sign-local-macos.sh\""),
        "local installs must sign artifacts before copying them into Moldable"
    );
    assert!(
        install.contains("$HOME/moldable-desktop/desktop/src-tauri"),
        "local installs must discover the active moldable-desktop checkout"
    );

    let signing = std::fs::read_to_string("scripts/sign-local-macos.sh")
        .expect("local signing helper must be readable");
    for binary in [
        "target/release/aivault",
        "target/release/aivaultd",
        "providers/postgres/target/release/aivault-provider-postgres",
    ] {
        assert!(
            signing.contains(binary),
            "local signing helper does not cover {binary}"
        );
    }
    assert!(
        signing.contains("--options runtime") && signing.contains("--timestamp"),
        "local signing must enable hardened runtime and trusted timestamps"
    );
    assert!(
        signing.contains("/usr/bin/codesign --verify --strict"),
        "local signing must verify every signed artifact"
    );
}
