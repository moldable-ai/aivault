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
