use bugraph::TokenCounter;
use std::{fs, path::Path, process::Command};

#[test]
fn forge_context_ranks_erc_4626_vault_classes_from_solidity_natspec() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = root.join("tests/fixtures/forge_context_vault.sol");
    let output_path = std::env::temp_dir().join(format!(
        "bugraph-forge-context-generic-{}.md",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_bugraph"))
        .current_dir(root)
        .args([
            "forge-context",
            "data/owasp.json",
            "--extra",
            "data/vaults.json",
            "data/protocols.json",
            "4096",
            "12",
            fixture.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    let context = fs::read_to_string(&output_path).unwrap();
    assert!(context.contains("# Bugraph context for forge properties"));
    assert!(context.contains("checklist of likely failure modes"));
    assert!(context.contains("target's own documentation still decides correct behavior"));
    assert!(context.contains("fm:vault-preview-bounds"), "{context}");
    assert!(
        context.contains("fm:vault-limit-overstatement"),
        "{context}"
    );
    let headings = context
        .lines()
        .filter(|line| line.starts_with("## `"))
        .count();
    assert!(headings <= 12);
    assert!(
        context
            .split("## `")
            .skip(1)
            .all(|section| section.contains("**Key condition to test:**"))
    );
    let preview = context
        .split("## `fm:vault-preview-bounds`")
        .nth(1)
        .unwrap()
        .split("**Key condition to test:**")
        .next()
        .unwrap();
    let description_lines = preview.matches("  \n").count() + 1;
    assert!((2..=4).contains(&description_lines), "{preview}");
    assert!(!context.lines().any(|line| {
        line.starts_with("## `finding:")
            || line.starts_with("## `mode:")
            || line.starts_with("## `protocol:")
            || line.starts_with("## `bastet:")
    }));
    assert!(!context.contains("```"));
    assert!(TokenCounter::for_model("gpt-4o").unwrap().count(&context) <= 4096);
}

#[test]
fn forge_context_includes_audit_findings_only_when_requested() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = root.join("tests/fixtures/forge_context_vault.sol");
    let output_path = std::env::temp_dir().join(format!(
        "bugraph-forge-context-findings-{}.md",
        std::process::id()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_bugraph"))
        .current_dir(root)
        .args([
            "forge-context",
            "data/owasp.json",
            "--extra",
            "data/vaults.json",
            "data/protocols.json",
            "--include-findings",
            "4096",
            "4",
            fixture.to_str().unwrap(),
            "--out",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let context = fs::read_to_string(&output_path).unwrap();
    assert!(
        context.contains("finding:cantina:bitcorn-deposit"),
        "{context}"
    );
}
