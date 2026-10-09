use cimices::{Graph, import_owasp};
use std::{fs, path::PathBuf};

fn temporary_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("cimices-import-{}-{name}", std::process::id()));
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    root
}

#[test]
fn imports_exact_markdown_in_stable_id_order() {
    let root = temporary_root("exact");
    let first_dir = root.join("docs/SCWE/SCSVS-AUTH");
    let second_dir = root.join("docs/SCWE/SCSVS-ARCH");
    let scsvs_dir = root.join("docs/SCSVS");
    fs::create_dir_all(&first_dir).unwrap();
    fs::create_dir_all(&second_dir).unwrap();
    fs::create_dir_all(&scsvs_dir).unwrap();
    fs::write(
        scsvs_dir.join("scsvs.yaml"),
        "groups:\n- gid: SCSVS-CODE\n  title: Code\n  description: Code failures.\n  controls: []\n- gid: SCSVS-GOV\n  title: Governance\n  description: Governance failures.\n  controls: []\n",
    )
    .unwrap();
    let first = "---\ntitle: First record\nid: SCWE-002\nmappings:\n  scsvs-cg: [SCSVS-CODE]\n---\n\n## Description\nExact β.\n\n```solidity\ncontract A {}\n```\n";
    let second = "---\r\ntitle: Second record\r\nid: SCWE-001\r\nmappings:\r\n  scsvs-cg: [SCSVS-GOV]\r\n---\r\n\r\nExact CRLF.\r\n";
    fs::write(first_dir.join("SCWE-002.md"), first).unwrap();
    fs::write(second_dir.join("SCWE-001.md"), second).unwrap();

    let corpus = import_owasp(&root, "a".repeat(40).as_str()).unwrap();
    let first_node = corpus
        .nodes
        .iter()
        .find(|node| node.id == "scwe:001")
        .unwrap();
    let second_node = corpus
        .nodes
        .iter()
        .find(|node| node.id == "scwe:002")
        .unwrap();
    assert_eq!(first_node.definition, second);
    assert_eq!(second_node.definition, first);
    assert_eq!(first_node.summary, "Second record");
    assert_eq!(second_node.summary, "First record: Exact β.");
    assert_eq!(first_node.facets, ["category:scsvs-gov"]);
    assert_eq!(second_node.facets, ["category:scsvs-code"]);
    assert_eq!(corpus.nodes.len(), 5);
    assert_eq!(corpus.edges.len(), 4);
    assert_eq!(corpus.revision, "owasp-scwe-aaaaaaaa-source-v4");
    assert_eq!(
        corpus
            .sources
            .iter()
            .find(|source| source.id == "SCWE-001")
            .unwrap()
            .url,
        format!(
            "https://github.com/OWASP/owasp-scs/blob/{}/docs/SCWE/SCSVS-ARCH/SCWE-001.md",
            "a".repeat(40)
        )
    );
    assert!(Graph::compile(corpus).is_ok());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unpinned_or_mismatched_sources() {
    let root = temporary_root("reject");
    let directory = root.join("docs/SCWE/SCSVS-AUTH");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("SCWE-001.md"),
        "---\ntitle: Wrong ID\nid: SCWE-002\nmappings:\n  scsvs-cg: [SCSVS-AUTH]\n---\nBody\n",
    )
    .unwrap();
    assert!(import_owasp(&root, "main").is_err());
    assert!(import_owasp(&root, &"a".repeat(40)).is_err());
    fs::remove_dir_all(root).unwrap();
}
