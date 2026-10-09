use cimices::{
    BundleFormat, BundleOptions, Detail, Graph, Relation, RetrievalMode, TokenCounter,
    import_bastet,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn temporary_file(name: &str, contents: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("cimices-bastet-{}-{name}.csv", std::process::id()));
    fs::write(&path, contents).unwrap();
    path
}

fn digest(contents: &str) -> String {
    format!("{:x}", Sha256::digest(contents.as_bytes()))
}

#[test]
fn imports_labeled_findings_and_only_unambiguous_specializations() {
    let contents = concat!(
        "\u{feff}Property,repo_path,severity,tag,subtag,detail,description\n",
        "2,repos/beta,High,\"DoS, Pause\",\"Bad Condition, Out of Gas\",reports/beta/h_1.md,\"Exact first line.\nSecond line.\"\n",
        "1,repos/alpha,Medium,DoS,Out of Gas,reports/alpha/m_1.md,Exact β\n",
        "3,repos/gamma,Medium,,,reports/gamma/m_1.md,Unlabeled\n",
    );
    let path = temporary_file("exact", contents);
    let corpus = import_bastet(&path, &digest(contents), "https://example.com/bastet.csv").unwrap();

    assert_eq!(
        corpus.revision.len(),
        "bastet-".len() + 12 + "-source-v1".len()
    );
    assert_eq!(corpus.sources[0].license, "CC-BY-NC-4.0");
    assert_eq!(corpus.nodes.len(), 6);
    assert_eq!(
        corpus
            .nodes
            .iter()
            .find(|node| node.id == "bastet:finding:2")
            .unwrap()
            .definition,
        "Exact first line.\nSecond line."
    );
    assert!(
        corpus
            .nodes
            .iter()
            .all(|node| node.id != "bastet:finding:3")
    );
    assert!(corpus.edges.iter().any(|edge| {
        edge.from == "bastet:subtag:out-of-gas"
            && edge.relation == Relation::Specializes
            && edge.to == "bastet:tag:dos"
    }));
    assert!(!corpus.edges.iter().any(|edge| {
        edge.from == "bastet:subtag:bad-condition" && edge.relation == Relation::Specializes
    }));
    assert_eq!(
        corpus
            .edges
            .iter()
            .filter(|edge| edge.from == "bastet:finding:2")
            .count(),
        2
    );
    let graph = Graph::compile(corpus).unwrap();
    let counter = TokenCounter::for_model("gpt-4o").unwrap();
    let taxonomy = serde_json::from_str::<Value>(&graph.taxonomy(&counter).jsonl).unwrap();
    let facets = taxonomy["facet_table"].as_array().unwrap();
    let dos = taxonomy["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record[0] == "bastet:tag:dos")
        .unwrap();
    assert!(
        dos[3]
            .as_array()
            .unwrap()
            .iter()
            .any(|slot| facets[slot.as_u64().unwrap() as usize] == "tag:dos")
    );
    let instances = graph.instances_with_options(
        "Exact",
        &["tag:dos"],
        &counter,
        BundleOptions {
            mode: RetrievalMode::Bm25,
            detail: Detail::Full,
            format: BundleFormat::Json,
            max_tokens: usize::MAX,
        },
    );
    assert_eq!(instances.hits.len(), 2);

    fs::remove_file(path).unwrap();
}

#[test]
fn rejects_digest_mismatch_duplicate_properties_and_id_collisions() {
    let ordinary = "Property,repo_path,severity,tag,subtag,detail,description\n1,repos/a,High,DoS,Out of Gas,reports/a/h.md,Exact\n";
    let path = temporary_file("digest", ordinary);
    assert!(import_bastet(&path, &"0".repeat(64), "https://example.com/bastet.csv").is_err());
    fs::remove_file(path).unwrap();

    let duplicate = concat!(
        "Property,repo_path,severity,tag,subtag,detail,description\n",
        "1,repos/a,High,DoS,Out of Gas,reports/a/h.md,First\n",
        "1,repos/b,Medium,Pause,Bad Condition,reports/b/m.md,Second\n",
    );
    let path = temporary_file("duplicate", duplicate);
    assert!(import_bastet(&path, &digest(duplicate), "https://example.com/bastet.csv").is_err());
    fs::remove_file(path).unwrap();

    let collision = concat!(
        "Property,repo_path,severity,tag,subtag,detail,description\n",
        "1,repos/a,High,\"A+B, A B\",Example,reports/a/h.md,Exact\n",
    );
    let path = temporary_file("collision", collision);
    assert!(import_bastet(&path, &digest(collision), "https://example.com/bastet.csv").is_err());
    fs::remove_file(path).unwrap();
}
