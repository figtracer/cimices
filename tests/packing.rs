use cimices::{
    BundleFormat, BundleOptions, Corpus, Detail, Graph, RetrievalMode, TokenCounter, expand_bundle,
};
use serde_json::{Value, json};
use std::process::Command;

fn corpus() -> Value {
    json!({"revision":"packing-v1", "sources":[
        {"id":"s","title":"Synthetic reference", "url":"https://example.invalid/pinned/é/reference.rs", "revision":"1", "license":"MIT"},
        {"id":"t","title":"Second reference", "url":"https://example.invalid/pinned/é/second.rs", "revision":"1", "license":"MIT"}
    ], "nodes":(0..5).map(|i| json!({
        "id":format!("n:{i}"),"kind":"failure_mode","summary":format!("record {i}"),
        "definition":format!("Exact condition {i}; do not delete negation. é 🦀 <|endoftext|>"),
        "review":"imported","sources":["t","s"],"facets":[format!("group:reference-packing-{}", i % 2)],
        "code":[{"language":"rust","source":"s","start_line":42,
            "text":"fn label() -> &'static str {\n    \"quote: \\\"; slash: \\\\; 🦀\"\n}\n"}]
    })).collect::<Vec<_>>(), "edges":[{"from":"n:1","relation":"specializes","to":"n:0"}]})
}

#[test]
fn compact_round_trips_complete_records_and_code_for_both_encodings() {
    let graph = Graph::compile(serde_json::from_value(corpus()).unwrap()).unwrap();
    for model in ["gpt-4", "gpt-4o"] {
        let counter = TokenCounter::for_model(model).unwrap();
        for detail in [Detail::Summary, Detail::Full] {
            let original = graph.bundle(
                "",
                &[],
                RetrievalMode::IdOrder,
                detail,
                &counter,
                usize::MAX,
            );
            let compact = graph.bundle_with_options(
                "",
                &[],
                &counter,
                BundleOptions {
                    mode: RetrievalMode::IdOrder,
                    detail,
                    format: BundleFormat::Compact,
                    max_tokens: usize::MAX,
                },
            );
            assert_eq!(
                expand_bundle(&compact.jsonl).unwrap(),
                serde_json::from_str::<Value>(&original.jsonl).unwrap()
            );
            assert!(compact.tokens < original.tokens);
            for budget in [0, 1, 128, 512, compact.tokens - 1, compact.tokens] {
                let result = graph.bundle_with_options(
                    "",
                    &[],
                    &counter,
                    BundleOptions {
                        mode: RetrievalMode::IdOrder,
                        detail,
                        format: BundleFormat::Compact,
                        max_tokens: budget,
                    },
                );
                assert_eq!(result.tokens, counter.count(&result.jsonl));
                assert!(result.tokens <= budget);
                assert_eq!(result.hits.len() + result.omitted, 5);
                if !result.jsonl.is_empty() {
                    let expanded = expand_bundle(&result.jsonl).unwrap();
                    assert_eq!(expanded["omitted"], result.omitted);
                    assert_eq!(
                        expanded["records"].as_array().unwrap().len(),
                        result.hits.len()
                    );
                    for record in expanded["records"].as_array().unwrap() {
                        let node = graph.node(record["id"].as_str().unwrap()).unwrap();
                        if matches!(detail, Detail::Full) {
                            assert_eq!(record["code"][0]["text"], node.code[0].text);
                            assert_eq!(record["code"][0]["start_line"], 42);
                            let source = record["code"][0]["source"].as_u64().unwrap() as usize;
                            assert_eq!(expanded["sources"][source], graph.corpus().sources[0].url);
                        } else {
                            assert!(record.get("code").is_none());
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn decoder_rejects_ambiguous_rows_and_unknown_versions() {
    let graph = Graph::compile(serde_json::from_value(corpus()).unwrap()).unwrap();
    let counter = TokenCounter::for_model("gpt-4o").unwrap();
    let compact = graph.bundle_with_options(
        "",
        &[],
        &counter,
        BundleOptions {
            mode: RetrievalMode::IdOrder,
            detail: Detail::Full,
            format: BundleFormat::Compact,
            max_tokens: usize::MAX,
        },
    );
    let value = serde_json::from_str::<Value>(&compact.jsonl).unwrap();
    assert_eq!(value["encoding"], "cimices/compact-v1");
    let mut bad = value.clone();
    bad["encoding"] = json!("future-version");
    assert!(expand_bundle(&bad.to_string()).is_err());
    for (fields, rows) in [
        (json!(["id", "id"]), json!([["x", "y"]])),
        (json!(["id"]), json!([[]])),
    ] {
        let mut bad = value.clone();
        bad["record_fields"] = fields;
        bad["records"] = rows;
        assert!(expand_bundle(&bad.to_string()).is_err());
    }
    for field in ["source_base", "record_defaults", "record_fields"] {
        let mut bad = value.clone();
        bad[field] = json!(false);
        assert!(expand_bundle(&bad.to_string()).is_err());
    }
}

#[test]
fn facet_dictionaries_round_trip_and_reject_out_of_range_indexes() {
    let mut value = corpus();
    for i in 5..24 {
        let mut node = value["nodes"][i % 5].clone();
        node["id"] = json!(format!("n:{i}"));
        value["nodes"].as_array_mut().unwrap().push(node);
    }
    let graph = Graph::compile(serde_json::from_value(value).unwrap()).unwrap();
    let counter = TokenCounter::for_model("gpt-4o").unwrap();
    let plain = graph.bundle(
        "",
        &[],
        RetrievalMode::IdOrder,
        Detail::Full,
        &counter,
        usize::MAX,
    );
    let compact = graph.bundle_with_options(
        "",
        &[],
        &counter,
        BundleOptions {
            mode: RetrievalMode::IdOrder,
            detail: Detail::Full,
            format: BundleFormat::Compact,
            max_tokens: usize::MAX,
        },
    );
    assert_eq!(
        expand_bundle(&compact.jsonl).unwrap(),
        serde_json::from_str::<Value>(&plain.jsonl).unwrap()
    );
    let mut value = serde_json::from_str::<Value>(&compact.jsonl).unwrap();
    assert!(value["facet_table"].is_array());
    if let Some(column) = value["record_fields"]
        .as_array()
        .and_then(|fields| fields.iter().position(|field| field == "facets"))
    {
        value["records"][0][column] = json!([999]);
    } else {
        value["records"][0]["facets"] = json!([999]);
    }
    assert!(expand_bundle(&value.to_string()).is_err());
}

#[test]
fn code_provenance_is_required_and_cli_preserves_pinned_markdown() {
    for (field, invalid) in [
        ("source", json!("unknown")),
        ("start_line", json!(0)),
        ("language", json!("")),
        ("text", json!("")),
    ] {
        let mut value = corpus();
        value["nodes"][0]["code"][0][field] = invalid;
        assert!(Graph::compile(serde_json::from_value(value).unwrap()).is_err());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_cimices"))
        .args([
            "bundle",
            "data/owasp.json",
            "bm25",
            "gpt-4o",
            "8192",
            "full",
            "Critical Address Parameters Not Validated for Zero Address",
            "--compact",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = std::str::from_utf8(&output.stdout).unwrap();
    assert!(TokenCounter::for_model("gpt-4o").unwrap().count(text) <= 8192);
    let value = expand_bundle(text).unwrap();
    let record = value["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == "scwe:143")
        .unwrap();
    let source = serde_json::from_str::<Corpus>(include_str!("../data/owasp.json")).unwrap();
    let node = source
        .nodes
        .iter()
        .find(|node| node.id == "scwe:143")
        .unwrap();
    assert_eq!(record["definition"], node.definition);
    assert!(
        node.definition
            .contains("### Fixed\n```solidity\nconstructor(address _owner")
    );
}
