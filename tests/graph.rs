use cimices::{Corpus, Graph, Ledger};
use serde_json::{Value, json};
use std::process::Command;

fn fixture() -> Value {
    json!({"revision":"v1", "nodes":[
        {"id":"a","kind":"failure_mode","summary":"root","facets":["domain:lending"]},
        {"id":"b","kind":"failure_mode","summary":"left","facets":["domain:lending","impact:availability"]},
        {"id":"c","kind":"failure_mode","summary":"right"},
        {"id":"d","kind":"failure_mode","summary":"shared é","facets":["domain:lending","impact:availability"]}
    ], "edges":[
        {"from":"b","relation":"specializes","to":"a"},
        {"from":"c","relation":"specializes","to":"a"},
        {"from":"d","relation":"specializes","to":"b"},
        {"from":"d","relation":"specializes","to":"c"}
    ]})
}

fn compile(value: Value) -> Result<Graph, String> {
    Graph::compile(serde_json::from_value::<Corpus>(value).unwrap())
}

#[test]
fn shared_descendants_are_unique_and_filters_intersect() {
    let graph = compile(fixture()).unwrap();
    assert_eq!(
        graph
            .descendants("a")
            .unwrap()
            .iter()
            .map(|n| n.id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b", "c", "d"]
    );
    assert_eq!(
        graph.matching(&["domain:lending", "impact:availability"]),
        [1, 3]
    );
    assert!(graph.matching(&["unknown:facet"]).is_empty());
    assert!(graph.descendants("missing").is_err());
}

#[test]
fn descendant_browsing_reports_shortest_bounded_depths() {
    let graph = compile(fixture()).unwrap();
    let root = graph.descendants_to_depth("a", 0).unwrap();
    assert_eq!(
        root.iter()
            .map(|hit| (hit.id, hit.depth))
            .collect::<Vec<_>>(),
        [("a", 0)]
    );
    let one = graph.descendants_to_depth("a", 1).unwrap();
    assert!(one.iter().all(|hit| hit.depth <= 1));
    let all = graph.descendants_to_depth("a", usize::MAX).unwrap();
    let mut ids = all.iter().map(|hit| hit.id).collect::<Vec<_>>();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count);
}

#[test]
fn validates_dag_and_typed_relations() {
    let mut value = fixture();
    value["edges"]
        .as_array_mut()
        .unwrap()
        .push(json!({"from":"a","relation":"specializes","to":"d"}));
    assert!(compile(value).err().unwrap().contains("cycle"));
    let mut value = fixture();
    value["edges"][0]["relation"] = json!("violates");
    assert!(compile(value).err().unwrap().contains("endpoint"));
    let mut value = fixture();
    value["edges"].as_array_mut().unwrap().extend([
        json!({"from":"a","relation":"related_to","to":"d"}),
        json!({"from":"d","relation":"related_to","to":"a"}),
    ]);
    assert!(compile(value).is_ok());
}

#[test]
fn rejects_duplicate_ids_edges_and_dangling_references() {
    let mut value = fixture();
    value["nodes"][1]["id"] = json!("a");
    assert!(compile(value).err().unwrap().contains("duplicate ID"));
    let mut value = fixture();
    let edge = value["edges"][0].clone();
    value["edges"].as_array_mut().unwrap().push(edge);
    assert!(compile(value).err().unwrap().contains("duplicate edge"));
    let mut value = fixture();
    value["edges"][0]["to"] = json!("missing");
    assert!(compile(value).err().unwrap().contains("unknown ID"));
}

#[test]
fn budgets_include_json_escaping_unicode_and_newlines() {
    let mut value = fixture();
    value["nodes"][0]["summary"] = json!("\"quoted\"\nUnicode: 🦀");
    let graph = compile(value).unwrap();
    let full = graph.context(&[], usize::MAX);
    for budget in 0..=full.jsonl.len() {
        let context = graph.context(&[], budget);
        assert!(context.jsonl.len() <= budget);
        assert_eq!(context.selected + context.omitted, 4);
        assert_eq!(context.jsonl.lines().count(), context.selected);
        for line in context.jsonl.lines() {
            serde_json::from_str::<Value>(line).unwrap();
        }
    }
    assert_eq!(graph.context(&[], full.jsonl.len()).jsonl, full.jsonl);
}

#[test]
fn input_order_does_not_change_context() {
    let value = fixture();
    let expected = compile(value.clone())
        .unwrap()
        .context(&[], usize::MAX)
        .jsonl;
    let mut reversed = value;
    reversed["nodes"].as_array_mut().unwrap().reverse();
    reversed["edges"].as_array_mut().unwrap().reverse();
    assert_eq!(
        compile(reversed).unwrap().context(&[], usize::MAX).jsonl,
        expected
    );
}

#[test]
fn coverage_preserves_unknowns_and_requires_evidence_and_revision() {
    let graph = compile(fixture()).unwrap();
    let mut ledger = serde_json::from_value::<Ledger>(json!({
        "revision":"v1", "scope_revision":"design-v1", "scope":["a","b","c","d"],
        "records":[{"id":"b","state":"assessed","evidence":["local review reference"]},
                   {"id":"c","state":"unresolved","evidence":["design context absent"]}]
    }))
    .unwrap();
    let coverage = graph.coverage(&ledger).unwrap();
    assert_eq!(coverage.total, 4);
    assert_eq!(coverage.unassessed, 2);
    assert_eq!(coverage.assessed, 1);
    assert_eq!(coverage.unresolved, 1);
    ledger.records[0].evidence.clear();
    assert!(graph.coverage(&ledger).is_err());
    ledger.records.clear();
    ledger.revision = "v2".into();
    assert!(graph.coverage(&ledger).is_err());
    ledger.revision = "v1".into();
    ledger.scope.push("a".into());
    assert!(graph.coverage(&ledger).is_err());
    ledger.scope = vec!["missing".into()];
    assert!(graph.coverage(&ledger).is_err());
}

#[test]
fn cli_emits_parseable_results_and_reports_errors() {
    let bin = env!("CARGO_BIN_EXE_cimices");
    let output = Command::new(bin)
        .args([
            "context",
            "data/example.json",
            "4096",
            "operation:liquidation",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let node = serde_json::from_slice::<Value>(&output.stdout).unwrap();
    assert_eq!(node["id"], "fm:liquidation-liveness");
    let output = Command::new(bin)
        .args(["coverage", "data/example.json", "data/ledger.json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report = serde_json::from_slice::<Value>(&output.stdout).unwrap();
    assert_eq!(report["unresolved"], 1);
    assert_eq!(report["unassessed"], 1);
    let output = Command::new(bin)
        .args(["show", "data/example.json", "missing"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
