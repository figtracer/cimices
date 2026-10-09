use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};

fn read_json(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn persistent_service_reuses_state_and_recovers_from_bad_requests() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cimices"))
        .args(["serve", "data/example.json", "gpt-4o"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let ready = read_json(&mut stdout);
    assert_eq!(ready["ready"], true);
    assert_eq!(ready["version"], 1);

    writeln!(
        stdin,
        "{}",
        json!({"version": 1, "id": "inventory", "op": "inventory"})
    )
    .unwrap();
    stdin.flush().unwrap();
    let inventory = read_json(&mut stdout);
    assert_eq!(inventory["ok"], true);
    assert_eq!(inventory["records"], 3);
    assert!(
        inventory["context"]
            .as_str()
            .unwrap()
            .contains("cimices/inventory-v1")
    );

    writeln!(
        stdin,
        "{}",
        json!({"version": 1, "id": "taxonomy", "op": "taxonomy"})
    )
    .unwrap();
    stdin.flush().unwrap();
    let taxonomy = read_json(&mut stdout);
    assert_eq!(taxonomy["ok"], true);
    assert_eq!(taxonomy["records"], 3);

    writeln!(stdin, "not json").unwrap();
    stdin.flush().unwrap();
    let malformed = read_json(&mut stdout);
    assert_eq!(malformed["ok"], false);

    let request = json!({
        "version": 1,
        "id": "unicode-β",
        "op": "bundle",
        "mode": "bm25",
        "max_tokens": 2048,
        "detail": "full",
        "query": "liquidation denial of service β",
        "facets": [],
        "compact": false
    });
    writeln!(stdin, "{request}").unwrap();
    stdin.flush().unwrap();
    let response = read_json(&mut stdout);
    assert_eq!(response["ok"], true);
    assert_eq!(response["id"], "unicode-β");
    let context = response["context"].as_str().unwrap();
    assert!(context.ends_with('\n'));
    assert_eq!(
        response["tokens"],
        tiktoken_rs::o200k_base()
            .unwrap()
            .encode_ordinary(context)
            .len()
    );

    writeln!(
        stdin,
        "{}",
        json!({
            "version": 1,
            "id": "instances",
            "op": "instances",
            "mode": "bm25",
            "max_tokens": 2048,
            "detail": "full",
            "query": "liquidation"
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let instances = read_json(&mut stdout);
    assert_eq!(instances["ok"], true);
    assert_eq!(instances["selected"].as_array().unwrap().len(), 0);

    writeln!(
        stdin,
        "{}",
        json!({
            "version": 1,
            "id": "resolve",
            "op": "resolve",
            "max_tokens": 2048,
            "detail": "full",
            "ids": ["fm:liquidation-liveness", "fm:liveness"]
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let resolved = read_json(&mut stdout);
    assert_eq!(resolved["ok"], true);
    assert_eq!(resolved["omitted_ids"], json!([]));
    assert_eq!(resolved["selected"][0]["id"], "fm:liquidation-liveness");
    assert_eq!(resolved["selected"][1]["id"], "fm:liveness");
    assert_eq!(
        resolved["tokens"],
        tiktoken_rs::o200k_base()
            .unwrap()
            .encode_ordinary(resolved["context"].as_str().unwrap())
            .len()
    );

    writeln!(
        stdin,
        "{}",
        json!({
            "version": 1,
            "id": "oversized",
            "op": "resolve",
            "max_tokens": 1,
            "detail": "full",
            "ids": ["fm:liveness", "fm:liquidation-liveness"]
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let oversized = read_json(&mut stdout);
    assert_eq!(
        oversized["omitted_ids"],
        json!(["fm:liquidation-liveness", "fm:liveness"])
    );

    writeln!(
        stdin,
        "{}",
        json!({
            "version": 1,
            "id": "unknown",
            "op": "resolve",
            "max_tokens": 2048,
            "detail": "full",
            "ids": ["missing"]
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let unknown = read_json(&mut stdout);
    assert_eq!(unknown["ok"], false);
    assert_eq!(unknown["error"], "unknown ID: missing");

    writeln!(
        stdin,
        "{}",
        json!({
            "version": 1,
            "id": "explore",
            "op": "explore",
            "max_tokens": 2048,
            "detail": "summary",
            "query": "liquidation",
            "max_direct_records": 1,
            "max_depth": 1
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let explored = read_json(&mut stdout);
    assert_eq!(explored["ok"], true);
    assert_eq!(
        explored["selected"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|hit| hit["relation"] == "match")
            .count(),
        1
    );
    let one_shot = Command::new(env!("CARGO_BIN_EXE_cimices"))
        .args([
            "explore",
            "data/example.json",
            "gpt-4o",
            "2048",
            "summary",
            "1",
            "1",
            "liquidation",
        ])
        .output()
        .unwrap();
    assert!(one_shot.status.success());
    assert_eq!(
        explored["context"].as_str().unwrap().as_bytes(),
        one_shot.stdout
    );

    writeln!(
        stdin,
        "{}",
        json!({
            "version": 1,
            "id": "tree",
            "op": "descendants",
            "root_id": "fm:liveness",
            "max_depth": 1
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let tree = read_json(&mut stdout);
    assert_eq!(tree["ok"], true);
    assert!(
        tree["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["depth"].as_u64().unwrap() <= 1)
    );

    writeln!(
        stdin,
        "{}",
        json!({"version": 1, "id": "missing", "op": "show", "record_id": "missing"})
    )
    .unwrap();
    stdin.flush().unwrap();
    let missing = read_json(&mut stdout);
    assert_eq!(missing["ok"], false);
    assert_eq!(missing["id"], "missing");

    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn service_bundle_context_matches_one_shot_output() {
    let expected = Command::new(env!("CARGO_BIN_EXE_cimices"))
        .args([
            "bundle",
            "data/example.json",
            "bm25",
            "gpt-4o",
            "2048",
            "summary",
            "liquidation denial of service",
        ])
        .output()
        .unwrap();
    assert!(expected.status.success());

    let mut child = Command::new(env!("CARGO_BIN_EXE_cimices"))
        .args(["serve", "data/example.json", "gpt-4o"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    read_json(&mut stdout);
    writeln!(
        stdin,
        "{}",
        json!({
            "version": 1,
            "id": "same",
            "op": "bundle",
            "mode": "bm25",
            "max_tokens": 2048,
            "detail": "summary",
            "query": "liquidation denial of service"
        })
    )
    .unwrap();
    stdin.flush().unwrap();
    let response = read_json(&mut stdout);
    assert_eq!(
        response["context"].as_str().unwrap().as_bytes(),
        expected.stdout
    );

    drop(stdin);
    assert!(child.wait().unwrap().success());
}
