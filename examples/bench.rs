//! Reproducible synthetic comparison of flat filtering and indexed filtering.

use cimices::{Corpus, Graph, Kind, Node};
use std::{env, hint::black_box, time::Instant};

fn main() {
    let args = env::args()
        .skip(1)
        .map(|s| s.parse::<usize>().expect("positive integer required"))
        .collect::<Vec<_>>();
    assert_eq!(args.len(), 2, "usage: bench NODE_COUNT ITERATIONS");
    let (count, iterations) = (args[0], args[1]);
    assert!(count > 0 && iterations > 0);
    // One percent selectivity, with two explicit facets per node.
    let nodes = (0..count)
        .map(|i| Node {
            code: Vec::new(),
            id: format!("fm:{i:08}"),
            kind: Kind::FailureMode,
            summary: format!("Synthetic classification record {i}"),
            definition: String::new(),
            facets: vec![format!("group:{}", i % 100), format!("type:{}", i % 2)],
            exclusions: Vec::new(),
            sources: Vec::new(),
            applicability: Vec::new(),
            mappings: Vec::new(),
            review: Default::default(),
        })
        .collect();
    let start = Instant::now();
    let graph = Graph::compile(Corpus {
        revision: "synthetic-v1".into(),
        sources: Vec::new(),
        nodes,
        edges: vec![],
    })
    .unwrap();
    let build = start.elapsed();
    let query = ["group:0", "type:0"];
    let flat = || {
        graph
            .corpus()
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| query.iter().all(|f| node.facets.iter().any(|v| v == f)))
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    };
    assert_eq!(flat(), graph.matching(&query));
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(flat());
    }
    let flat_time = start.elapsed();
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(graph.matching(black_box(&query)));
    }
    let indexed_time = start.elapsed();
    println!(
        "nodes={count} iterations={iterations} matches={} build_ms={:.3} flat_us={:.3} indexed_us={:.3}",
        graph.matching(&query).len(),
        build.as_secs_f64() * 1e3,
        flat_time.as_secs_f64() * 1e6 / iterations as f64,
        indexed_time.as_secs_f64() * 1e6 / iterations as f64
    );
}
