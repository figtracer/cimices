# Benchmarking

```sh
cargo run --locked --release --example bench -- 10000 1000
```

The synthetic benchmark compares flat filtering with indexed facet intersection.
Both implementations materialize the same matching IDs. It reports index compilation
and mean warm query time; it excludes parsing, process startup, token packing, and
network or model calls. It has no graph edges and does not measure DAG traversal.

Use matched inputs, repeated runs, and representative corpus sizes. Separate cold
loading from repeated queries, and include tokenizer initialization when measuring
CLI latency. Keep raw runs outside the repository. This benchmark does not establish
routing performance or vulnerability-detection quality.

For a harness replay, start `cimices serve` as a Node child, wait for readiness, and
measure from writing each request through parsing its response. Report process-to-ready
and first-response latency separately, then warm p50/p95 and complete session time.
Compare the extracted `context` bytes with the equivalent one-shot command and recount
that final string independently. Record source hashes, query order, detail, token cap,
direct-record limit, depth, binary profile, runtime versions, filesystem-cache state,
and combined parent/child memory. A cached map lookup is a useful lower bound, not an
equivalent search-and-packing baseline.
