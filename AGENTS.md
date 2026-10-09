# Agent instructions

Cimices organizes and retrieves smart contract security knowledge. Keep taxonomy
definitions, source evidence, retrieval policy, and assessment state separate.

Run `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
and `cargo test --locked --all-targets` before submitting code changes. Run corpus
validation and the evaluation command in the README when changing data or retrieval.

Preserve stable IDs and typed edge semantics. Only specialization must be acyclic.
Require citations for source-checked records. Never invent findings, source claims,
human review, or audit results. Read data/ATTRIBUTION.md before editing the corpus.

Keep evaluation topic groups disjoint across dev/test. Do not tune on test cases or
claim agent-detection improvements from authored lexical diagnostics. Keep experimental
runs outside the repository; summarize material results succinctly in the README and
retain local per-case evidence. State limitations. A visited taxonomy node is not
evidence of assessment coverage. Token budgets count the actual returned text.

Use conventional commit titles. Keep PR descriptions concise and disclose material
AI assistance. Do not add protocol scanning or exploit execution to the knowledge
retrieval layer. See CONTRIBUTING.md for contribution and license boundaries.
