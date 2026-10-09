# bugraph

[![CI](https://github.com/figtracer/bugraph/actions/workflows/ci.yml/badge.svg)](https://github.com/figtracer/bugraph/actions/workflows/ci.yml)

Route an UltraFuzz threat model to the most relevant OWASP bug classes in about
8.2 ms, locally and with zero model tokens.

Bugraph compiles the OWASP Smart Contract Security Project into a Rust-searchable
DAG, ranks its failure modes from threats and invariants, and returns a fixed-size
route. Agents receive the selected complete descriptions and code examples instead
of reading and comparing the whole OWASP catalog.

## Why use it

- Select exactly the number of bug classes a campaign can afford.
- Keep ranking, graph traversal, token counting, and serialization off the model.
- Retrieve complete pinned records with stable IDs and citations in one call.
- Measure coverage from the categories, failure modes, and findings explored.

## Results

The pinned OWASP snapshot contains 156 complete SCWE records under 11 SCSVS
categories, represented by 168 nodes and 167 edges.

| Operation | Result |
| --- | ---: |
| Full UltraFuzz OWASP planner catalog | 143,407 GPT-5.6 tokens |
| UltraFuzz capability registry used before routing | 272 GPT-5.6 tokens |
| Bugraph route selection | 0 model tokens |
| 5 × 1,000 one-shot K=16 routes | 8.17 ms median each |
| Route + K=16 UltraFuzz goal plan | 0 model tokens; 8.92 ms median |

The route benchmark includes process startup, corpus parsing, BM25 ranking,
weighted fusion, hashing, and JSON serialization.

Beyond OWASP, [vault standards](data/vaults.json) adds six curated failure modes
and two properties from ERC-4626 and ERC-7540, with applicability notes and pinned
sources. Search it with `bugraph bundle data/vaults.json bm25 gpt-4o 4096 full "vault previews"`.

[Protocol audit knowledge](docs/protocols.md) connects twenty-six findings from
Code4rena, Cantina, and Blackthorn to twenty-six reusable failure modes. Morpho,
Bitcorn, Silo, InfiniFi, and Telcoin reports add dust recovery, terminal-loss entry,
vault valuation, paused repayment, interest-rate state, epoch accounting, and
validator-registry cases.

The optional source-labeled [Bastet dataset](https://drive.google.com/file/d/19YBeCmPwx3aLZ9PZVGjjRDSYifBYpbLe/view)
imports 104 classes, 572 audit findings, and 846 edges.

## Use

```sh
git clone https://github.com/figtracer/bugraph.git
cd bugraph
cargo install --path . --locked

bugraph route-ultrafuzz-bundle data/owasp.json threat-model.json gpt-4o 8192 16 full --compact
bugraph route-ultrafuzz-plan data/owasp.json threat-model.json vulnerability-db/catalog.json 16
bugraph resolve data/owasp.json gpt-4o 8192 full scwe:037 scwe:141 --compact
bugraph explore data/owasp.json gpt-4o 4096 full 8 2 "liquidation denial of service" --compact
bugraph instances data/protocols.json bm25 gpt-4o 4096 full "withdrawal" --compact
```

## Use with forge properties

Generate a Markdown checklist from the target Solidity declarations and NatSpec,
then pass it to Foundry.

```sh
bugraph forge-context data/owasp.json --extra data/vaults.json 4096 12 src/Vault.sol --out forge-context.md
forge properties --context forge-context.md
```

The command counts the generated Markdown with the `gpt-4o` tokenizer. Without
`--include-findings`, it retains SCWE records and standards data such as
`data/vaults.json`, not audit-derived protocol or Bastet records. To include audit
records, supply their corpus and add `--include-findings`.

See [retrieval](docs/retrieval.md), [encoding](docs/packing.md),
[evaluation](docs/evaluation.md), and [contributing](CONTRIBUTING.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

Code is MIT. Bundled data is CC-BY-SA-4.0. External Bastet inputs use
[CC-BY-NC-4.0](https://arxiv.org/html/2606.03387v1#S5).
