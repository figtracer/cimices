# Retrieval

The library compiles JSON into an immutable graph with integer node references,
facet and lexical posting lists, and cached JSONL summaries. Load once and reuse
`Graph` in a long-lived consumer. The `serve` command keeps one graph and tokenizer
alive behind a versioned JSON-lines protocol; ordinary CLI commands reload them.

Start `cimices serve CORPUS MODEL` and wait for its readiness line. Each subsequent
stdin line is one request and produces exactly one stdout line. `op: "inventory"`
returns every node and edge as a self-describing routing table; `op: "taxonomy"`
omits concrete findings and their instance edges. Bundle requests use
the ordinary retrieval fields plus `version`, a correlation `id`, and `op: "bundle"`.
The response carries the exact token-counted bundle in `context`; extract that string
unchanged before forwarding it to a model. `op: "instances"` uses the same bundle
fields but ranks only concrete findings. `op: "show"` accepts `record_id`. Errors
are per request, so malformed input does not discard the loaded index. `op: "resolve"`
accepts `ids`, `detail`, `max_tokens`, and optional `compact`; it rejects unknown or
duplicate IDs, packs in stable ID order, and returns `omitted_ids` for selected records
that cannot fit. EOF stops the process.

`op: "explore"` adds `max_direct_records` and `max_depth`. It packs BM25 matches
first, expands only from matches that fit, and uses remaining capacity for their
specialization ancestors. Depth zero disables expansion. Shared ancestors keep their
shortest distance and direct matches keep their own score and role. The response's
`selected` metadata reports each record's role and depth; that transport metadata is
not part of `context`. `op: "descendants"` accepts `root_id` and `max_depth` for
bounded category-to-mechanism browsing.

## Modes

`inventory CORPUS MODEL` is the exhaustive routing layer. It includes stable IDs,
source-derived semantic summaries, interned facets, and all typed edges, with the exact
model-token count available through the library or service response. It omits full
definitions and provenance metadata; retrieve those by ID with `show` or a full bundle.
The inventory does not rank or remove classes.

`taxonomy CORPUS MODEL` is the smaller exhaustive routing layer for corpora that also
contain concrete findings. It retains every failure mode, property, and relationship
between those classes. `instances CORPUS MODE MODEL MAX_TOKENS DETAIL QUERY [facets
...]` then searches only findings, so a caller can select a Tag or Subtag facet before
spending tokens on source examples. Imported class records expose the canonical
`tag:...` or `subtag:...` routing facet used by their finding instances; `level:...`
describes the class layer and is not a branch selector.

`resolve CORPUS MODEL MAX_TOKENS DETAIL ID [ID ...]` is the deterministic handoff
from routing to source detail. It fetches the selected set in one bundle without a
second relevance pass. Service responses expose both the accepted records and exact
omitted IDs; the one-shot command writes the same trace to stderr while keeping only
model context on stdout.

`id_order` returns failure modes in stable ID order, the original flat baseline.
`bm25` ranks positive lexical matches. `bm25_ancestors` interleaves each match with
its unique broader failure modes, nearest ancestors first. Ancestors retain the
originating score; they are structural context, not independent semantic matches.

BM25 maintains separate failure-mode and finding indexes over summary, definition,
applicability, and facets. Exclusions and source
titles are not positive relevance evidence. Terms are Unicode alphanumeric runs,
lowercased; query terms are deduplicated. There is no stemming, learned synonym
expansion, embedding service, relevance threshold, or semantic negation handling.
Ties resolve by stable ID. Shared ancestors appear once.

The direct-first `explore` policy leaves `bm25_ancestors` available for compatibility.
It considers every lexical match before structural context, so broad categories cannot
consume space reserved for direct evidence. Facets remain explicit: traversal may cross
a filtered intermediate node and consumes a hop, but only matching ancestors are
returned.

Fixed parameters `k1=1.2`, `b=0.75`, and positive log IDF follow conventional
[Lucene BM25 defaults](https://lucene.apache.org/core/9_12_1/core/org/apache/lucene/search/similarities/BM25Similarity.html).
They were not fitted to the suite. Unfiltered lexical queries score only matching
posting lists. Each posting's BM25 contribution is computed once when the immutable
index is built; queries add those contributions in sorted term order. Rebuilding the
graph recomputes weights for the new corpus. Sorting costs depend on matching document
count. Plain ranked lookup needs no ancestor-deduplication set.

## Token budgets

`TokenCounter::for_model` uses the locked `tiktoken-rs` model-to-encoding mapping.
Unknown models fail. Tests exercise `gpt-4` (`cl100k_base`) and `gpt-4o` (`o200k_base`).
Model-name support is exactly that of the locked dependency, not all providers.

Content is ordinary text, including strings resembling special token delimiters.
Packing considers whole JSONL records in ranking order, skips records that do not
fit, and recounts the complete candidate text. Independently counted BPE lengths
are not assumed additive. Counts cover stdout, including source URLs and JSON syntax.

The caller must separately reserve messages, instructions, tools, API envelopes, and
completion tokens. See official [token counting guidance](https://developers.openai.com/cookbook/examples/how_to_count_tokens_with_tiktoken).
The byte-budgeted `context` command retains deterministic ID ordering.

## Compact bundles

`bundle CORPUS MODE MODEL MAX_TOKENS DETAIL QUERY [facets ...]` uses the same
ranking as `search`. `DETAIL` is `summary` or `full`. It returns one compact JSON
object containing `revision`, `records`, a `sources` array of citation URLs, and
`omitted` (ranked candidates that did not fit). Each record’s integer `sources`
values are zero-based indexes into that response’s citation table, not stable IDs.
Record IDs remain stable. The complete source registry is available through `show`.

The corpus revision and identical citation URLs appear once. Empty optional fields
are omitted. Full records add complete definitions, applicability, exclusions, and
external mappings, and attached code excerpts. Code text is kept verbatim; excerpts
carry their language, one-based source start line, and citation-table source index.
Relationships appear under `edges` only when both endpoints are
selected; omission does not establish that no other relationships exist. Graph
expansion remains opt-in through `bm25_ancestors`. A DAG and semantic similarity
search are separate concepts; this engine currently uses lexical ranking.

Packing recounts the entire serialized object, including citations, edges, omission
count, JSON syntax, and trailing newline. Definitions are never truncated. Records
that do not fit are skipped. If no record matches or fits, stdout is empty. Successful
bundle calls produce no stderr diagnostics, so ranking metadata cannot silently add
tokens to the returned context. The library also exposes exact token counts. A single
record can cost more than legacy JSONL because of the envelope; savings depend on
record count, repetition, and the selected detail level.

Use a full bundle when the question needs descriptions immediately; a summary bundle
followed by `show` is useful when only a few records will need expansion. Fetching the
entire corpus or expanding all ancestors is not inherently token-efficient.

Append `--compact` to opt into lossless structural compression. It compares ordinary
JSON with factored and tabular JSON, counts their complete decoding guides, and
keeps the smallest candidate. See [encoding and code preservation](packing.md).
The existing `Graph::bundle` keeps ordinary JSON; `bundle_with_options` accepts an
explicit `BundleFormat`.

## Performance boundaries

Packing is greedy, not an optimal relevance-per-token solver. Recounting growing
text trades CPU for exact budgeting and can be expensive for many candidates.
Tokenizer initialization is cached per process. No disk index, memory mapping,
embedding database, or parallel retrieval is required. Measure representative
workloads before adding these. See [benchmark instructions](../BENCHMARKS.md).
