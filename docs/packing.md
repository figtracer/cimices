# Lossless bundle encoding

Append `--compact` to `bundle` to reduce repeated structure while retaining every
selected field. The response remains valid JSON. It may use ordinary bundle JSON
when compression would cost more tokens. The token cap includes JSON syntax,
source dictionaries, code, the encoding marker, the inline decoding guide, and the
trailing newline. It excludes the caller's tool/message envelopes.

```sh
cimices bundle data/owasp.json bm25 gpt-4o 2048 full "contract architecture" --compact
cimices expand saved-bundle.json
```

Rust consumers can use `Graph::bundle_with_options` with `BundleFormat::Compact`,
then `expand_bundle` to recover ordinary bundle data. `Graph::bundle` and the CLI
without `--compact` retain their existing JSON format.

## Contract

Compact responses carry `encoding: "cimices/compact-v1"` and a `decode` guide.
A decoder applies the following operations:

1. If `source_base` exists, prepend it to each string in `sources`. Citation slots
   remain zero-based indexes into that array, including code's `source` index.
2. If `record_fields` exists, each record is an array whose values correspond to
   those field names in order. Convert each row to an object. Rows must have exactly
   the declared width; duplicate field names are invalid. Tabular encoding is used
   only when every record has the same fields, so missing values need no sentinel.
3. Merge `record_defaults` into each record. Local values override shared defaults.
4. If `facet_table` exists, replace each integer in record `facets` with the string
   at that zero-based table index. These indexes are separate from citation slots.
   Out-of-range indexes are invalid.
5. Remove the encoding metadata (`encoding`, `decode`, `source_base`,
   `record_fields`, `record_defaults`, `facet_table`). Other fields and array order remain intact.

Absent defaults are empty. Without an encoding marker, the input is ordinary bundle
JSON. Unknown markers and malformed compact structures fail expansion.

`expand_bundle(encoded) == original` compares parsed JSON data. Object-key order and
JSON escape spelling are not significant; every string value is exact, including
negation, identifiers, code indentation, Unicode, and trailing code newlines. Source
URLs are reconstructed exactly. Code is neither minified nor summarized. Excerpts
can be partial functions and are reference material, not executable test cases.

## Selection and cost

For each proposed record selection, the encoder compares plain JSON, shared URL
prefixes, shared identical record fields, and uniform table rows. It chooses the
smallest tested representation using the requested tokenizer, including decoding
instructions. A second pass tests a dictionary for repeated facet strings, keeping
it only if the complete response shrinks. This is not a proof of the globally shortest representation. The
packer keeps whole records and can omit records that exceed the budget; `omitted`
counts them. A smaller representation may allow more records into the same cap.

Exact comparison and repeated whole-response tokenization require extra CPU. Plain
JSON remains available when serialization latency or existing consumer compatibility
matters more than input-token savings. Neither representation changes ranking or
makes graph traversal evidence of security coverage.

## Research basis

[JTON (April 2026)](https://arxiv.org/abs/2604.05865) motivates sharing tabular schema,
while [Notation Matters (June 2026 revision)](https://arxiv.org/abs/2605.29676) shows
why format changes need separate comprehension and tool-output checks. These papers
do not validate Cimices's format. We retain conventional JSON tool interfaces and
unchanged prose/code rather than adopting content-deleting prompt compression.

[Dictionary-Encoding and In-Context Learning (2026)](https://arxiv.org/abs/2604.13066)
supports testing repeated-value dictionaries with their overhead included. Cimices
limits this additional indirection to classification metadata; prose and code stay
verbatim. [Meta-Tokens (2025)](https://arxiv.org/abs/2506.00307) studies a different
model-specific approach; its vocabulary changes are not required by this format.
