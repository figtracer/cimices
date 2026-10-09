//! Lexical retrieval and exact model-token budgets for serialized context.

use crate::{BundleFormat, Graph, Kind, Node, ReviewStatus, packing};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tiktoken_rs::{CoreBPE, bpe_for_model};

/// Conventional BM25 defaults, fixed before evaluation; not fitted to the suite.
const K1: f64 = 1.2;
const B: f64 = 0.75;

pub(crate) fn terms(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .collect()
}

pub(crate) struct SearchIndex {
    // Each posting stores its immutable BM25 contribution, not term frequency.
    postings: HashMap<String, Vec<(usize, f64)>>,
}

impl SearchIndex {
    pub(crate) fn build(nodes: &[Node], kind: Kind) -> Self {
        let mut postings = HashMap::<String, Vec<(usize, f64)>>::new();
        let mut lengths = vec![0; nodes.len()];
        let mut documents = 0;
        for (index, node) in nodes.iter().enumerate() {
            if node.kind == kind {
                documents += 1;
                let mut frequencies = HashMap::<String, usize>::new();
                // Exclusions and source titles are not positive relevance evidence.
                for field in [&node.summary, &node.definition]
                    .into_iter()
                    .chain(&node.facets)
                    .chain(&node.applicability)
                {
                    for term in terms(field) {
                        lengths[index] += 1;
                        *frequencies.entry(term).or_default() += 1;
                    }
                }
                for (term, frequency) in frequencies {
                    postings
                        .entry(term)
                        .or_default()
                        .push((index, frequency as f64));
                }
            }
        }
        let average = (lengths.iter().sum::<usize>() as f64 / documents.max(1) as f64).max(1.0);
        for entries in postings.values_mut() {
            let idf = (1.0
                + (documents as f64 - entries.len() as f64 + 0.5) / (entries.len() as f64 + 0.5))
                .ln();
            for (index, contribution) in entries {
                let frequency = *contribution;
                let denominator = frequency + K1 * (1.0 - B + B * lengths[*index] as f64 / average);
                *contribution = idf * frequency * (K1 + 1.0) / denominator;
            }
        }
        Self { postings }
    }

    fn scores(&self, query: &str) -> HashMap<usize, f64> {
        let mut scores = HashMap::<usize, f64>::new();
        let mut query_terms = terms(query);
        query_terms.sort_unstable();
        query_terms.dedup();
        for term in query_terms {
            if let Some(postings) = self.postings.get(&term) {
                for &(index, contribution) in postings {
                    *scores.entry(index).or_default() += contribution;
                }
            }
        }
        scores
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalMode {
    IdOrder,
    Bm25,
    Bm25Ancestors,
}

/// Choose the information returned for each selected record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    Summary,
    Full,
}

/// Retrieval and representation policy for a token-capped bundle.
#[derive(Clone, Copy)]
pub struct BundleOptions {
    pub mode: RetrievalMode,
    pub detail: Detail,
    pub format: BundleFormat,
    pub max_tokens: usize,
}

#[derive(Serialize)]
struct BundleCode<'a> {
    language: &'a str,
    source: usize,
    start_line: usize,
    text: &'a str,
}

#[derive(Serialize)]
struct BundleRecord<'a> {
    id: &'a str,
    kind: Kind,
    summary: &'a str,
    review: ReviewStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<usize>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    facets: &'a [String],
    #[serde(skip_serializing_if = "str::is_empty")]
    definition: &'a str,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    applicability: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    exclusions: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    mappings: &'a [String],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    code: Vec<BundleCode<'a>>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Hit<'a> {
    pub id: &'a str,
    pub score: f64,
    pub relation: &'static str,
}

/// Direct-first context plus the structural distance of each returned hit.
pub struct ExplorationContext<'a> {
    pub context: RankedContext<'a>,
    pub depths: Vec<usize>,
}

/// Counts ordinary text, including strings resembling special token delimiters.
/// Counts exclude API message envelopes, tools, instructions, and completion tokens.
pub struct TokenCounter {
    model: String,
    bpe: &'static CoreBPE,
}

impl TokenCounter {
    pub fn for_model(model: &str) -> Result<Self, String> {
        let bpe = bpe_for_model(model).map_err(|error| error.to_string())?;
        Ok(Self {
            model: model.into(),
            bpe,
        })
    }

    pub fn count(&self, text: &str) -> usize {
        self.bpe.encode_ordinary(text).len()
    }

    pub fn model(&self) -> &str {
        &self.model
    }
}

pub struct RankedContext<'a> {
    pub jsonl: String,
    pub hits: Vec<Hit<'a>>,
    pub tokens: usize,
    pub omitted: usize,
}

/// Complete lightweight routing view. Record IDs retrieve full source-backed detail.
pub struct InventoryContext {
    pub jsonl: String,
    pub tokens: usize,
    pub records: usize,
}

impl Graph {
    /// Return every node and edge in a compact, self-describing routing inventory.
    pub fn inventory(&self, counter: &TokenCounter) -> InventoryContext {
        self.inventory_where(counter, |_| true)
    }

    /// Return every failure mode, property, and edge between them without findings.
    pub fn taxonomy(&self, counter: &TokenCounter) -> InventoryContext {
        self.inventory_where(counter, |node| node.kind != Kind::Finding)
    }

    fn inventory_where(
        &self,
        counter: &TokenCounter,
        include: impl Fn(&Node) -> bool,
    ) -> InventoryContext {
        let included = self
            .corpus
            .nodes
            .iter()
            .filter(|node| include(node))
            .collect::<Vec<_>>();
        let ids = included
            .iter()
            .map(|node| node.id.as_str())
            .collect::<HashSet<_>>();
        let mut facet_table = included
            .iter()
            .flat_map(|node| &node.facets)
            .collect::<Vec<_>>();
        facet_table.sort_unstable();
        facet_table.dedup();
        let facet_slots = facet_table
            .iter()
            .enumerate()
            .map(|(slot, facet)| (facet.as_str(), slot))
            .collect::<HashMap<_, _>>();
        let records = self
            .corpus
            .nodes
            .iter()
            .filter(|node| ids.contains(node.id.as_str()))
            .map(|node| {
                serde_json::json!([
                    node.id,
                    node.kind,
                    node.summary,
                    node.facets
                        .iter()
                        .map(|facet| facet_slots[facet.as_str()])
                        .collect::<Vec<_>>()
                ])
            })
            .collect::<Vec<_>>();
        let edges = self
            .corpus
            .edges
            .iter()
            .filter(|edge| ids.contains(edge.from.as_str()) && ids.contains(edge.to.as_str()))
            .map(|edge| serde_json::json!([edge.from, edge.relation, edge.to]))
            .collect::<Vec<_>>();
        let value = serde_json::json!({
            "schema": "bugraph/inventory-v1",
            "revision": self.corpus.revision,
            "record_fields": ["id", "kind", "summary", "facets"],
            "facet_table": facet_table,
            "records": records,
            "edge_fields": ["from", "relation", "to"],
            "edges": edges,
        });
        let jsonl = format!("{value}\n");
        InventoryContext {
            tokens: counter.count(&jsonl),
            records: included.len(),
            jsonl,
        }
    }

    /// Pack a single JSON object with a shared citation table and corpus revision.
    /// Full detail retains whole definitions, applicability, and exclusions.
    /// An empty string means no complete record fitted or no records matched.
    pub fn bundle(
        &self,
        query: &str,
        facets: &[&str],
        mode: RetrievalMode,
        detail: Detail,
        counter: &TokenCounter,
        max_tokens: usize,
    ) -> RankedContext<'_> {
        self.bundle_with_options(
            query,
            facets,
            counter,
            BundleOptions {
                mode,
                detail,
                format: BundleFormat::Json,
                max_tokens,
            },
        )
    }

    /// Compact mode chooses the smallest supported exact representation for each
    /// candidate. It includes its decoding guide in the token budget.
    pub fn bundle_with_options(
        &self,
        query: &str,
        facets: &[&str],
        counter: &TokenCounter,
        options: BundleOptions,
    ) -> RankedContext<'_> {
        let ranked = self.rank(query, facets, options.mode);
        let total = ranked.len();
        self.pack_ranked(ranked, counter, options, total, usize::MAX)
    }

    /// Rank and pack concrete findings, with facets selecting taxonomy branches.
    pub fn instances_with_options(
        &self,
        query: &str,
        facets: &[&str],
        counter: &TokenCounter,
        options: BundleOptions,
    ) -> RankedContext<'_> {
        let ranked = self.rank_kind(query, facets, options.mode, Kind::Finding);
        let total = ranked.len();
        self.pack_ranked(ranked, counter, options, total, usize::MAX)
    }

    /// Resolve an explicit set of IDs into one stable, token-capped bundle.
    ///
    /// Unknown and duplicate IDs fail instead of silently changing the caller's
    /// selected set. Records are packed in stable ID order.
    pub fn resolve_with_options<'a>(
        &'a self,
        ids: &[&'a str],
        counter: &TokenCounter,
        options: BundleOptions,
    ) -> Result<RankedContext<'a>, String> {
        if ids.is_empty() {
            return Err("resolve requires at least one ID".into());
        }
        let mut ids = ids.to_vec();
        ids.sort_unstable();
        for pair in ids.windows(2) {
            if pair[0] == pair[1] {
                return Err(format!("duplicate ID: {}", pair[0]));
            }
        }
        self.resolve_ranked(ids, counter, options)
    }

    /// Resolve explicit IDs in caller priority order, so a token cap retains the
    /// highest-priority records first.
    pub fn resolve_ordered_with_options<'a>(
        &'a self,
        ids: &[&'a str],
        counter: &TokenCounter,
        options: BundleOptions,
    ) -> Result<RankedContext<'a>, String> {
        if ids.is_empty() {
            return Err("resolve requires at least one ID".into());
        }
        let mut seen = HashSet::with_capacity(ids.len());
        for id in ids {
            if !seen.insert(*id) {
                return Err(format!("duplicate ID: {id}"));
            }
        }
        self.resolve_ranked(ids.to_vec(), counter, options)
    }

    fn resolve_ranked<'a>(
        &'a self,
        ids: Vec<&'a str>,
        counter: &TokenCounter,
        options: BundleOptions,
    ) -> Result<RankedContext<'a>, String> {
        let ranked = ids
            .into_iter()
            .map(|id| {
                if !self.ids.contains_key(id) {
                    return Err(format!("unknown ID: {id}"));
                }
                Ok(Hit {
                    id,
                    score: 0.0,
                    relation: "selected",
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let total = ranked.len();
        Ok(self.pack_ranked(ranked, counter, options, total, usize::MAX))
    }

    /// Pack lexical matches before bounded structural context. Ancestors never
    /// displace an accepted direct match or bypass the direct-record limit.
    pub fn bundle_direct_first(
        &self,
        query: &str,
        facets: &[&str],
        counter: &TokenCounter,
        options: BundleOptions,
        max_direct_records: usize,
        max_depth: usize,
    ) -> ExplorationContext<'_> {
        let direct_mode = match options.mode {
            RetrievalMode::IdOrder => RetrievalMode::IdOrder,
            RetrievalMode::Bm25 | RetrievalMode::Bm25Ancestors => RetrievalMode::Bm25,
        };
        let direct = self.rank(query, facets, direct_mode);
        let direct_ids = direct.iter().map(|hit| hit.id).collect::<HashSet<_>>();
        let all_ancestors = self.bounded_ancestors(&direct, facets, max_depth);
        let total = direct.len() + all_ancestors.len();
        let selected_direct = self.pack_ranked(direct, counter, options, total, max_direct_records);
        if selected_direct.hits.is_empty() || all_ancestors.is_empty() {
            let depths = vec![0; selected_direct.hits.len()];
            return ExplorationContext {
                context: selected_direct,
                depths,
            };
        }
        let mut ancestors = self.bounded_ancestors(&selected_direct.hits, facets, max_depth);
        ancestors.retain(|(hit, _)| !direct_ids.contains(hit.id));
        let mut ranked = selected_direct.hits;
        let ancestor_depths = ancestors
            .iter()
            .map(|(hit, depth)| (hit.id, *depth))
            .collect::<HashMap<_, _>>();
        ranked.extend(ancestors.into_iter().map(|(hit, _)| hit));
        let context = self.pack_ranked(ranked, counter, options, total, usize::MAX);
        let depths = context
            .hits
            .iter()
            .map(|hit| ancestor_depths.get(hit.id).copied().unwrap_or(0))
            .collect();
        ExplorationContext { context, depths }
    }

    fn pack_ranked<'a>(
        &'a self,
        ranked: Vec<Hit<'a>>,
        counter: &TokenCounter,
        options: BundleOptions,
        total: usize,
        max_records: usize,
    ) -> RankedContext<'a> {
        let initial_count = ranked.len().min(max_records);
        if initial_count > 0 {
            let selected = ranked[..initial_count]
                .iter()
                .map(|hit| &self.corpus.nodes[self.ids[hit.id]])
                .collect::<Vec<_>>();
            let (jsonl, tokens) = self.serialize_selection(&selected, counter, options, total);
            if tokens <= options.max_tokens {
                return RankedContext {
                    jsonl,
                    omitted: total - initial_count,
                    hits: ranked[..initial_count].to_vec(),
                    tokens,
                };
            }
        }
        let mut selected = Vec::new();
        let mut result = RankedContext {
            jsonl: String::new(),
            hits: Vec::new(),
            tokens: 0,
            omitted: 0,
        };
        for hit in ranked {
            if result.hits.len() == max_records {
                break;
            }
            selected.push(&self.corpus.nodes[self.ids[hit.id]]);
            let (text, tokens) = self.serialize_selection(&selected, counter, options, total);
            if tokens <= options.max_tokens {
                result.jsonl = text;
                result.tokens = tokens;
                result.hits.push(hit);
            } else {
                selected.pop();
            }
        }
        result.omitted = total - result.hits.len();
        result
    }

    fn serialize_selection(
        &self,
        selected: &[&Node],
        counter: &TokenCounter,
        options: BundleOptions,
        total: usize,
    ) -> (String, usize) {
        let source_urls = self
            .corpus
            .sources
            .iter()
            .map(|source| (source.id.as_str(), source.url.as_str()))
            .collect::<HashMap<_, _>>();
        let mut sources = Vec::new();
        let mut source_slots = HashMap::new();
        let records = selected
            .iter()
            .map(|node| {
                let citations = node
                    .sources
                    .iter()
                    .map(|id| {
                        let url = source_urls[id.as_str()];
                        *source_slots.entry(url).or_insert_with(|| {
                            sources.push(url);
                            sources.len() - 1
                        })
                    })
                    .collect::<Vec<_>>();
                let full = matches!(options.detail, Detail::Full);
                BundleRecord {
                    id: &node.id,
                    kind: node.kind,
                    summary: &node.summary,
                    review: node.review,
                    sources: citations,
                    facets: &node.facets,
                    definition: if full { &node.definition } else { "" },
                    applicability: if full { &node.applicability } else { &[] },
                    exclusions: if full { &node.exclusions } else { &[] },
                    mappings: if full { &node.mappings } else { &[] },
                    code: if full {
                        node.code
                            .iter()
                            .map(|code| BundleCode {
                                language: &code.language,
                                source: source_slots[source_urls[code.source.as_str()]],
                                start_line: code.start_line,
                                text: &code.text,
                            })
                            .collect()
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect::<Vec<_>>();
        let ids = selected
            .iter()
            .map(|node| node.id.as_str())
            .collect::<HashSet<_>>();
        let edges = self
            .corpus
            .edges
            .iter()
            .filter(|edge| ids.contains(edge.from.as_str()) && ids.contains(edge.to.as_str()))
            .collect::<Vec<_>>();
        let mut value = serde_json::json!({
            "revision": self.corpus.revision,
            "sources": sources,
            "records": records,
            "omitted": total - selected.len(),
        });
        if !edges.is_empty() {
            value["edges"] = serde_json::to_value(edges).expect("serializable edges");
        }
        packing::serialize(value, options.format, counter)
    }

    fn bounded_ancestors<'a>(
        &'a self,
        direct: &[Hit<'a>],
        facets: &[&str],
        max_depth: usize,
    ) -> Vec<(Hit<'a>, usize)> {
        if max_depth == 0 {
            return Vec::new();
        }
        let candidates =
            (!facets.is_empty()).then(|| self.matching(facets).into_iter().collect::<HashSet<_>>());
        let direct_ids = direct
            .iter()
            .map(|hit| self.ids[hit.id])
            .collect::<HashSet<_>>();
        let mut best = HashMap::<usize, (usize, usize, f64)>::new();
        for (seed_order, hit) in direct.iter().enumerate() {
            let seed = self.ids[hit.id];
            let mut pending = self.parents[seed]
                .iter()
                .map(|&parent| (parent, 1))
                .collect::<VecDeque<_>>();
            let mut walked = HashSet::new();
            while let Some((parent, depth)) = pending.pop_front() {
                if !walked.insert(parent) {
                    continue;
                }
                if !direct_ids.contains(&parent)
                    && candidates.as_ref().is_none_or(|set| set.contains(&parent))
                {
                    let candidate = (depth, seed_order, hit.score);
                    if best.get(&parent).is_none_or(|current| {
                        candidate.0 < current.0
                            || candidate.0 == current.0 && candidate.1 < current.1
                    }) {
                        best.insert(parent, candidate);
                    }
                }
                if depth < max_depth {
                    pending.extend(self.parents[parent].iter().map(|&next| (next, depth + 1)));
                }
            }
        }
        let mut ancestors = best.into_iter().collect::<Vec<_>>();
        ancestors.sort_unstable_by(|(left, a), (right, b)| {
            a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(left.cmp(right))
        });
        ancestors
            .into_iter()
            .map(|(index, (depth, _, score))| {
                (
                    Hit {
                        id: &self.corpus.nodes[index].id,
                        score,
                        relation: "ancestor",
                    },
                    depth,
                )
            })
            .collect()
    }

    /// Rank only failure modes. Ancestors are explicit structural context and keep
    /// the originating lexical score; they are not independent semantic matches.
    pub fn rank(&self, query: &str, facets: &[&str], mode: RetrievalMode) -> Vec<Hit<'_>> {
        self.rank_kind(query, facets, mode, Kind::FailureMode)
    }

    /// Rank concrete findings with the same lexical policy as failure modes.
    pub fn rank_findings(&self, query: &str, facets: &[&str], mode: RetrievalMode) -> Vec<Hit<'_>> {
        self.rank_kind(query, facets, mode, Kind::Finding)
    }

    fn rank_kind(
        &self,
        query: &str,
        facets: &[&str],
        mode: RetrievalMode,
        kind: Kind,
    ) -> Vec<Hit<'_>> {
        // Unfiltered lexical queries touch only term postings, not every node.
        let candidates =
            (!facets.is_empty()).then(|| self.matching(facets).into_iter().collect::<HashSet<_>>());
        let eligible = |index: usize| {
            self.corpus.nodes[index].kind == kind
                && candidates.as_ref().is_none_or(|set| set.contains(&index))
        };
        let mut ranked = match mode {
            RetrievalMode::IdOrder => (0..self.corpus.nodes.len())
                .filter(|&i| eligible(i))
                .map(|i| (i, 0.0))
                .collect::<Vec<_>>(),
            _ => self
                .searches
                .get(&kind)
                .expect("compiled search index for public node kinds")
                .scores(query)
                .into_iter()
                .filter(|(i, _)| eligible(*i))
                .collect(),
        };
        ranked.sort_unstable_by(|(a, x), (b, y)| y.total_cmp(x).then(a.cmp(b)));
        if kind != Kind::FailureMode || !matches!(mode, RetrievalMode::Bm25Ancestors) {
            return ranked
                .into_iter()
                .map(|(index, score)| Hit {
                    id: &self.corpus.nodes[index].id,
                    score,
                    relation: "match",
                })
                .collect();
        }
        let mut output = Vec::new();
        let mut seen = HashSet::new();
        for (index, score) in ranked {
            if seen.insert(index) {
                output.push(Hit {
                    id: &self.corpus.nodes[index].id,
                    score,
                    relation: "match",
                });
            }
            let mut pending = self.parents[index]
                .iter()
                .map(|&parent| (parent, 1))
                .collect::<VecDeque<_>>();
            let mut walked = HashSet::new();
            while let Some((parent, depth)) = pending.pop_front() {
                if walked.insert(parent) {
                    if eligible(parent) && seen.insert(parent) {
                        output.push(Hit {
                            id: &self.corpus.nodes[parent].id,
                            score,
                            relation: "ancestor",
                        });
                    }
                    pending.extend(self.parents[parent].iter().map(|&next| (next, depth + 1)));
                }
            }
        }
        output
    }

    /// Keep whole records and recount the complete candidate output: BPE token
    /// counts are not assumed additive across record boundaries.
    pub fn ranked_context(
        &self,
        query: &str,
        facets: &[&str],
        mode: RetrievalMode,
        counter: &TokenCounter,
        max_tokens: usize,
        max_records: usize,
    ) -> RankedContext<'_> {
        let ranked = self.rank(query, facets, mode);
        let total = ranked.len();
        let mut result = RankedContext {
            jsonl: String::new(),
            hits: Vec::new(),
            tokens: 0,
            omitted: 0,
        };
        for hit in ranked {
            if result.hits.len() == max_records {
                break;
            }
            let previous = result.jsonl.len();
            result.jsonl.push_str(&self.summaries[self.ids[hit.id]]);
            let tokens = counter.count(&result.jsonl);
            if tokens <= max_tokens {
                result.tokens = tokens;
                result.hits.push(hit);
            } else {
                result.jsonl.truncate(previous);
            }
        }
        result.omitted = total - result.hits.len();
        result
    }
}
