//! A validated, immutable index for source-backed failure-mode knowledge.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

mod retrieval;
pub use retrieval::{
    BundleOptions, Detail, ExplorationContext, Hit, InventoryContext, RankedContext, RetrievalMode,
    TokenCounter,
};

mod packing;
pub use packing::{BundleFormat, expand_bundle};

mod evaluation;
pub use evaluation::{EvalCase, EvalReport, EvalSuite, Split};

mod import;
pub use import::import_owasp;

mod bastet;
pub use bastet::import_bastet;

mod route;
pub use route::{Route, RouteEvidence, RouteSelection};

/// Authoring format; revision identifies the exact corpus snapshot.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Corpus {
    pub revision: String,
    #[serde(default)]
    pub sources: Vec<Source>,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

/// A concept or source record, with independent classification facets.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub kind: Kind,
    pub summary: String,
    #[serde(default)]
    pub definition: String,
    #[serde(default)]
    pub facets: Vec<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub applicability: Vec<String>,
    #[serde(default)]
    pub mappings: Vec<String>,
    #[serde(default)]
    pub review: ReviewStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code: Vec<CodeExcerpt>,
}

/// An exact source excerpt, with one-based line location in its pinned source.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeExcerpt {
    pub language: String,
    pub source: String,
    pub start_line: usize,
    pub text: String,
}

/// Source checking records provenance, not independent expert validation.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    #[default]
    Draft,
    /// Imported from a pinned source without independent content adjudication.
    Imported,
    SourceChecked,
}

/// A pinned source and its reuse terms. Nodes refer to its ID.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub title: String,
    pub url: String,
    pub revision: String,
    pub license: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    FailureMode,
    Property,
    Finding,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub from: String,
    pub relation: Relation,
    pub to: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    Specializes,
    Violates,
    InstanceOf,
    RelatedTo,
}

/// Internal references use integer offsets; public references remain stable IDs.
pub struct Graph {
    corpus: Corpus,
    ids: HashMap<String, usize>,
    facets: HashMap<String, Vec<usize>>,
    children: Vec<Vec<usize>>,
    parents: Vec<Vec<usize>>,
    summaries: Vec<String>,
    searches: HashMap<Kind, retrieval::SearchIndex>,
}

/// Exact byte-budgeted JSONL. Selection is deterministic ID order, not relevance ranking.
pub struct Context {
    pub jsonl: String,
    pub selected: usize,
    pub omitted: usize,
}

/// A node reached while browsing a specialization subtree.
#[derive(Debug, Serialize)]
pub struct TraversalHit<'a> {
    pub id: &'a str,
    pub depth: usize,
}

impl Graph {
    pub fn compile(mut corpus: Corpus) -> Result<Self, String> {
        if corpus.revision.trim().is_empty() {
            return Err("corpus revision must be nonempty".into());
        }
        corpus.nodes.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        let mut source_ids = HashMap::new();
        for source in &corpus.sources {
            if [
                source.id.as_str(),
                &source.title,
                &source.revision,
                &source.license,
            ]
            .iter()
            .any(|s| s.trim().is_empty())
                || !source.url.starts_with("https://")
                || source_ids.insert(source.id.as_str(), source).is_some()
            {
                return Err(
                    "sources require unique IDs, HTTPS URLs, titles, revisions and licenses".into(),
                );
            }
        }
        let mut ids = HashMap::with_capacity(corpus.nodes.len());
        let mut facets = HashMap::<String, Vec<usize>>::new();
        for (index, node) in corpus.nodes.iter_mut().enumerate() {
            if node.id.trim().is_empty() || node.summary.trim().is_empty() {
                return Err("node ID and summary must be nonempty".into());
            }
            if ids.insert(node.id.clone(), index).is_some() {
                return Err(format!("duplicate ID: {}", node.id));
            }
            for source in &node.sources {
                if !source_ids.contains_key(source.as_str()) {
                    return Err(format!("unknown source: {source}"));
                }
            }
            for code in &node.code {
                if code.language.trim().is_empty()
                    || code.text.is_empty()
                    || code.start_line == 0
                    || !node.sources.contains(&code.source)
                {
                    return Err(format!(
                        "code requires language, text, a source attached to its node and a positive start line: {}",
                        node.id
                    ));
                }
            }
            if matches!(
                node.review,
                ReviewStatus::Imported | ReviewStatus::SourceChecked
            ) && node.sources.is_empty()
            {
                return Err(format!(
                    "imported or source-checked node requires provenance: {}",
                    node.id
                ));
            }
            node.facets.sort_unstable();
            node.facets.dedup();
            for facet in &node.facets {
                if !facet.contains(':') || facet.split(':').any(str::is_empty) {
                    return Err(format!("invalid facet: {facet}; expected dimension:value"));
                }
                facets.entry(facet.clone()).or_default().push(index);
            }
        }
        let mut children = vec![Vec::new(); corpus.nodes.len()];
        let mut parents = vec![Vec::new(); corpus.nodes.len()];
        let mut indegree = vec![0usize; corpus.nodes.len()];
        let mut seen = HashSet::new();
        for edge in &corpus.edges {
            let from = *ids
                .get(&edge.from)
                .ok_or_else(|| format!("unknown ID: {}", edge.from))?;
            let to = *ids
                .get(&edge.to)
                .ok_or_else(|| format!("unknown ID: {}", edge.to))?;
            if !seen.insert((from, edge.relation, to)) {
                return Err(format!("duplicate edge: {} -> {}", edge.from, edge.to));
            }
            let kinds = (corpus.nodes[from].kind, corpus.nodes[to].kind);
            let valid = match edge.relation {
                Relation::Specializes => kinds == (Kind::FailureMode, Kind::FailureMode),
                Relation::Violates => kinds == (Kind::FailureMode, Kind::Property),
                Relation::InstanceOf => kinds == (Kind::Finding, Kind::FailureMode),
                Relation::RelatedTo => true,
            };
            if !valid {
                return Err(format!("invalid endpoint kinds for {:?}", edge.relation));
            }
            if edge.relation == Relation::Specializes {
                children[to].push(from);
                parents[from].push(to);
                indegree[from] += 1;
            }
        }
        let mut ready = indegree
            .iter()
            .enumerate()
            .filter_map(|(i, &d)| (d == 0).then_some(i))
            .collect::<VecDeque<_>>();
        let mut visited = 0;
        while let Some(parent) = ready.pop_front() {
            visited += 1;
            for &child in &children[parent] {
                indegree[child] -= 1;
                if indegree[child] == 0 {
                    ready.push_back(child);
                }
            }
        }
        if visited != corpus.nodes.len() {
            return Err("specialization edges contain a cycle".into());
        }
        for list in &mut parents {
            list.sort_unstable();
        }
        let summaries = corpus
            .nodes
            .iter()
            .map(|node| {
                let mut line = serde_json::to_string(&serde_json::json!({
                    "id": node.id, "kind": node.kind, "summary": node.summary,
                    "facets": node.facets, "revision": corpus.revision,
                    "sources": node.sources.iter().map(|id| source_ids[id.as_str()].url.as_str()).collect::<Vec<_>>(),
                    "review": node.review,
                }))
                .expect("serializing string fields cannot fail");
                line.push('\n');
                line
            })
            .collect();
        let searches = [Kind::FailureMode, Kind::Property, Kind::Finding]
            .into_iter()
            .map(|kind| (kind, retrieval::SearchIndex::build(&corpus.nodes, kind)))
            .collect();
        Ok(Self {
            corpus,
            ids,
            facets,
            children,
            parents,
            summaries,
            searches,
        })
    }

    pub fn corpus(&self) -> &Corpus {
        &self.corpus
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.ids.get(id).map(|&i| &self.corpus.nodes[i])
    }

    /// AND filtering starts with the smallest posting list. Facets are explicit,
    /// not inherited; a match is a classification match, not proof of applicability.
    pub fn matching(&self, facets: &[&str]) -> Vec<usize> {
        if facets.is_empty() {
            return (0..self.corpus.nodes.len()).collect();
        }
        let mut lists = Vec::with_capacity(facets.len());
        for facet in facets {
            let Some(list) = self.facets.get(*facet) else {
                return Vec::new();
            };
            lists.push(list);
        }
        lists.sort_unstable_by_key(|list| list.len());
        lists[0]
            .iter()
            .copied()
            .filter(|id| lists[1..].iter().all(|list| list.binary_search(id).is_ok()))
            .collect()
    }

    /// Return the root and unique descendants, independent of traversal depth.
    pub fn descendants(&self, root: &str) -> Result<Vec<&Node>, String> {
        let &root = self
            .ids
            .get(root)
            .ok_or_else(|| format!("unknown ID: {root}"))?;
        let mut seen = vec![false; self.corpus.nodes.len()];
        let mut pending = vec![root];
        seen[root] = true;
        while let Some(parent) = pending.pop() {
            for &child in &self.children[parent] {
                if !seen[child] {
                    seen[child] = true;
                    pending.push(child);
                }
            }
        }
        Ok(seen
            .into_iter()
            .enumerate()
            .filter_map(|(i, present)| present.then_some(&self.corpus.nodes[i]))
            .collect())
    }

    /// Return a root and its unique descendants through at most `max_depth`
    /// specialization edges. Shared descendants keep their shortest distance.
    pub fn descendants_to_depth(
        &self,
        root: &str,
        max_depth: usize,
    ) -> Result<Vec<TraversalHit<'_>>, String> {
        let &root = self
            .ids
            .get(root)
            .ok_or_else(|| format!("unknown ID: {root}"))?;
        let mut depths = vec![usize::MAX; self.corpus.nodes.len()];
        let mut pending = VecDeque::from([(root, 0)]);
        depths[root] = 0;
        while let Some((parent, depth)) = pending.pop_front() {
            if depth == max_depth {
                continue;
            }
            for &child in &self.children[parent] {
                if depth + 1 < depths[child] {
                    depths[child] = depth + 1;
                    pending.push_back((child, depth + 1));
                }
            }
        }
        let mut hits = depths
            .into_iter()
            .enumerate()
            .filter(|(_, depth)| *depth != usize::MAX)
            .map(|(index, depth)| TraversalHit {
                id: &self.corpus.nodes[index].id,
                depth,
            })
            .collect::<Vec<_>>();
        hits.sort_unstable_by(|left, right| {
            left.depth.cmp(&right.depth).then(left.id.cmp(right.id))
        });
        Ok(hits)
    }

    /// Pack complete summary records, including delimiters, within a UTF-8 byte budget.
    /// Oversized records are skipped; later smaller records may still fit.
    pub fn context(&self, facets: &[&str], max_bytes: usize) -> Context {
        let candidates = self.matching(facets);
        let mut result = Context {
            jsonl: String::new(),
            selected: 0,
            omitted: 0,
        };
        for index in candidates {
            let line = &self.summaries[index];
            if line.len() <= max_bytes - result.jsonl.len() {
                result.jsonl.push_str(line);
                result.selected += 1;
            } else {
                result.omitted += 1;
            }
        }
        result
    }

    /// Count explicit states against a fixed, revision-bound scope.
    pub fn coverage(&self, ledger: &Ledger) -> Result<Coverage, String> {
        if ledger.revision != self.corpus.revision || ledger.scope_revision.trim().is_empty() {
            return Err(
                "ledger must identify the corpus revision and reviewed scope revision".into(),
            );
        }
        let scope = ledger.scope.iter().collect::<HashSet<_>>();
        if scope.len() != ledger.scope.len() {
            return Err("duplicate scope ID".into());
        }
        for id in &scope {
            if self
                .node(id)
                .is_none_or(|node| node.kind != Kind::FailureMode)
            {
                return Err(format!("scope ID must identify a failure mode: {id}"));
            }
        }
        let mut result = Coverage {
            total: scope.len(),
            unassessed: scope.len(),
            unresolved: 0,
            not_applicable: 0,
            assessed: 0,
            concern: 0,
        };
        let mut seen = HashSet::new();
        for record in &ledger.records {
            if !scope.contains(&record.id) || !seen.insert(&record.id) {
                return Err(format!(
                    "out-of-scope or duplicate assessment: {}",
                    record.id
                ));
            }
            if record.evidence.is_empty() || record.evidence.iter().any(|s| s.trim().is_empty()) {
                return Err(format!(
                    "assessment requires evidence or an unresolved-context explanation: {}",
                    record.id
                ));
            }
            result.unassessed -= 1;
            match record.state {
                AssessmentState::Unresolved => result.unresolved += 1,
                AssessmentState::NotApplicable => result.not_applicable += 1,
                AssessmentState::Assessed => result.assessed += 1,
                AssessmentState::Concern => result.concern += 1,
            }
        }
        Ok(result)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub revision: String,
    pub scope_revision: String,
    pub scope: Vec<String>,
    pub records: Vec<Assessment>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub id: String,
    pub state: AssessmentState,
    pub evidence: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentState {
    Unresolved,
    NotApplicable,
    Assessed,
    Concern,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Coverage {
    pub total: usize,
    pub unassessed: usize,
    pub unresolved: usize,
    pub not_applicable: usize,
    pub assessed: usize,
    pub concern: usize,
}
