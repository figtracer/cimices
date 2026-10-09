//! Deterministic routing from a threat model to failure-mode records.

use crate::{Graph, RetrievalMode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

const THREAT_WEIGHT: f64 = 4.0;
const INVARIANT_WEIGHT: f64 = 2.0;
const COVERAGE_GAP_WEIGHT: f64 = 1.0;
const RESULTS_PER_QUERY: usize = 10;
// These are short, target-specific result lists. An offset would flatten the
// difference between a precise first hit and generic records repeated near the
// bottom of many lists, allowing the latter to crowd out the former.
const RRF_OFFSET: usize = 0;
// Prefer category breadth when relevance is close, while retaining a clearly
// stronger target-specific result from an already represented category.
const CATEGORY_REPEAT_PENALTY: f64 = 0.15;

#[derive(Deserialize)]
struct ThreatModel {
    schema_version: String,
    #[serde(default)]
    capabilities: Vec<Capability>,
    #[serde(default)]
    attack_surfaces: Vec<NamedItem>,
    #[serde(default)]
    invariants: Vec<NamedItem>,
    #[serde(default)]
    threats: Vec<Threat>,
    #[serde(default)]
    coverage_gaps: Vec<NamedItem>,
}

#[derive(Deserialize)]
struct Capability {
    id: String,
    status: CapabilityStatus,
    #[serde(default)]
    rationale: Option<String>,
    #[serde(default)]
    evidence: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CapabilityStatus {
    Present,
    Absent,
    Unknown,
}

#[derive(Deserialize)]
struct NamedItem {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    statement: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    entry_points: Vec<String>,
}

#[derive(Deserialize)]
struct Threat {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    impact: String,
    #[serde(default)]
    preconditions: Vec<String>,
    #[serde(default)]
    invariant_ids: Vec<String>,
    #[serde(default)]
    attack_surface_ids: Vec<String>,
}

#[derive(Deserialize)]
struct PlannerCatalog {
    schema_version: String,
    database_schema_version: u64,
    database_aggregate_sha256: String,
    records: Vec<PlannerRecord>,
}

#[derive(Deserialize)]
struct PlannerRecord {
    id: String,
    title: String,
    capabilities: PlannerCapabilities,
    source_sha256: String,
    source_size_bytes: u64,
    selected_artifact_path: String,
}

#[derive(Default, Deserialize)]
struct PlannerCapabilities {
    #[serde(default)]
    required: Vec<String>,
    #[serde(default)]
    optional: Vec<String>,
    #[serde(default)]
    incompatible: Vec<String>,
}

struct Query {
    id: String,
    weight: f64,
    text: String,
}

/// One lexical vote supporting a routed failure mode.
#[derive(Debug, Serialize)]
pub struct RouteEvidence {
    pub query_id: String,
    pub rank: usize,
    pub score: f64,
}

/// A failure mode selected through weighted reciprocal-rank fusion.
#[derive(Debug, Serialize)]
pub struct RouteSelection<'a> {
    pub id: &'a str,
    pub score: f64,
    pub evidence: Vec<RouteEvidence>,
}

/// A reproducible, locally computed route for one verified threat model.
#[derive(Debug, Serialize)]
pub struct Route<'a> {
    pub schema: &'static str,
    pub corpus_revision: &'a str,
    pub threat_model_sha256: String,
    pub query_count: usize,
    pub max_classes: usize,
    pub selected: Vec<RouteSelection<'a>>,
}

impl Graph {
    /// Route a v1 threat model without sending the taxonomy to a model.
    pub fn route(&self, threat_model: &[u8], max_classes: usize) -> Result<Route<'_>, String> {
        if max_classes == 0 {
            return Err("max classes must be positive".into());
        }
        let model = serde_json::from_slice::<ThreatModel>(threat_model)
            .map_err(|error| format!("invalid threat model: {error}"))?;
        if model.schema_version != "cimices.threat-model.v1" {
            return Err(format!(
                "unsupported threat model schema: {}",
                model.schema_version
            ));
        }
        let queries = model.queries();
        if queries.is_empty() {
            return Err("threat model has no routing queries".into());
        }

        let absent_categories = model
            .capabilities
            .iter()
            .filter(|capability| matches!(capability.status, CapabilityStatus::Absent))
            .map(|capability| capability.id.as_str())
            .collect::<HashSet<_>>();
        let mut scores = HashMap::<&str, f64>::new();
        let mut evidence = HashMap::<&str, Vec<RouteEvidence>>::new();
        for query in &queries {
            for (index, hit) in self
                .rank(&query.text, &[], RetrievalMode::Bm25)
                .into_iter()
                .filter(|hit| {
                    self.node(hit.id).is_some_and(|node| {
                        !node
                            .facets
                            .iter()
                            .any(|facet| facet.starts_with("taxonomy:"))
                            && category(node).is_none_or(|value| !absent_categories.contains(value))
                    })
                })
                .take(RESULTS_PER_QUERY)
                .enumerate()
            {
                *scores.entry(hit.id).or_default() += reciprocal_rank(query.weight, index + 1);
                evidence.entry(hit.id).or_default().push(RouteEvidence {
                    query_id: query.id.clone(),
                    rank: index + 1,
                    score: hit.score,
                });
            }
        }
        let mut ranked = scores.into_iter().collect::<Vec<_>>();
        ranked.sort_unstable_by(|(left_id, left), (right_id, right)| {
            right.total_cmp(left).then(left_id.cmp(right_id))
        });
        let mut category_counts = HashMap::<&str, usize>::new();
        let mut selected = Vec::with_capacity(max_classes.min(ranked.len()));
        while !ranked.is_empty() && selected.len() < max_classes {
            let best = ranked
                .iter()
                .enumerate()
                .max_by(|(_, (left_id, left)), (_, (right_id, right))| {
                    let left_category = self.node(left_id).and_then(category);
                    let right_category = self.node(right_id).and_then(category);
                    let left = adjusted_score(
                        *left,
                        left_category
                            .and_then(|value| category_counts.get(value))
                            .copied(),
                    );
                    let right = adjusted_score(
                        *right,
                        right_category
                            .and_then(|value| category_counts.get(value))
                            .copied(),
                    );
                    left.total_cmp(&right).then(right_id.cmp(left_id))
                })
                .map(|(index, _)| index)
                .expect("nonempty candidates have a best route");
            let (id, raw_score) = ranked.swap_remove(best);
            let node_category = self.node(id).and_then(category);
            let score = adjusted_score(
                raw_score,
                node_category
                    .and_then(|value| category_counts.get(value))
                    .copied(),
            );
            if let Some(node_category) = node_category {
                *category_counts.entry(node_category).or_default() += 1;
            }
            selected.push({
                let mut evidence = evidence.remove(id).expect("a score has routing evidence");
                evidence.sort_unstable_by(|left, right| {
                    left.query_id
                        .cmp(&right.query_id)
                        .then(left.rank.cmp(&right.rank))
                });
                RouteSelection {
                    id,
                    score,
                    evidence,
                }
            });
        }
        Ok(Route {
            schema: "cimices/route-v1",
            corpus_revision: &self.corpus().revision,
            threat_model_sha256: format!("{:x}", Sha256::digest(threat_model)),
            query_count: queries.len(),
            max_classes,
            selected,
        })
    }

    /// Build the complete goal plan locally from a routed planner catalog.
    pub fn route_plan(
        &self,
        threat_model: &[u8],
        planner_catalog: &[u8],
        max_classes: usize,
    ) -> Result<(Route<'_>, Value), String> {
        let model = serde_json::from_slice::<ThreatModel>(threat_model)
            .map_err(|error| format!("invalid threat model: {error}"))?;
        let catalog = serde_json::from_slice::<PlannerCatalog>(planner_catalog)
            .map_err(|error| format!("invalid planner catalog: {error}"))?;
        if catalog.schema_version != "cimices.planner-catalog.v1" {
            return Err(format!(
                "unsupported planner catalog schema: {}",
                catalog.schema_version
            ));
        }
        let route = self.route(threat_model, max_classes)?;
        let records = catalog
            .records
            .iter()
            .map(|record| (record.id.as_str(), record))
            .collect::<HashMap<_, _>>();
        let routed_ids = route
            .selected
            .iter()
            .map(|selection| planner_class_id(selection.id))
            .collect::<Vec<_>>();
        if routed_ids.len() != catalog.records.len()
            || routed_ids
                .iter()
                .any(|id| !records.contains_key(id.as_str()))
        {
            return Err(
                "planner catalog must contain every routed class and no other records".into(),
            );
        }

        let capabilities = model
            .capabilities
            .iter()
            .map(|capability| (capability.id.as_str(), capability))
            .collect::<HashMap<_, _>>();
        let routed_records = route
            .selected
            .iter()
            .zip(routed_ids.iter())
            .map(|(selection, id)| {
                (
                    selection,
                    *records
                        .get(id.as_str())
                        .expect("routed catalog membership was checked"),
                )
            })
            .collect::<Vec<_>>();
        let mut applicable = Vec::new();
        let decisions = routed_records
            .iter()
            .map(|(_, record)| {
                let decisive = record
                    .capabilities
                    .required
                    .iter()
                    .any(|id| capabilities.get(id.as_str()).is_some_and(|value| matches!(value.status, CapabilityStatus::Absent)))
                    || record.capabilities.incompatible.iter().any(|id| {
                        capabilities
                            .get(id.as_str())
                            .is_some_and(|value| matches!(value.status, CapabilityStatus::Present))
                    });
                if !decisive {
                    applicable.push(record.id.as_str());
                }
                let checks = [
                    ("required", &record.capabilities.required),
                    ("optional", &record.capabilities.optional),
                    ("incompatible", &record.capabilities.incompatible),
                ]
                .into_iter()
                .flat_map(|(requirement, ids)| {
                    let capabilities = &capabilities;
                    ids.iter().map(move |id| {
                        let capability = capabilities.get(id.as_str());
                        json!({
                            "capability_id": id,
                            "requirement": requirement,
                            "observed_status": capability.map_or("unknown", |value| value.status.as_str()),
                            "evidence": capability.map_or_else(Vec::new, |value| value.evidence.clone()),
                            "rationale": capability.map_or_else(
                                || "This capability was not established by the upstream threat model.".to_owned(),
                                |value| value.rationale.clone().unwrap_or_else(|| "Not recorded in the upstream threat model.".to_owned()),
                            ),
                        })
                    })
                })
                .collect::<Vec<_>>();
                json!({
                    "class_id": record.id,
                    "decision": if decisive { "inapplicable" } else { "applicable" },
                    "checks": checks,
                    "rationale": if decisive {
                        "A required capability is proven absent or an incompatible capability is proven present."
                    } else {
                        "No required capability is proven absent and no incompatible capability is proven present."
                    },
                })
            })
            .collect::<Vec<_>>();

        let selected_record = |record: &PlannerRecord| {
            json!({
                "id": record.id,
                "path": record.selected_artifact_path,
                "sha256": record.source_sha256,
                "size_bytes": record.source_size_bytes,
            })
        };
        let class_goals = routed_records
            .iter()
            .filter(|(_, record)| applicable.contains(&record.id.as_str()))
            .map(|(selection, record)| {
                let threat_ids = model
                    .threats
                    .iter()
                    .filter(|threat| {
                        let query_id = format!("threat:{}", threat.id);
                        selection
                            .evidence
                            .iter()
                            .any(|evidence| evidence.query_id == query_id)
                    })
                    .map(|threat| threat.id.as_str())
                    .collect::<Vec<_>>();
                let coverage_gap = threat_ids.is_empty();
                let threat_keys = if coverage_gap {
                    vec!["threat-model:coverage-gap"]
                } else {
                    threat_ids.clone()
                };
                let mut replacements = Map::new();
                replacements.insert(format!("class:{}", record.id), json!(record.title));
                if coverage_gap {
                    replacements.insert(
                        "threat-model:coverage-gap".into(),
                        json!(format!("Unmodeled coverage for {}", record.title)),
                    );
                } else {
                    for threat in model
                        .threats
                        .iter()
                        .filter(|threat| threat_ids.contains(&threat.id.as_str()))
                    {
                        replacements.insert(threat.id.clone(), json!(threat.title));
                    }
                }
                let attack_surface_ids = model
                    .threats
                    .iter()
                    .filter(|threat| threat_ids.contains(&threat.id.as_str()))
                    .flat_map(|threat| threat.attack_surface_ids.iter().cloned())
                    .fold(Vec::new(), |mut ids, id| {
                        if !ids.contains(&id) {
                            ids.push(id);
                        }
                        ids
                    });
                let threat_placeholders = threat_keys
                    .iter()
                    .map(|id| format!("{{{{{id}}}}}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                json!({
                    "kind": "class",
                    "id": record.id,
                    "node_id": format!("dynamic:class:{}", record.id),
                    "class_id": record.id,
                    "class_replacement_key": format!("class:{}", record.id),
                    "threat_ids": threat_ids,
                    "threat_replacement_keys": threat_keys,
                    "attack_surface_ids": attack_surface_ids,
                    "coverage_gap": coverage_gap,
                    "selected_record": selected_record(record),
                    "title": record.title,
                    "goal_prompt": format!("Your /goal is to find a vulnerability of type {{{{class:{}}}}} using {threat_placeholders}.", record.id),
                    "replacements": replacements,
                    "selection_rationale": "Cimices routed this class from the verified threat model using local deterministic retrieval.",
                })
            })
            .collect::<Vec<_>>();
        let threat_goals = model
            .threats
            .iter()
            .map(|threat| {
                let class_ids = class_goals
                    .iter()
                    .filter(|goal| {
                        goal["threat_ids"]
                            .as_array()
                            .is_some_and(|ids| ids.iter().any(|id| id == &threat.id))
                    })
                    .map(|goal| goal["id"].clone())
                    .collect::<Vec<_>>();
                json!({
                    "kind": "threat",
                    "id": threat.id,
                    "node_id": format!("dynamic:threat:{}", threat.id),
                    "threat_ids": [threat.id.as_str()],
                    "class_ids": class_ids,
                    "attack_surface_ids": threat.attack_surface_ids,
                    "title": threat.title,
                    "goal_prompt": format!("Your /goal is to find any vulnerability affecting {{{{{}}}}}.", threat.id),
                    "replacements": { threat.id.clone(): threat.title.clone() },
                    "selection_rationale": "The additive policy creates one goal for every verified modeled threat.",
                })
            })
            .collect::<Vec<_>>();
        let selected_records = routed_records
            .iter()
            .filter(|(_, record)| applicable.contains(&record.id.as_str()))
            .map(|(_, record)| selected_record(record))
            .collect::<Vec<_>>();
        let plan = json!({
            "schema_version": "cimices.goal-plan.v1",
            "policy": "additive-v1",
            "threat_model_sha256": format!("{:x}", Sha256::digest(threat_model)),
            "vulnerability_database": {
                "planner_catalog_schema_version": catalog.schema_version,
                "snapshot_manifest_schema_version": "cimices.planner-snapshot.v1",
                "database_schema_version": catalog.database_schema_version,
                "aggregate_sha256": catalog.database_aggregate_sha256,
                "catalog_sha256": format!("{:x}", Sha256::digest(planner_catalog)),
            },
            "catalog_class_ids": routed_ids,
            "modeled_threat_ids": model.threats.iter().map(|threat| threat.id.as_str()).collect::<Vec<_>>(),
            "threat_goals": threat_goals,
            "class_goals": class_goals,
            "applicability_decisions": decisions,
            "selected_class_records": selected_records,
            "roaming_goal": {
                "node_id": "goal-roaming",
                "prompt_path": "strategies/roaming-goal.md",
                "purpose": "Challenge the taxonomy and threat model for uncovered target-specific failures.",
            },
            "counts": {
                "threats": model.threats.len(),
                "applicable_classes": applicable.len(),
                "inapplicable_classes": catalog.records.len() - applicable.len(),
                "dynamic_goals": model.threats.len() + applicable.len(),
                "total_goals": model.threats.len() + applicable.len() + 1,
            },
        });
        Ok((route, plan))
    }
}

impl CapabilityStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
        }
    }
}

fn planner_class_id(id: &str) -> String {
    id.strip_prefix("scwe:")
        .map_or_else(|| id.to_owned(), |number| format!("scwe-{number}"))
}

fn category(node: &crate::Node) -> Option<&str> {
    node.facets
        .iter()
        .find_map(|facet| facet.strip_prefix("category:"))
}

fn adjusted_score(score: f64, prior_category_selections: Option<usize>) -> f64 {
    score / (1.0 + CATEGORY_REPEAT_PENALTY * prior_category_selections.unwrap_or_default() as f64)
}

fn reciprocal_rank(weight: f64, rank: usize) -> f64 {
    weight / (RRF_OFFSET + rank) as f64
}

impl ThreatModel {
    fn queries(&self) -> Vec<Query> {
        let invariants = self
            .invariants
            .iter()
            .map(|item| (item.id.as_str(), item))
            .collect::<HashMap<_, _>>();
        let surfaces = self
            .attack_surfaces
            .iter()
            .map(|item| (item.id.as_str(), item))
            .collect::<HashMap<_, _>>();
        let mut queries = self
            .threats
            .iter()
            .filter_map(|threat| {
                let mut parts = vec![
                    threat.title.as_str(),
                    threat.description.as_str(),
                    threat.impact.as_str(),
                ];
                parts.extend(threat.preconditions.iter().map(String::as_str));
                for invariant in threat
                    .invariant_ids
                    .iter()
                    .filter_map(|id| invariants.get(id.as_str()))
                {
                    parts.extend([invariant.name.as_str(), invariant.statement.as_str()]);
                }
                for surface in threat
                    .attack_surface_ids
                    .iter()
                    .filter_map(|id| surfaces.get(id.as_str()))
                {
                    parts.extend([surface.name.as_str(), surface.description.as_str()]);
                    parts.extend(surface.entry_points.iter().map(String::as_str));
                }
                query(format!("threat:{}", threat.id), THREAT_WEIGHT, parts)
            })
            .collect::<Vec<_>>();
        queries.extend(self.invariants.iter().filter_map(|item| {
            query(
                format!("invariant:{}", item.id),
                INVARIANT_WEIGHT,
                [item.name.as_str(), item.statement.as_str()],
            )
        }));
        queries.extend(self.coverage_gaps.iter().filter_map(|item| {
            query(
                format!("gap:{}", item.id),
                COVERAGE_GAP_WEIGHT,
                [
                    item.name.as_str(),
                    item.title.as_str(),
                    item.description.as_str(),
                    item.reason.as_str(),
                ],
            )
        }));
        queries
    }
}

fn query<'a>(id: String, weight: f64, parts: impl IntoIterator<Item = &'a str>) -> Option<Query> {
    let text = parts
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!text.is_empty()).then_some(Query { id, weight, text })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Corpus, Kind, Node};
    use serde_json::json;

    fn graph() -> Graph {
        Graph::compile(Corpus {
            revision: "test-v1".into(),
            sources: Vec::new(),
            nodes: [
                ("access", "privileged authorization role bypass"),
                ("rounding", "vault share rounding accounting precision loss"),
                ("reentrancy", "callback reentrancy external call"),
            ]
            .into_iter()
            .map(|(id, summary)| Node {
                id: id.into(),
                kind: Kind::FailureMode,
                summary: summary.into(),
                definition: String::new(),
                facets: vec![format!(
                    "category:scsvs-{}",
                    if id == "rounding" { "comp" } else { "code" }
                )],
                exclusions: Vec::new(),
                sources: Vec::new(),
                applicability: Vec::new(),
                mappings: Vec::new(),
                review: Default::default(),
                code: Vec::new(),
            })
            .collect(),
            edges: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn reciprocal_rank_preserves_strong_specific_hits() {
        let specific = reciprocal_rank(THREAT_WEIGHT, 1);
        let repeated_generic = reciprocal_rank(THREAT_WEIGHT, 4)
            + reciprocal_rank(INVARIANT_WEIGHT, 3)
            + reciprocal_rank(COVERAGE_GAP_WEIGHT, 3);

        assert!(specific > repeated_generic);
    }

    #[test]
    fn category_diversity_is_a_soft_penalty() {
        let specific_repeat = adjusted_score(3.0, Some(1));
        let weaker_new_category = adjusted_score(2.5, None);
        let fourth_repeat = adjusted_score(3.0, Some(4));

        assert!(specific_repeat > weaker_new_category);
        assert!(fourth_repeat < weaker_new_category);
    }

    #[test]
    fn routes_linked_threat_model_fields_and_rejects_invalid_inputs() {
        let bytes = serde_json::to_vec(&json!({
            "schema_version": "cimices.threat-model.v1",
            "attack_surfaces": [{
                "id": "surface:vault", "name": "Vault shares",
                "description": "Share accounting", "entry_points": ["deposit", "redeem"]
            }],
            "invariants": [{
                "id": "invariant:rounding", "name": "Rounding",
                "statement": "Vault share precision is conserved"
            }],
            "threats": [{
                "id": "threat:dilution", "title": "Share dilution",
                "description": "Rounding changes accounting", "impact": "Precision loss",
                "preconditions": ["Small deposit"],
                "invariant_ids": ["invariant:rounding"],
                "attack_surface_ids": ["surface:vault"]
            }],
            "coverage_gaps": []
        }))
        .unwrap();
        let graph = graph();
        let route = graph.route(&bytes, 2).unwrap();
        assert_eq!(route.schema, "cimices/route-v1");
        assert_eq!(route.query_count, 2);
        assert_eq!(route.selected[0].id, "rounding");
        assert_eq!(route.selected.len(), 1);
        assert_eq!(route.threat_model_sha256.len(), 64);
        assert!(graph.route(&bytes, 0).is_err());

        let mut absent = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        absent["capabilities"] = json!([{"id":"scsvs-comp","status":"absent"}]);
        let absent = serde_json::to_vec(&absent).unwrap();
        assert!(graph.route(&absent, 2).unwrap().selected.is_empty());

        let wrong = br#"{"schema_version":"cimices.threat-model.v2"}"#;
        assert!(graph.route(wrong, 1).is_err());

        let catalog = serde_json::to_vec(&json!({
            "schema_version": "cimices.planner-catalog.v1",
            "database_schema_version": 4,
            "database_aggregate_sha256": "a".repeat(64),
            "records": [{
                "id": "rounding",
                "title": "Rounding",
                "capabilities": {
                    "required": [],
                    "optional": ["scsvs-comp"],
                    "incompatible": []
                },
                "source_sha256": "b".repeat(64),
                "source_size_bytes": 42,
                "selected_artifact_path": "vulnerability-db/selected/rounding.md"
            }]
        }))
        .unwrap();
        let (_, plan) = graph.route_plan(&bytes, &catalog, 2).unwrap();
        assert_eq!(plan["threat_goals"].as_array().unwrap().len(), 1);
        assert_eq!(plan["class_goals"].as_array().unwrap().len(), 1);
        assert_eq!(plan["class_goals"][0]["id"], "rounding");
        assert_eq!(
            plan["class_goals"][0]["threat_ids"],
            json!(["threat:dilution"])
        );
        assert_eq!(plan["counts"]["dynamic_goals"], 2);
        assert_eq!(
            plan["applicability_decisions"][0]["checks"][0]["observed_status"],
            "unknown"
        );

        let extra_catalog = serde_json::to_vec(&json!({
            "schema_version": "cimices.planner-catalog.v1",
            "database_schema_version": 4,
            "database_aggregate_sha256": "a".repeat(64),
            "records": []
        }))
        .unwrap();
        assert!(graph.route_plan(&bytes, &extra_catalog, 2).is_err());
    }
}
