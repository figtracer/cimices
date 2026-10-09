//! Reversible structural compression of JSON bundles; content strings stay exact.

use crate::TokenCounter;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashSet;

const ENCODING: &str = "cimices/compact-v1";
const GUIDE: &str = "URLs = source_base + sources[i]. Array records follow record_fields. Merge record_defaults into each record; local fields override. Code source indexes sources.";
const FACET_GUIDE: &str = "URLs = source_base + sources[i]. Array records follow record_fields. Merge record_defaults into each record; local fields override. Code source indexes sources. Facet indexes resolve through facet_table.";

/// Compact may return ordinary JSON when its complete encoding costs fewer tokens.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleFormat {
    Json,
    Compact,
}

pub(crate) fn serialize(
    value: Value,
    format: BundleFormat,
    counter: &TokenCounter,
) -> (String, usize) {
    let text = format!("{value}\n");
    let tokens = counter.count(&text);
    let mut best = (text, tokens);
    if matches!(format, BundleFormat::Json) {
        return best;
    }
    let mut best_value = value.clone();
    let mut base = value;
    base["encoding"] = json!(ENCODING);
    base["decode"] = json!(GUIDE);
    let sources = base["sources"].as_array().expect("bundle sources");
    if let Some(first) = sources.first().and_then(Value::as_str) {
        let common = sources.iter().skip(1).fold(first.len(), |end, source| {
            first[..end]
                .char_indices()
                .zip(source.as_str().expect("source URL").chars())
                .take_while(|((_, a), b)| a == b)
                .map(|((offset, ch), _)| offset + ch.len_utf8())
                .last()
                .unwrap_or(0)
        });
        if let Some(slash) = first[..common].rfind('/') {
            let prefix = first[..=slash].to_owned();
            base["sources"] = json!(
                sources
                    .iter()
                    .map(|source| { &source.as_str().expect("source URL")[prefix.len()..] })
                    .collect::<Vec<_>>()
            );
            base["source_base"] = json!(prefix);
        }
    }
    let mut factored = base.clone();
    let records = factored["records"].as_array_mut().expect("bundle records");
    if records.len() > 1 {
        let defaults = records[0]
            .as_object()
            .expect("bundle record")
            .iter()
            .filter(|(key, value)| {
                records[1..]
                    .iter()
                    .all(|record| record.get(*key) == Some(*value))
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<_, _>>();
        for record in records {
            for key in defaults.keys() {
                record.as_object_mut().expect("bundle record").remove(key);
            }
        }
        if !defaults.is_empty() {
            factored["record_defaults"] = Value::Object(defaults);
        }
    }
    for candidate in [base, factored] {
        let mut rows = candidate.clone();
        let records = &candidate["records"];
        let fields = records[0]
            .as_object()
            .expect("nonempty bundle")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let uniform = records
            .as_array()
            .expect("bundle records")
            .iter()
            .all(|record| {
                record
                    .as_object()
                    .expect("bundle record")
                    .keys()
                    .eq(fields.iter())
            });
        let tabular = uniform && !fields.is_empty();
        if tabular {
            rows["records"] = json!(
                records
                    .as_array()
                    .expect("bundle records")
                    .iter()
                    .map(|record| {
                        fields
                            .iter()
                            .map(|field| &record[field])
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            );
            rows["record_fields"] = json!(fields);
        }
        for value in std::iter::once(candidate).chain(tabular.then_some(rows)) {
            let text = format!("{value}\n");
            let tokens = counter.count(&text);
            if tokens < best.1 {
                best = (text, tokens);
                best_value = value;
            }
        }
    }
    let mut table = Vec::new();
    let mut occurrences = 0;
    let facet_column = best_value["record_fields"]
        .as_array()
        .and_then(|fields| fields.iter().position(|field| field == "facets"));
    let mut intern = |facets: &mut Value| {
        if let Some(facets) = facets.as_array_mut() {
            for facet in facets {
                occurrences += 1;
                let slot = table
                    .iter()
                    .position(|entry| entry == facet)
                    .unwrap_or_else(|| {
                        table.push(facet.clone());
                        table.len() - 1
                    });
                *facet = json!(slot);
            }
        }
    };
    if let Some(facets) = best_value
        .get_mut("record_defaults")
        .and_then(|value| value.get_mut("facets"))
    {
        intern(facets);
    }
    for record in best_value["records"]
        .as_array_mut()
        .expect("bundle records")
    {
        let facets = if let Some(column) = facet_column {
            record.get_mut(column)
        } else {
            record.get_mut("facets")
        };
        if let Some(facets) = facets {
            intern(facets);
        }
    }
    if occurrences > table.len() {
        best_value["encoding"] = json!(ENCODING);
        best_value["decode"] = json!(FACET_GUIDE);
        best_value["facet_table"] = json!(table);
        let text = format!("{best_value}\n");
        let tokens = counter.count(&text);
        if tokens < best.1 {
            best = (text, tokens);
        }
    }
    best
}

/// Expand a compact bundle to its original JSON data model. String values,
/// including code whitespace, and array order are preserved exactly.
pub fn expand_bundle(text: &str) -> Result<Value, String> {
    let mut value = serde_json::from_str::<Value>(text).map_err(|error| error.to_string())?;
    let object = value.as_object_mut().ok_or("expected a bundle object")?;
    let Some(encoding) = object.remove("encoding") else {
        return Ok(value);
    };
    let guide = if object.contains_key("facet_table") {
        FACET_GUIDE
    } else {
        GUIDE
    };
    if encoding != ENCODING || object.remove("decode") != Some(json!(guide)) {
        return Err("unsupported bundle encoding or decoding guide".into());
    }
    if let Some(prefix) = object.remove("source_base") {
        let prefix = prefix.as_str().ok_or("source_base must be a string")?;
        let sources = object
            .get_mut("sources")
            .and_then(Value::as_array_mut)
            .ok_or("expected source array")?;
        for source in sources {
            *source = json!(format!(
                "{prefix}{}",
                source.as_str().ok_or("source suffix must be a string")?
            ));
        }
    }
    let fields = object.remove("record_fields");
    let defaults = object.remove("record_defaults");
    let facets = object.remove("facet_table");
    let records = object
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("expected record array")?;
    if let Some(fields) = fields {
        let fields = fields.as_array().ok_or("record_fields must be an array")?;
        let mut seen = HashSet::new();
        let fields = fields
            .iter()
            .map(|field| {
                let field = field.as_str().ok_or("record field must be a string")?;
                if !seen.insert(field) {
                    return Err("duplicate record field");
                }
                Ok(field)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for record in records.iter_mut() {
            let row = record.as_array().ok_or("expected array record")?;
            if row.len() != fields.len() {
                return Err("record width differs from record_fields".into());
            }
            *record = Value::Object(
                fields
                    .iter()
                    .zip(row)
                    .map(|(field, value)| ((*field).to_owned(), value.clone()))
                    .collect(),
            );
        }
    }
    let defaults = defaults
        .map(|value| {
            value
                .as_object()
                .cloned()
                .ok_or("record_defaults must be an object")
        })
        .transpose()?;
    let facets = facets
        .map(|value| {
            let values = value.as_array().ok_or("facet_table must be an array")?;
            if !values.iter().all(Value::is_string) {
                return Err("facet_table entries must be strings");
            }
            Ok(values.clone())
        })
        .transpose()?;
    for record in records {
        let record = record.as_object_mut().ok_or("expected object record")?;
        if let Some(defaults) = &defaults {
            for (key, value) in defaults {
                record.entry(key).or_insert_with(|| value.clone());
            }
        }
        if let Some(table) = &facets
            && let Some(facets) = record.get_mut("facets")
        {
            for facet in facets.as_array_mut().ok_or("facets must be an array")? {
                *facet = facet
                    .as_u64()
                    .and_then(|slot| usize::try_from(slot).ok())
                    .and_then(|slot| table.get(slot))
                    .ok_or("invalid facet index")?
                    .clone();
            }
        }
    }
    Ok(value)
}
