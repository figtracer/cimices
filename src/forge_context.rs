//! Markdown context generation for Foundry property tests.

use bugraph::{Corpus, Graph, Kind, Node, RetrievalMode, TokenCounter};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
};

const TOKEN_MODEL: &str = "gpt-4o";
// Match the reciprocal-rank fusion and category diversity policy used by
// UltraFuzz routing.
const RRF_OFFSET: usize = 0;
const CATEGORY_REPEAT_PENALTY: f64 = 0.15;
// Keep each source-derived checklist entry within the requested two to four lines.
const MAX_DESCRIPTION_SENTENCES: usize = 3;
const MIN_DESCRIPTION_LINES: usize = 2;
const MAX_DESCRIPTION_LINES: usize = 4;
const DESCRIPTION_LINE_WIDTH: usize = 72;
const MAX_DESCRIPTION_CHARS: usize = DESCRIPTION_LINE_WIDTH * MAX_DESCRIPTION_LINES;
const MAX_CONDITION_CHARS: usize = 320;
const MAX_INLINE_CODE_CHARS: usize = 80;
const USAGE: &str = "forge-context CORPUS [--extra EXTRA ...] [--include-findings] BUDGET_TOKENS K TARGET.sol... --out FILE";

struct Options {
    corpus: PathBuf,
    extras: Vec<PathBuf>,
    include_findings: bool,
    budget_tokens: usize,
    k: usize,
    targets: Vec<PathBuf>,
    output: PathBuf,
}

struct Identifier {
    text: String,
    next_code_byte: Option<u8>,
    in_assembly: bool,
}

pub(super) fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let options = parse_options(args)?;
    let corpus = load_corpus(&options)?;
    let graph = Graph::compile(corpus)?;
    let mut queries = options
        .targets
        .iter()
        .map(|target| target_query(target))
        .collect::<Result<Vec<_>, _>>()?;
    queries.retain(|query| !query.trim().is_empty());
    if queries.is_empty() {
        return Err("target Solidity files contain no supported query signals".into());
    }

    let counter = TokenCounter::for_model(TOKEN_MODEL)?;
    let ranked = fused_ranking(&graph, &queries, options.include_findings);
    let markdown = render_context(&graph, &ranked, &counter, options.budget_tokens, options.k)?;
    fs::write(&options.output, markdown)?;
    Ok(())
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let Some(corpus) = args.first() else {
        return Err(USAGE.into());
    };
    let mut remaining = args[1..].to_vec();
    let mut include_findings = false;
    remaining.retain(|argument| {
        if argument == "--include-findings" {
            include_findings = true;
            false
        } else {
            true
        }
    });

    let mut index = 0;
    let mut extras = Vec::new();
    while remaining
        .get(index)
        .is_some_and(|argument| argument == "--extra")
    {
        index += 1;
        let first_extra = index;
        while let Some(argument) = remaining.get(index) {
            if argument.starts_with("--") || argument.parse::<usize>().is_ok() {
                break;
            }
            extras.push(PathBuf::from(argument));
            index += 1;
        }
        if index == first_extra {
            return Err(format!(
                "--extra requires at least one corpus path\nUsage: {USAGE}"
            ));
        }
    }

    let budget_tokens = parse_positive(remaining.get(index), "BUDGET_TOKENS")?;
    index += 1;
    let k = parse_positive(remaining.get(index), "K")?;
    index += 1;

    let Some(output_index) = remaining[index..]
        .iter()
        .position(|argument| argument == "--out")
    else {
        return Err(format!("forge-context requires --out FILE\nUsage: {USAGE}"));
    };
    let targets = remaining[index..index + output_index]
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if targets.is_empty() || targets.iter().any(|target| target.starts_with("--")) {
        return Err(format!(
            "forge-context requires target Solidity files\nUsage: {USAGE}"
        ));
    }
    let output = remaining
        .get(index + output_index + 1)
        .map(PathBuf::from)
        .ok_or_else(|| format!("forge-context requires --out FILE\nUsage: {USAGE}"))?;
    if index + output_index + 2 != remaining.len() {
        return Err(format!(
            "unexpected arguments after --out FILE\nUsage: {USAGE}"
        ));
    }

    Ok(Options {
        corpus: PathBuf::from(corpus),
        extras,
        include_findings,
        budget_tokens,
        k,
        targets,
        output,
    })
}

fn parse_positive(argument: Option<&String>, name: &str) -> Result<usize, String> {
    let value = argument
        .ok_or_else(|| format!("forge-context requires {name}\nUsage: {USAGE}"))?
        .parse::<usize>()
        .map_err(|_| format!("{name} must be a positive integer\nUsage: {USAGE}"))?;
    if value == 0 {
        return Err(format!("{name} must be a positive integer\nUsage: {USAGE}"));
    }
    Ok(value)
}

fn load_corpus(options: &Options) -> Result<Corpus, Box<dyn Error>> {
    let mut revisions = Vec::new();
    let mut sources = Vec::new();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut source_ids = HashSet::new();
    let mut node_ids = HashSet::new();

    for path in std::iter::once(&options.corpus).chain(&options.extras) {
        let bytes = fs::read(path)
            .map_err(|error| format!("cannot read corpus {}: {error}", path.display()))?;
        let corpus = serde_json::from_slice::<Corpus>(&bytes)
            .map_err(|error| format!("cannot parse corpus {}: {error}", path.display()))?;
        if corpus.revision.trim().is_empty() {
            return Err(format!("corpus {} has an empty revision", path.display()).into());
        }
        revisions.push(corpus.revision.clone());
        let corpus = filter_corpus(corpus, options.include_findings);
        for source in corpus.sources {
            if !source_ids.insert(source.id.clone()) {
                return Err(
                    format!("duplicate source ID while combining corpora: {}", source.id).into(),
                );
            }
            sources.push(source);
        }
        for node in corpus.nodes {
            if !node_ids.insert(node.id.clone()) {
                return Err(
                    format!("duplicate node ID while combining corpora: {}", node.id).into(),
                );
            }
            nodes.push(node);
        }
        edges.extend(corpus.edges);
    }

    if nodes.is_empty() {
        return Err(
            "no generic bug classes remain; use --include-findings for audit-derived corpora"
                .into(),
        );
    }
    Ok(Corpus {
        revision: format!("forge-context:{}", revisions.join("+")),
        sources,
        nodes,
        edges,
    })
}

fn filter_corpus(corpus: Corpus, include_findings: bool) -> Corpus {
    let is_owasp = corpus.nodes.iter().any(|node| node.id.starts_with("scwe:"));
    let audit_sources = corpus
        .sources
        .iter()
        .filter(|source| source.id.starts_with("audit:") || source.id.starts_with("bastet:"))
        .map(|source| source.id.clone())
        .collect::<HashSet<_>>();
    let nodes = corpus
        .nodes
        .into_iter()
        .filter(|node| {
            (!is_owasp || node.id.starts_with("scwe:"))
                && (include_findings || !is_protocol_specific(node, &audit_sources))
        })
        .collect::<Vec<_>>();
    let node_ids = nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<HashSet<_>>();
    let source_ids = nodes
        .iter()
        .flat_map(|node| node.sources.iter().cloned())
        .collect::<HashSet<_>>();
    let sources = corpus
        .sources
        .into_iter()
        .filter(|source| source_ids.contains(&source.id))
        .collect();
    let edges = corpus
        .edges
        .into_iter()
        .filter(|edge| node_ids.contains(&edge.from) && node_ids.contains(&edge.to))
        .collect();
    Corpus {
        revision: corpus.revision,
        sources,
        nodes,
        edges,
    }
}

fn is_protocol_specific(node: &Node, audit_sources: &HashSet<String>) -> bool {
    node.kind == Kind::Finding
        || node.id.starts_with("bastet:")
        || node.facets.iter().any(|facet| facet == "dataset:bastet")
        || node
            .sources
            .iter()
            .any(|source| audit_sources.contains(source))
}

fn target_query(path: &Path) -> Result<String, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("cannot read Solidity target {}: {error}", path.display()))?;
    Ok(query_from_source(&source))
}

fn query_from_source(source: &str) -> String {
    let (identifiers, natspec) = solidity_parts(source);
    let mut terms = Vec::new();
    for (index, identifier) in identifiers.iter().enumerate() {
        if !identifier.in_assembly
            && matches!(
                identifier.text.as_str(),
                "contract" | "interface" | "library" | "function" | "error"
            )
            && (identifier.text != "function" || identifier.next_code_byte != Some(b'('))
            && let Some(name) = identifiers.get(index + 1)
            && !name.in_assembly
        {
            push_identifier_terms(&mut terms, &name.text);
        }
        push_notable_terms(&mut terms, &identifier.text);
    }
    terms.extend(natspec);
    terms.join(" ")
}

fn solidity_parts(source: &str) -> (Vec<Identifier>, Vec<String>) {
    let bytes = source.as_bytes();
    let mut identifiers = Vec::new();
    let mut natspec = Vec::new();
    let mut blocks = Vec::new();
    let mut assembly_pending = false;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            if bytes.get(index + 2) == Some(&b'/') {
                let mut comments = String::new();
                loop {
                    let line_end = line_end(bytes, index + 3);
                    comments.push_str(&source[index + 3..line_end]);
                    comments.push('\n');
                    index = line_end.saturating_add(1).min(bytes.len());
                    let mut next = index;
                    while matches!(bytes.get(next), Some(b' ' | b'\t')) {
                        next += 1;
                    }
                    if bytes.get(next) == Some(&b'/')
                        && bytes.get(next + 1) == Some(&b'/')
                        && bytes.get(next + 2) == Some(&b'/')
                    {
                        index = next;
                    } else {
                        break;
                    }
                }
                collect_natspec(&comments, &mut natspec);
            } else {
                index = line_end(bytes, index + 2)
                    .saturating_add(1)
                    .min(bytes.len());
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let is_natspec = bytes.get(index + 2) == Some(&b'*');
            let content_start = index + usize::from(is_natspec) + 2;
            let mut end = content_start;
            while end + 1 < bytes.len() && !(bytes[end] == b'*' && bytes[end + 1] == b'/') {
                end += 1;
            }
            if is_natspec {
                collect_natspec(&source[content_start..end], &mut natspec);
            }
            index = if end + 1 < bytes.len() {
                end + 2
            } else {
                bytes.len()
            };
            continue;
        }
        if matches!(bytes[index], b'\'' | b'"') {
            index = skip_string(bytes, index);
            continue;
        }
        if bytes[index] == b'{' {
            let in_assembly = blocks.last().copied().unwrap_or(false) || assembly_pending;
            blocks.push(in_assembly);
            assembly_pending = false;
            index += 1;
            continue;
        }
        if bytes[index] == b'}' {
            blocks.pop();
            assembly_pending = false;
            index += 1;
            continue;
        }
        if bytes[index] == b';' {
            assembly_pending = false;
            index += 1;
            continue;
        }
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while bytes
                .get(index)
                .is_some_and(|byte| is_identifier_continue(*byte))
            {
                index += 1;
            }
            let text = source[start..index].to_owned();
            let in_assembly = blocks.last().copied().unwrap_or(false);
            if text == "assembly" && !in_assembly {
                assembly_pending = true;
            }
            identifiers.push(Identifier {
                text,
                next_code_byte: next_code_byte(bytes, index),
                in_assembly,
            });
            continue;
        }
        index += 1;
    }
    (identifiers, natspec)
}

fn next_code_byte(bytes: &[u8], mut index: usize) -> Option<u8> {
    while let Some(byte) = bytes.get(index).copied() {
        if byte.is_ascii_whitespace() {
            index += 1;
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index = line_end(bytes, index + 2)
                .saturating_add(1)
                .min(bytes.len());
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
        } else {
            return Some(byte);
        }
    }
    None
}

fn line_end(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| start + offset)
}

fn skip_string(bytes: &[u8], mut index: usize) -> usize {
    let quote = bytes[index];
    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == quote {
            return index + 1;
        } else {
            index += 1;
        }
    }
    index
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn collect_natspec(comment: &str, output: &mut Vec<String>) {
    let mut current = None;
    for raw_line in comment.lines() {
        let line = raw_line.trim().trim_start_matches('*').trim();
        if let Some(text) = natspec_text(line) {
            if text.is_empty() {
                current = None;
            } else {
                output.push(text.to_owned());
                current = Some(output.len() - 1);
            }
        } else if line.starts_with('@') {
            current = None;
        } else if !line.is_empty()
            && let Some(index) = current
        {
            output[index].push(' ');
            output[index].push_str(line);
        }
    }
}

fn natspec_text(line: &str) -> Option<&str> {
    for tag in ["@notice", "@dev", "@param", "@return"] {
        let Some(rest) = line.strip_prefix(tag) else {
            continue;
        };
        if rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace) {
            return Some(rest.trim());
        }
    }
    None
}

fn push_identifier_terms(terms: &mut Vec<String>, identifier: &str) {
    terms.push(identifier.to_owned());
    terms.extend(split_identifier(identifier));
}

fn split_identifier(identifier: &str) -> Vec<String> {
    identifier
        .split('_')
        .flat_map(split_camel_case)
        .filter(|term| !term.is_empty() && *term != identifier)
        .collect()
}

fn split_camel_case(identifier: &str) -> Vec<String> {
    let characters = identifier.char_indices().collect::<Vec<_>>();
    let mut start = 0;
    let mut parts = Vec::new();
    for index in 1..characters.len() {
        let (_, previous) = characters[index - 1];
        let (offset, current) = characters[index];
        let next = characters.get(index + 1).map(|(_, character)| *character);
        let boundary = (current.is_ascii_uppercase()
            && (previous.is_ascii_lowercase()
                || previous.is_ascii_uppercase()
                    && next.is_some_and(|character| character.is_ascii_lowercase())))
            || current.is_ascii_digit() != previous.is_ascii_digit();
        if boundary {
            parts.push(identifier[start..offset].to_owned());
            start = offset;
        }
    }
    if start < identifier.len() {
        parts.push(identifier[start..].to_owned());
    }
    parts
}

fn push_notable_terms(terms: &mut Vec<String>, identifier: &str) {
    let normalized = identifier.to_ascii_lowercase();
    if normalized.contains("erc4626") {
        terms.push("ERC 4626".into());
    }
    for keyword in [
        "permit",
        "signature",
        "nonce",
        "oracle",
        "decode",
        "calldata",
        "assembly",
        "delegatecall",
        "initialize",
    ] {
        if normalized.contains(keyword) {
            terms.push(keyword.into());
        }
    }
}

fn fused_ranking(graph: &Graph, queries: &[String], include_findings: bool) -> Vec<String> {
    let mut scores = HashMap::<String, f64>::new();
    for query in queries {
        for (index, hit) in graph
            .rank(query, &[], RetrievalMode::Bm25)
            .into_iter()
            .enumerate()
        {
            *scores.entry(hit.id.to_owned()).or_default() += reciprocal_rank(index + 1);
        }
        if include_findings {
            for (index, hit) in graph
                .rank_findings(query, &[], RetrievalMode::Bm25)
                .into_iter()
                .enumerate()
            {
                *scores.entry(hit.id.to_owned()).or_default() += reciprocal_rank(index + 1);
            }
        }
    }

    let mut candidates = scores.into_iter().collect::<Vec<_>>();
    let mut category_counts = HashMap::<String, usize>::new();
    let mut ranked = Vec::with_capacity(candidates.len());
    while !candidates.is_empty() {
        let mut best = 0;
        for index in 1..candidates.len() {
            let (candidate_id, candidate_score) = &candidates[index];
            let (best_id, best_score) = &candidates[best];
            let candidate_score = adjusted_score(
                *candidate_score,
                category(graph, candidate_id)
                    .and_then(|value| category_counts.get(value))
                    .copied(),
            );
            let best_score = adjusted_score(
                *best_score,
                category(graph, best_id)
                    .and_then(|value| category_counts.get(value))
                    .copied(),
            );
            if candidate_score.total_cmp(&best_score).is_gt()
                || candidate_score.total_cmp(&best_score).is_eq() && candidate_id < best_id
            {
                best = index;
            }
        }
        let (id, _) = candidates.swap_remove(best);
        if let Some(category) = category(graph, &id) {
            *category_counts.entry(category.to_owned()).or_default() += 1;
        }
        ranked.push(id);
    }
    ranked
}

fn reciprocal_rank(rank: usize) -> f64 {
    1.0 / (RRF_OFFSET + rank) as f64
}

fn adjusted_score(score: f64, prior_category_selections: Option<usize>) -> f64 {
    score / (1.0 + CATEGORY_REPEAT_PENALTY * prior_category_selections.unwrap_or_default() as f64)
}

fn category<'a>(graph: &'a Graph, id: &str) -> Option<&'a str> {
    graph.node(id).and_then(|node| {
        node.facets
            .iter()
            .find_map(|facet| facet.strip_prefix("category:"))
    })
}

fn render_context(
    graph: &Graph,
    ranked: &[String],
    counter: &TokenCounter,
    budget_tokens: usize,
    k: usize,
) -> Result<String, String> {
    let mut markdown = "# Bugraph context for forge properties\n\nThis file provides Bugraph context for `forge properties`.\nIt is a checklist of likely failure modes selected from the target Solidity declarations and NatSpec.\nThe target's own documentation still decides correct behavior.\n\n".to_owned();
    if counter.count(&markdown) > budget_tokens {
        return Err("BUDGET_TOKENS is too small for the required context header".into());
    }

    let mut selected = 0;
    for id in ranked {
        if selected == k {
            break;
        }
        let Some(node) = graph.node(id) else {
            continue;
        };
        let previous_length = markdown.len();
        markdown.push_str(&render_class(graph, node));
        if counter.count(&markdown) <= budget_tokens {
            selected += 1;
        } else {
            markdown.truncate(previous_length);
        }
    }
    if selected == 0 && !ranked.is_empty() {
        return Err("BUDGET_TOKENS is too small to include a complete bug class".into());
    }
    Ok(markdown)
}

fn render_class(graph: &Graph, node: &Node) -> String {
    let title = class_title(graph, node);
    let description = class_description(node);
    let condition = key_condition(node, &description);
    let citations = source_citations(graph, node);
    format!(
        "## `{}` — {title}\n\n{description}\n\n**Key condition to test:** {condition}{citations}\n\n",
        node.id
    )
}

fn source_citations(graph: &Graph, node: &Node) -> String {
    let citations = node
        .sources
        .iter()
        .filter_map(|id| {
            graph
                .corpus()
                .sources
                .iter()
                .find(|source| source.id == *id)
        })
        .map(|source| format!("[{}]({})", source.title, source.url))
        .collect::<Vec<_>>();
    if citations.is_empty() {
        String::new()
    } else {
        format!("\n\n**Source:** {}", citations.join("; "))
    }
}

fn class_title(graph: &Graph, node: &Node) -> String {
    if let Some(number) = node.id.strip_prefix("scwe:") {
        let prefix = format!("SCWE-{number}:");
        if let Some(source) = node.sources.iter().find_map(|id| {
            graph
                .corpus()
                .sources
                .iter()
                .find(|source| source.id == *id)
        }) {
            let title = source
                .title
                .strip_prefix(&prefix)
                .unwrap_or(&source.title)
                .trim();
            if !title.is_empty() {
                return clean_markdown(title);
            }
        }
    }
    let summary = clean_markdown(&node.summary);
    summary
        .split_once(": ")
        .map_or(summary.clone(), |(title, _)| title.to_owned())
}

fn class_description(node: &Node) -> String {
    let source = if node.id.starts_with("scwe:") {
        markdown_section(&node.definition, "Description").unwrap_or_else(|| node.definition.clone())
    } else {
        node.definition.clone()
    };
    let text = clean_markdown(&source);
    let text = if text.is_empty() {
        clean_markdown(&node.summary)
    } else {
        text
    };
    let lines = sentences(&text)
        .into_iter()
        .take(MAX_DESCRIPTION_SENTENCES)
        .collect::<Vec<_>>();
    let description = if lines.is_empty() {
        node.id.clone()
    } else {
        lines.join(" ")
    };
    wrap_description(&truncate_chars(&description, MAX_DESCRIPTION_CHARS))
}

fn markdown_section(definition: &str, section: &str) -> Option<String> {
    let heading = format!("## {section}");
    let mut in_section = false;
    let mut lines = Vec::new();
    for line in definition.lines() {
        let trimmed = line.trim();
        if trimmed == heading {
            in_section = true;
            continue;
        }
        if in_section && trimmed.starts_with("## ") {
            break;
        }
        if in_section {
            lines.push(trimmed);
        }
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

fn wrap_description(text: &str) -> String {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut omitted = false;
    for word in text.split_whitespace() {
        let width = line.chars().count() + usize::from(!line.is_empty()) + word.chars().count();
        if width > DESCRIPTION_LINE_WIDTH && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
            if lines.len() == MAX_DESCRIPTION_LINES {
                omitted = true;
                break;
            }
            line = String::new();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() && lines.len() < MAX_DESCRIPTION_LINES {
        lines.push(line);
    }
    if omitted {
        let last = lines.last_mut().expect("an omitted description has a line");
        if !last.ends_with('…') {
            last.push('…');
        }
    }
    if lines.len() == 1 {
        let words = lines[0].split_whitespace().collect::<Vec<_>>();
        if words.len() > 1 {
            let split = words.len().div_ceil(2);
            lines = vec![words[..split].join(" "), words[split..].join(" ")];
        } else {
            lines.push(lines[0].clone());
        }
    }
    while lines.len() < MIN_DESCRIPTION_LINES {
        lines.push(text.to_owned());
    }
    lines.join("  \n")
}

fn clean_markdown(text: &str) -> String {
    let mut in_code = false;
    let mut lines = Vec::new();
    for raw_line in text.lines() {
        if raw_line.starts_with("    ") || raw_line.starts_with('\t') {
            continue;
        }
        let mut line = raw_line.trim();
        if line.starts_with("```") || line.starts_with("~~~") {
            in_code = !in_code;
            continue;
        }
        if in_code || line.is_empty() {
            continue;
        }
        line = line.trim_start_matches(['#', '-', '*', '>', ' ']).trim();
        if !line.is_empty() {
            lines.push(strip_inline_code(line).replace("**", "").replace("__", ""));
        }
    }
    lines
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn strip_inline_code(text: &str) -> String {
    let mut output = String::new();
    let mut code_start = None;
    for (index, character) in text.char_indices() {
        if character != '`' {
            if code_start.is_none() {
                output.push(character);
            }
            continue;
        }
        if let Some(start) = code_start {
            let snippet = &text[start..index];
            if snippet.chars().count() <= MAX_INLINE_CODE_CHARS {
                output.push_str(snippet);
            }
            code_start = None;
        } else {
            code_start = Some(index + character.len_utf8());
        }
    }
    output
}

fn sentences(text: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut start = 0;
    for (index, character) in text.char_indices() {
        if !matches!(character, '.' | '!' | '?') {
            continue;
        }
        let end = index + character.len_utf8();
        if text[end..].chars().next().is_none_or(char::is_whitespace) {
            let sentence = text[start..end].trim();
            if !sentence.is_empty() {
                output.push(sentence.to_owned());
            }
            start = end;
        }
    }
    let rest = text[start..].trim();
    if !rest.is_empty() {
        output.push(rest.to_owned());
    }
    output
}

fn key_condition(node: &Node, description: &str) -> String {
    let description = description.split_whitespace().collect::<Vec<_>>().join(" ");
    let detail = sentences(&description)
        .into_iter()
        .next()
        .unwrap_or(description);
    if let Some(scope) = node
        .applicability
        .first()
        .map(|scope| clean_markdown(scope))
        .filter(|scope| !scope.is_empty())
    {
        let condition = if scope == detail {
            scope
        } else {
            format!("{scope} {detail}")
        };
        return truncate_chars(&condition, MAX_CONDITION_CHARS);
    }
    if let Some(remediation) = markdown_section(&node.definition, "Remediation") {
        let remediation = clean_markdown(&remediation);
        if let Some(condition) = sentences(&remediation).into_iter().next() {
            return truncate_chars(&condition, MAX_CONDITION_CHARS);
        }
    }
    truncate_chars(&format!("Review whether: {detail}"), MAX_CONDITION_CHARS)
}

fn truncate_chars(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let end = text
        .char_indices()
        .nth(limit)
        .map_or(text.len(), |(offset, _)| offset);
    let prefix = &text[..end];
    let boundary = prefix.rfind(char::is_whitespace).unwrap_or(prefix.len());
    format!("{}…", prefix[..boundary].trim_end())
}

#[cfg(test)]
mod tests {
    use super::query_from_source;

    #[test]
    fn query_uses_supported_solidity_signals_and_ignores_non_declarations() {
        let query = query_from_source(
            r#"
            contract PermitVault {}
            library OracleLibrary {}
            interface ICodec {}

            error InvalidSignatureNonce();

            /// @notice Decode calldata with an oracle signature and nonce.
            /// @dev Initialize the permit verifier.
            /// @param payload Encoded calldata.
            /// @return valid Whether decode succeeds.
            function permit(bytes calldata payload) external returns (bool valid);

            function initialize() external;
            function (IgnoredFunctionType calldata) external callback;
            function /* type */ (CommentedFunctionType calldata) external commentedCallback;

            function usesAssembly() external {
                assembly {
                    function ignoredYul() {}
                    let success := delegatecall(gas(), address(), 0, 0, 0, 0)
                }
            }

            // error IgnoredComment();
            string constant IGNORE = "delegatecall";
            "#,
        );

        for signal in [
            "PermitVault",
            "OracleLibrary",
            "ICodec",
            "InvalidSignatureNonce",
            "permit",
            "initialize",
            "Decode calldata with an oracle signature and nonce.",
            "delegatecall",
        ] {
            assert!(query.contains(signal), "missing {signal:?} in {query:?}");
        }
        assert!(!query.contains("IgnoredFunctionType"));
        assert!(!query.contains("CommentedFunctionType"));
        assert!(!query.contains("ignoredYul"));
        assert!(!query.contains("IgnoredComment"));
    }
}
