//! Query resolution and ranking — Search Spec §5.
//!
//! A query is tokenised exactly as publishing tokenises, each term's postings
//! are looked up, and results are merged and ranked locally by the querying
//! node. No query contacts a central search service, and no query crosses a
//! network boundary — the latter is structural rather than enforced, since a
//! term's collection key is derived from the network ID and an index is scoped
//! to one network by construction.

use crate::{LocalIndex, Term, tokenize};
use intranet_governance::PointerId;

/// One ranked result.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    /// The content that matched.
    pub pointer_id: PointerId,
    /// Relevance score; higher ranks earlier.
    pub score: f64,
    /// Which query terms this result matched.
    pub matched_terms: Vec<Term>,
}

/// A query's outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResults {
    /// Results, most relevant first.
    pub results: Vec<SearchResult>,
    /// Whether any matched term's enumeration was known to be incomplete.
    ///
    /// Surfaced rather than hidden so a caller can say "showing partial
    /// results" instead of implying it saw everything. The difference between a
    /// partial answer and a wrong one is only visible if incompleteness is
    /// reported.
    pub incomplete: bool,
}

/// Runs a query against a node's local index.
///
/// Ranking is TF-IDF-shaped, weighted by which field a term matched:
///
/// - **Term frequency** — how often the term appears in the content.
/// - **Inverse document frequency** — a term appearing in nearly everything
///   discriminates poorly, so it contributes less than a rare one.
/// - **Field weight** — a title or tag match reflects a deliberate act of
///   description by the publisher, so it says more than an incidental body
///   occurrence.
///
/// **Flagged: the specs call the exact formula implementation-level tuning.**
/// This is a reasonable default, not a derived requirement.
pub fn search(index: &LocalIndex, query: &str) -> SearchResults {
    let terms = tokenize::tokenize(query);
    if terms.is_empty() {
        return SearchResults {
            results: Vec::new(),
            incomplete: false,
        };
    }

    let corpus = index.len().max(1) as f64;
    let mut scored: std::collections::BTreeMap<PointerId, (f64, Vec<Term>)> =
        std::collections::BTreeMap::new();
    let mut incomplete = false;

    // Deduplicate query terms so repeating a word does not inflate its weight.
    let mut seen_terms = std::collections::BTreeSet::new();

    for term in terms {
        if !seen_terms.insert(term.clone()) {
            continue;
        }
        if index.is_truncated(&term) {
            incomplete = true;
        }

        let postings = index.postings_for(&term);
        if postings.is_empty() {
            continue;
        }

        // Rarer terms discriminate better. The +1 keeps a term present in every
        // document from scoring exactly zero, which would discard an otherwise
        // legitimate single-term query entirely.
        let document_frequency = postings.len() as f64;
        let idf = (corpus / document_frequency).ln() + 1.0;

        for posting in postings {
            let Some(stats) = posting.terms.get(&term) else {
                continue;
            };
            // Sub-linear in frequency: the tenth occurrence of a word says far
            // less than the second, and linear weighting is what lets keyword
            // stuffing dominate a ranking.
            let tf = 1.0 + (f64::from(stats.frequency)).ln();
            let contribution = tf * idf * stats.best_field.weight();

            let entry = scored
                .entry(posting.pointer_id)
                .or_insert_with(|| (0.0, Vec::new()));
            entry.0 += contribution;
            entry.1.push(term.clone());
        }
    }

    let mut results: Vec<SearchResult> = scored
        .into_iter()
        .map(|(pointer_id, (score, matched_terms))| SearchResult {
            pointer_id,
            score,
            matched_terms,
        })
        .collect();

    // Highest score first; ties break on pointer id so a query is reproducible.
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.pointer_id.cmp(&b.pointer_id))
    });

    SearchResults {
        results,
        incomplete,
    }
}
