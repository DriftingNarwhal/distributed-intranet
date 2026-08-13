//! Tokenisation and normalisation — Search Spec §3.1, §5.
//!
//! Publishing and querying must tokenise **identically**, or a term indexed at
//! publish time is unreachable at query time. That is why one function serves
//! both directions rather than each side having its own.
//!
//! The specs call exact rules implementation-level tuning, so what follows is a
//! deliberate, documented choice rather than a derived requirement: lowercase,
//! split on non-alphanumeric, drop stop words, strip a small set of English
//! suffixes. It is intentionally conservative — over-aggressive stemming
//! collapses distinct terms and makes precise search impossible, and that is far
//! harder to notice than a missing match.

/// Minimum length for a token to be indexed.
///
/// One-character tokens carry almost no discriminating power while appearing in
/// nearly every document, so indexing them costs storage and returns noise.
const MIN_TOKEN_LEN: usize = 2;

/// Very common words that match nearly everything and rank nothing.
const STOP_WORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from", "has", "have", "he",
    "her", "his", "in", "is", "it", "its", "of", "on", "or", "she", "that", "the", "they", "this",
    "to", "was", "were", "will", "with", "you", "your",
];

/// A normalised search term.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Term(String);

impl Term {
    /// Wraps an already-normalised term.
    ///
    /// Prefer [`tokenize`]; this exists for callers reconstructing a term from
    /// storage, where normalisation already happened.
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The term text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Term {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Splits text into normalised terms.
///
/// Returns terms in order of appearance, including repeats — callers count
/// frequencies from this, so deduplicating here would discard the signal
/// relevance ranking depends on.
pub fn tokenize(text: &str) -> Vec<Term> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter_map(|raw| {
            let lowered = raw.to_lowercase();
            if lowered.len() < MIN_TOKEN_LEN || STOP_WORDS.contains(&lowered.as_str()) {
                return None;
            }
            let stemmed = stem(&lowered);
            (stemmed.len() >= MIN_TOKEN_LEN).then_some(Term(stemmed))
        })
        .collect()
}

/// Counts how often each term appears.
pub fn term_frequencies(text: &str) -> std::collections::BTreeMap<Term, u32> {
    let mut counts = std::collections::BTreeMap::new();
    for term in tokenize(text) {
        *counts.entry(term).or_insert(0) += 1;
    }
    counts
}

/// Strips a small set of common English suffixes.
///
/// Deliberately minimal. Aggressive stemming merges words that should stay
/// distinct, and the failure is silent — a query returns confidently wrong
/// results rather than none — so this errs toward under-stemming.
fn stem(word: &str) -> String {
    // Words this short are more likely to be mangled than helped.
    if word.len() <= 3 {
        return word.to_string();
    }

    for suffix in ["ingly", "edly", "ing", "ies", "ed", "es", "s"] {
        if let Some(root) = word.strip_suffix(suffix)
            && root.len() >= 3
        {
            // "ies" -> "y" keeps "libraries" and "library" together.
            if suffix == "ies" {
                return format!("{root}y");
            }
            return root.to_string();
        }
    }
    word.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(text: &str) -> Vec<String> {
        tokenize(text).into_iter().map(|t| t.0).collect()
    }

    #[test]
    fn tokenisation_lowercases_and_splits_on_punctuation() {
        assert_eq!(
            terms("Hello, World! Rust-lang."),
            vec!["hello", "world", "rust", "lang"]
        );
    }

    #[test]
    fn stop_words_are_dropped() {
        assert_eq!(terms("the quick brown fox"), vec!["quick", "brown", "fox"]);
    }

    #[test]
    fn very_short_tokens_are_dropped() {
        assert_eq!(terms("a b cd"), vec!["cd"]);
    }

    #[test]
    fn publishing_and_querying_tokenise_identically() {
        // The property that makes indexed terms reachable at all: if these ever
        // diverge, a published term silently becomes unqueryable.
        let text = "Distributed Networks and Replication";
        assert_eq!(terms(text), terms(text));
        assert_eq!(terms("networks"), terms("Networks"));
    }

    #[test]
    fn basic_plurals_and_verb_forms_collapse() {
        assert_eq!(terms("network"), terms("networks"));
        assert_eq!(terms("library"), terms("libraries"));
        assert_eq!(terms("publish"), terms("published"));
    }

    #[test]
    fn short_words_are_left_alone() {
        // Words of three characters or fewer are more likely to be mangled than
        // helped, so no suffix rule applies to them.
        assert_eq!(terms("gas"), vec!["gas"]);
        assert_eq!(terms("bed"), vec!["bed"]);
        assert_eq!(terms("was is as"), Vec::<String>::new());
    }

    #[test]
    fn stripping_never_leaves_a_stub_root() {
        // "ties" reaches "tie" and stops rather than continuing to "ti": a root
        // shorter than three characters is rejected, which is what keeps
        // aggressive rules from grinding words down to noise.
        assert_eq!(terms("ties"), vec!["tie"]);
        assert_eq!(terms("tie"), vec!["tie"]);
    }

    #[test]
    fn known_limitation_naive_suffix_stripping_merges_some_unrelated_words() {
        // Pinned rather than hidden. A suffix stripper with no dictionary cannot
        // tell a plural from a word that merely ends in "s", so "news" collapses
        // onto "new". The cost is occasional false matches; the alternative is
        // shipping a full stemmer, which the specs explicitly leave as tuning.
        // This test exists so the behaviour is a recorded decision rather than a
        // surprise, and so replacing the stemmer has a visible checkpoint.
        assert_eq!(terms("news"), terms("new"));
    }

    #[test]
    fn distinct_words_are_not_collapsed() {
        assert_ne!(terms("storage"), terms("store"));
        assert_ne!(terms("relay"), terms("replay"));
    }

    #[test]
    fn frequencies_are_counted() {
        let counts = term_frequencies("relay relay relay mesh");
        assert_eq!(counts[&Term::new("relay")], 3);
        assert_eq!(counts[&Term::new("mesh")], 1);
    }

    #[test]
    fn empty_and_punctuation_only_text_yields_nothing() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("!!! ... ???").is_empty());
    }

    #[test]
    fn non_ascii_text_is_tokenised_rather_than_discarded() {
        // Alphanumeric splitting is Unicode-aware, so non-English content is
        // indexed rather than silently dropped.
        assert_eq!(terms("café naïve"), vec!["café", "naïve"]);
        assert_eq!(terms("日本語 テスト"), vec!["日本語", "テスト"]);
    }
}
