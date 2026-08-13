//! What gets indexed — Search Spec §2.
//!
//! Two tiers, and the distinction is deliberate:
//!
//! - **Default metadata** ([`ContentMetadata`]) accompanies every publish of
//!   every content type and is indexed automatically. No publisher action is
//!   required beyond publishing.
//! - **An opt-in index document** ([`IndexDocument`]) exposes richer structured
//!   fields for publishers who want them.
//!
//! # Structured, never a scrape
//!
//! A publisher explicitly maps what it wants searchable into title, tags, and
//! body text. Nothing is automatically extracted from arbitrary content. That
//! gives field-level control: a wiki can expose a page's rendered text while
//! withholding editor notes stored alongside it. An automatic scrape could not
//! make that distinction, and the failure would be a privacy leak the publisher
//! never agreed to.

use crate::SearchError;
use intranet_crypto::{Enc, Signature};
use intranet_governance::PointerId;
use intranet_identity::{PerNetworkIdentity, PerNetworkIdentityId};

/// Domain tag for index document signatures.
const DOCUMENT_DOMAIN: &str = "intranet.index-document.v1";

/// Which field a term matched, for relevance weighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    /// The content's title.
    Title,
    /// An explicit keyword tag.
    Tag,
    /// The content's description.
    Description,
    /// Searchable body text.
    Body,
}

impl Field {
    /// Relevance weight for a match in this field.
    ///
    /// Title and tag matches are deliberate acts of description by the
    /// publisher, so they say more about what content *is* than an incidental
    /// body occurrence. **Flagged: the specs call exact ranking
    /// implementation-level tuning; these weights are a choice, not a
    /// requirement.**
    pub fn weight(self) -> f64 {
        match self {
            Self::Title => 3.0,
            Self::Tag => 2.5,
            Self::Description => 1.5,
            Self::Body => 1.0,
        }
    }

    pub(crate) fn discriminant(self) -> u8 {
        match self {
            Self::Title => 0,
            Self::Tag => 1,
            Self::Description => 2,
            Self::Body => 3,
        }
    }
}

/// Minimal descriptive metadata carried by every publish — §2.1.
///
/// Applies uniformly across content types: an app bundle's name and
/// description, a text page, an image. Everything published has some minimal
/// describable identity, and all of it is indexed by default.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentMetadata {
    /// Human-readable title.
    pub title: String,
    /// Short description.
    pub description: String,
}

impl ContentMetadata {
    /// Builds metadata.
    pub fn new(title: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
        }
    }

    /// Whether this metadata carries anything indexable.
    ///
    /// Empty metadata is permitted rather than rejected: content can be
    /// legitimately unnamed, and refusing to publish it would make indexing a
    /// gate on publishing, which it must never be.
    pub fn is_empty(&self) -> bool {
        self.title.trim().is_empty() && self.description.trim().is_empty()
    }
}

/// Optional richer searchable content — §2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDocument {
    /// The pointer this document describes.
    pub pointer_id: PointerId,
    /// Searchable title, which may restate or extend the default metadata's.
    pub title: String,
    /// Searchable keyword tags.
    pub tags: Vec<String>,
    /// Searchable plaintext body.
    ///
    /// The publisher extracts and provides this explicitly. It is never derived
    /// automatically from content, which is what keeps indexing opt-in at the
    /// field level rather than an all-or-nothing scrape.
    pub body_text: String,
    /// Who published it.
    pub publisher_identity: PerNetworkIdentityId,
    /// The publisher's signature.
    pub signature: Signature,
}

impl IndexDocument {
    /// Creates and signs an index document.
    pub fn create(
        publisher: &PerNetworkIdentity,
        pointer_id: PointerId,
        title: impl Into<String>,
        tags: Vec<String>,
        body_text: impl Into<String>,
    ) -> Self {
        let title = title.into();
        let body_text = body_text.into();
        let publisher_id = publisher.id();
        let payload = Self::payload(&pointer_id, &title, &tags, &body_text, &publisher_id);
        Self {
            pointer_id,
            title,
            tags,
            body_text,
            publisher_identity: publisher_id,
            signature: publisher.sign(&payload),
        }
    }

    /// Verifies the publisher's signature.
    pub fn verify(&self) -> Result<(), SearchError> {
        let payload = Self::payload(
            &self.pointer_id,
            &self.title,
            &self.tags,
            &self.body_text,
            &self.publisher_identity,
        );
        self.publisher_identity
            .verifying_key()
            .verify(&payload, &self.signature)
            .map_err(|_| SearchError::BadSignature)
    }

    fn payload(
        pointer_id: &PointerId,
        title: &str,
        tags: &[String],
        body_text: &str,
        publisher: &PerNetworkIdentityId,
    ) -> Enc {
        let mut e = Enc::domain(DOCUMENT_DOMAIN);
        e.fixed(pointer_id.as_bytes()).str(title);
        e.seq(tags.iter(), |e, tag| {
            e.str(tag);
        });
        e.str(body_text);
        publisher.encode(&mut e);
        e
    }
}

/// Everything indexable about one publish.
///
/// Bundles the always-present metadata with the optional rich document, so the
/// posting builder has a single input regardless of whether a publisher opted
/// in to richer indexing.
#[derive(Debug, Clone)]
pub struct IndexableContent<'a> {
    /// The pointer being indexed.
    pub pointer_id: PointerId,
    /// Metadata every publish carries.
    pub metadata: &'a ContentMetadata,
    /// Richer fields, if the publisher provided them.
    pub document: Option<&'a IndexDocument>,
}

impl IndexableContent<'_> {
    /// Field-tagged text to be indexed, in weight order.
    pub(crate) fn fields(&self) -> Vec<(Field, &str)> {
        let mut fields = vec![
            (Field::Title, self.metadata.title.as_str()),
            (Field::Description, self.metadata.description.as_str()),
        ];
        if let Some(document) = self.document {
            fields.push((Field::Title, document.title.as_str()));
            fields.push((Field::Body, document.body_text.as_str()));
            for tag in &document.tags {
                fields.push((Field::Tag, tag.as_str()));
            }
        }
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intranet_identity::{MasterSeed, NetworkId};

    fn publisher() -> PerNetworkIdentity {
        MasterSeed::from_entropy([2u8; 32])
            .identity_for(&NetworkId::from_bytes([1u8; 32]))
            .unwrap()
    }

    #[test]
    fn an_index_document_round_trips() {
        let document = IndexDocument::create(
            &publisher(),
            PointerId::from_bytes([7u8; 32]),
            "Replication",
            vec!["storage".into(), "durability".into()],
            "How replicas are placed.",
        );
        assert!(document.verify().is_ok());
    }

    #[test]
    fn tampering_with_indexed_fields_breaks_the_signature() {
        // Keyword stuffing after the fact must not be possible.
        let mut document = IndexDocument::create(
            &publisher(),
            PointerId::from_bytes([7u8; 32]),
            "Replication",
            vec!["storage".into()],
            "body",
        );
        document.tags.push("unrelated-popular-term".into());
        assert_eq!(document.verify(), Err(SearchError::BadSignature));
    }

    #[test]
    fn title_and_tag_matches_outweigh_body_matches() {
        assert!(Field::Title.weight() > Field::Body.weight());
        assert!(Field::Tag.weight() > Field::Body.weight());
        assert!(Field::Description.weight() > Field::Body.weight());
    }

    #[test]
    fn metadata_alone_is_indexable_without_an_index_document() {
        let metadata = ContentMetadata::new("A Title", "A description");
        let content = IndexableContent {
            pointer_id: PointerId::from_bytes([1u8; 32]),
            metadata: &metadata,
            document: None,
        };
        let fields = content.fields();
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().any(|(f, _)| *f == Field::Title));
    }

    #[test]
    fn empty_metadata_is_permitted() {
        // Indexing must never become a gate on publishing.
        assert!(ContentMetadata::default().is_empty());
        assert!(!ContentMetadata::new("x", "").is_empty());
    }

    #[test]
    fn withheld_fields_are_never_indexed() {
        // The field-level control that structured indexing exists to provide: a
        // publisher's private notes stay unindexed because they were never
        // mapped into body_text, not because anything filtered them out.
        let document = IndexDocument::create(
            &publisher(),
            PointerId::from_bytes([7u8; 32]),
            "Public Page",
            vec![],
            "the rendered page text",
        );
        let metadata = ContentMetadata::new("Public Page", "public summary");
        let content = IndexableContent {
            pointer_id: document.pointer_id,
            metadata: &metadata,
            document: Some(&document),
        };

        let indexed: String = content
            .fields()
            .iter()
            .map(|(_, text)| *text)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!indexed.contains("editor note"));
        assert!(indexed.contains("rendered page text"));
    }
}
