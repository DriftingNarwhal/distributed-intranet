//! Canonical, length-prefixed byte encoding.
//!
//! # Why this exists rather than a serialization library
//!
//! Several guarantees in this protocol require that two independent nodes, given
//! the same logical value, produce *byte-identical* output:
//!
//! - Governance log entry hashes must match across nodes, or the lower-entry-hash
//!   fork tie-break (Core Protocol Spec §2.7.1, point 1) picks different winners on
//!   different nodes and the log stops converging.
//! - The same-version mutable pointer tie-break (Storage Spec §2.2) has the same
//!   requirement, since it reuses that rule.
//! - Concurrent DEK re-wraps by different members must produce byte-identical
//!   `DekWrapping` records "with no conflict to resolve" (Storage Spec §5.3).
//!
//! A general-purpose format (JSON, and most binary formats used with derive macros)
//! makes that a property of field ordering, map iteration order, float formatting,
//! and library version — none of which the protocol controls. Encoding is therefore
//! explicit and hand-written per type, so that "what bytes does this value hash to"
//! is answerable by reading one function.
//!
//! # Framing rule
//!
//! Every variable-length field is length-prefixed with a `u64` length, and every
//! sum type is prefixed with a discriminant tag. This makes the encoding injective:
//! no two distinct logical values can produce the same byte string, which is what
//! stops a `("ab", "c")` / `("a", "bc")` style collision from being signed as
//! equivalent.

/// Builder for canonical byte encodings.
///
/// Fields are appended in a fixed, hand-written order per type. See the module
/// docs for why the ordering is explicit rather than derived.
#[derive(Debug, Default, Clone)]
pub struct Enc(Vec<u8>);

impl Enc {
    /// Starts an empty encoding.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Starts an encoding with a domain-separation tag.
    ///
    /// Every distinct signable or hashable type in this protocol begins with its
    /// own tag, so that a value of one type can never be reinterpreted as a value
    /// of another under the same key — a signature over a `Ballot` must not also
    /// verify as a signature over a `LogEntry`.
    pub fn domain(tag: &str) -> Self {
        let mut e = Self::new();
        e.str(tag);
        e
    }

    /// Appends a single byte, unframed (fixed width).
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    /// Appends a `u32` in big-endian order, unframed (fixed width).
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends a `u64` in big-endian order, unframed (fixed width).
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends an `i64` in big-endian order, unframed (fixed width).
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Appends a boolean as a single `0x00` / `0x01` byte.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    /// Appends a variant discriminant tag.
    ///
    /// Sum types encode their discriminant before their payload so that two
    /// variants carrying structurally identical payloads never collide.
    pub fn variant(&mut self, discriminant: u8) -> &mut Self {
        self.u8(discriminant)
    }

    /// Appends a length-prefixed byte string.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u64(b.len() as u64);
        self.0.extend_from_slice(b);
        self
    }

    /// Appends a length-prefixed UTF-8 string.
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// Appends a fixed-width byte array without a length prefix.
    ///
    /// Safe to leave unframed precisely because the width is a compile-time
    /// constant, so it cannot absorb or yield bytes to an adjacent field.
    pub fn fixed<const N: usize>(&mut self, b: &[u8; N]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }

    /// Appends an optional value, tagged present/absent.
    pub fn option<T>(&mut self, v: Option<&T>, f: impl FnOnce(&mut Self, &T)) -> &mut Self {
        match v {
            None => {
                self.u8(0);
            }
            Some(inner) => {
                self.u8(1);
                f(self, inner);
            }
        }
        self
    }

    /// Appends a count-prefixed sequence.
    ///
    /// Callers are responsible for passing an iterator with deterministic order —
    /// in practice every call site iterates a `BTreeMap`/`BTreeSet`, which is why
    /// governance state uses ordered collections throughout rather than hash maps.
    pub fn seq<T>(
        &mut self,
        items: impl ExactSizeIterator<Item = T>,
        mut f: impl FnMut(&mut Self, T),
    ) -> &mut Self {
        self.u64(items.len() as u64);
        for item in items {
            f(self, item);
        }
        self
    }

    /// Consumes the builder, returning the encoded bytes.
    pub fn finish(&self) -> Vec<u8> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefixing_prevents_field_boundary_collisions() {
        // The classic ambiguity: without framing, ("ab","c") and ("a","bc") both
        // encode to "abc" and would produce the same signature.
        let mut a = Enc::new();
        a.str("ab").str("c");
        let mut b = Enc::new();
        b.str("a").str("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn domain_separation_distinguishes_types() {
        let mut ballot = Enc::domain("intranet.ballot.v1");
        ballot.fixed(&[9u8; 32]);
        let mut entry = Enc::domain("intranet.entry.v1");
        entry.fixed(&[9u8; 32]);
        assert_ne!(ballot.finish(), entry.finish());
    }

    #[test]
    fn variants_with_identical_payloads_do_not_collide() {
        let mut add = Enc::new();
        add.variant(0).str("group-a");
        let mut remove = Enc::new();
        remove.variant(1).str("group-a");
        assert_ne!(add.finish(), remove.finish());
    }

    #[test]
    fn option_tagging_distinguishes_absent_from_empty() {
        let mut absent = Enc::new();
        absent.option(None::<&Vec<u8>>, |e, v| {
            e.bytes(v);
        });
        let mut present_empty = Enc::new();
        present_empty.option(Some(&Vec::new()), |e, v| {
            e.bytes(v);
        });
        assert_ne!(absent.finish(), present_empty.finish());
    }

    #[test]
    fn encoding_is_deterministic_across_builds() {
        let build = || {
            let mut e = Enc::domain("t");
            e.u64(7).str("x").seq([1u8, 2, 3].iter(), |e, v| {
                e.u8(*v);
            });
            e.finish()
        };
        assert_eq!(build(), build());
    }
}
