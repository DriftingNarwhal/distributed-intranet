//! Decoder mirroring [`Enc`](crate::Enc), for values that travel over a wire.
//!
//! # Why this exists, and why it is not the inverse of `Enc` in the way it looks
//!
//! `Enc` is a *hashing* encoder: nothing ever needed to read its output back,
//! because both sides recompute it from a value they already hold. Gossip
//! changes that — a governance log entry arrives as bytes from a peer, and
//! something has to turn those bytes into a `LogEntry`.
//!
//! The obvious risk in adding a decoder is that the wire format becomes a second
//! representation that can silently disagree with the canonical one. A decoder
//! bug that swaps two fields, or reads a variant tag as a different variant,
//! would produce a *valid-looking* entry that is not the entry the sender
//! signed. Since entry hashes drive the fork-choice tie-break (Core Protocol
//! Spec §2.7.1), a node that decoded differently would compute a different hash
//! and quietly stop converging — the exact failure this project's hand-written
//! encoding exists to prevent.
//!
//! The defence is not decoder correctness. It is that **nothing trusts a decoded
//! value**: a decoded entry is re-hashed and its signature re-verified against
//! that hash before it is used for anything. Any disagreement between encoder
//! and decoder therefore surfaces as a rejected entry rather than as divergence.
//! See `intranet-governance`'s `wire` module, which is where that check lives.
//!
//! # Hostile input
//!
//! Unlike `Enc`, this reads bytes chosen by someone else. Every length and count
//! is checked against the bytes actually remaining before anything is allocated,
//! so a peer cannot make a node reserve gigabytes by claiming a `u64::MAX`-long
//! sequence. That check is what makes the difference between a parse error and a
//! memory-exhaustion vector.

use std::fmt;

/// Why decoding failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended before a field was complete.
    UnexpectedEnd {
        /// How many bytes the field needed.
        needed: usize,
        /// How many remained.
        remaining: usize,
    },
    /// A length or count field exceeded the bytes actually present.
    ///
    /// Separate from [`Self::UnexpectedEnd`] because it is the signature of
    /// hostile or corrupt input rather than of a truncated stream.
    ImplausibleLength {
        /// The length claimed by the input.
        claimed: u64,
        /// The bytes actually remaining.
        remaining: usize,
    },
    /// A sum type carried a discriminant this build does not know.
    UnknownVariant {
        /// What the value is called, for the error message.
        type_name: &'static str,
        /// The unrecognized discriminant.
        discriminant: u8,
    },
    /// A boolean was neither `0x00` nor `0x01`.
    ///
    /// Rejected rather than coerced: accepting `0x02` as true would mean two
    /// distinct byte strings decode to the same value, which breaks the
    /// injectivity the encoding depends on.
    InvalidBool(u8),
    /// A string field was not valid UTF-8.
    InvalidUtf8,
    /// The domain-separation tag did not match the expected one.
    WrongDomain {
        /// The tag the caller expected.
        expected: &'static str,
    },
    /// Bytes remained after the value was fully decoded.
    ///
    /// Rejected because trailing bytes mean the sender and receiver disagree
    /// about the shape of what was sent, and because ignoring them would let the
    /// same logical value be carried by more than one byte string.
    TrailingBytes {
        /// How many bytes were left over.
        remaining: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd { needed, remaining } => {
                write!(f, "input ended early: needed {needed} bytes, {remaining} remain")
            }
            Self::ImplausibleLength { claimed, remaining } => write!(
                f,
                "length {claimed} exceeds the {remaining} bytes remaining"
            ),
            Self::UnknownVariant {
                type_name,
                discriminant,
            } => write!(f, "unknown {type_name} discriminant {discriminant}"),
            Self::InvalidBool(v) => write!(f, "invalid boolean byte {v:#04x}"),
            Self::InvalidUtf8 => write!(f, "string field was not valid UTF-8"),
            Self::WrongDomain { expected } => {
                write!(f, "wrong domain tag, expected '{expected}'")
            }
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing bytes after the decoded value")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Reader for canonical byte encodings produced by [`Enc`](crate::Enc).
///
/// Every method mirrors the `Enc` method of the same name, in the same order, so
/// that an encode and decode pair can be read side by side and checked against
/// each other by eye. That symmetry is deliberate: it is the only practical
/// review technique for a hand-written codec.
#[derive(Debug)]
pub struct Dec<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    /// Starts reading a value.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Starts reading a value, requiring a matching domain-separation tag.
    ///
    /// The mirror of [`Enc::domain`](crate::Enc::domain), and load-bearing for
    /// the same reason: it stops bytes written as one type from being read as
    /// another.
    pub fn domain(bytes: &'a [u8], tag: &'static str) -> Result<Self, DecodeError> {
        let mut dec = Self::new(bytes);
        if dec.str()? != tag {
            return Err(DecodeError::WrongDomain { expected: tag });
        }
        Ok(dec)
    }

    /// How many bytes remain unread.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::UnexpectedEnd {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Reads a single byte.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// Reads a big-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    /// Reads a big-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }

    /// Reads a big-endian `i64`.
    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }

    /// Reads a boolean, rejecting any byte other than `0x00` or `0x01`.
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(DecodeError::InvalidBool(other)),
        }
    }

    /// Reads a variant discriminant tag.
    pub fn variant(&mut self) -> Result<u8, DecodeError> {
        self.u8()
    }

    /// Reads a length claimed by the input, checked against what is actually
    /// present.
    ///
    /// The check is the whole point. `bytes` and `seq` both begin with an
    /// attacker-chosen `u64`, and both would otherwise be an invitation to
    /// allocate on the strength of a number a peer made up.
    fn length(&mut self) -> Result<usize, DecodeError> {
        let claimed = self.u64()?;
        if claimed > self.remaining() as u64 {
            return Err(DecodeError::ImplausibleLength {
                claimed,
                remaining: self.remaining(),
            });
        }
        Ok(claimed as usize)
    }

    /// Reads a length-prefixed byte string.
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.length()?;
        self.take(len)
    }

    /// Reads a length-prefixed UTF-8 string.
    pub fn str(&mut self) -> Result<&'a str, DecodeError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| DecodeError::InvalidUtf8)
    }

    /// Reads a fixed-width byte array.
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    /// Reads an optional value.
    ///
    /// Generic over the closure's error type so that a caller decoding a richer
    /// type can raise its own errors from inside a sequence or an option —
    /// `intranet-governance`'s wire codec rejects off-curve public keys that
    /// way. `E: From<DecodeError>` keeps the framing errors reportable without
    /// forcing every caller to unify on one error enum.
    pub fn option<T, E: From<DecodeError>>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        match self.u8().map_err(E::from)? {
            0 => Ok(None),
            1 => Ok(Some(f(self)?)),
            other => Err(E::from(DecodeError::InvalidBool(other))),
        }
    }

    /// Reads a count-prefixed sequence.
    ///
    /// The count is bounded by the bytes remaining before anything is
    /// allocated, on the reasoning that no encodable item occupies zero bytes,
    /// so a sequence can never be longer than the input carrying it. Without
    /// that, a peer sending nine bytes could ask for a `u64::MAX`-element
    /// allocation.
    pub fn seq<T, E: From<DecodeError>>(
        &mut self,
        mut f: impl FnMut(&mut Self) -> Result<T, E>,
    ) -> Result<Vec<T>, E> {
        let count = self.length().map_err(E::from)?;
        let mut items = Vec::new();
        for _ in 0..count {
            items.push(f(self)?);
        }
        Ok(items)
    }

    /// Finishes decoding, requiring the input to be fully consumed.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() > 0 {
            return Err(DecodeError::TrailingBytes {
                remaining: self.remaining(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Enc;

    #[test]
    fn every_enc_primitive_round_trips() {
        let mut e = Enc::domain("intranet.test.v1");
        e.u8(7)
            .u32(70_000)
            .u64(1 << 40)
            .i64(-5)
            .bool(true)
            .variant(3)
            .bytes(b"hello")
            .str("wide \u{2014} string")
            .fixed(&[9u8; 32])
            .option(Some(&4u8), |e, v| {
                e.u8(*v);
            })
            .seq([1u8, 2, 3].iter(), |e, v| {
                e.u8(*v);
            });
        let encoded = e.finish();

        let mut d = Dec::domain(&encoded, "intranet.test.v1").unwrap();
        assert_eq!(d.u8().unwrap(), 7);
        assert_eq!(d.u32().unwrap(), 70_000);
        assert_eq!(d.u64().unwrap(), 1 << 40);
        assert_eq!(d.i64().unwrap(), -5);
        assert!(d.bool().unwrap());
        assert_eq!(d.variant().unwrap(), 3);
        assert_eq!(d.bytes().unwrap(), b"hello");
        assert_eq!(d.str().unwrap(), "wide \u{2014} string");
        assert_eq!(d.fixed::<32>().unwrap(), [9u8; 32]);
        assert_eq!(d.option(|d| d.u8()).unwrap(), Some(4));
        assert_eq!(d.seq(|d| d.u8()).unwrap(), vec![1, 2, 3]);
        d.finish().unwrap();
    }

    #[test]
    fn a_wrong_domain_tag_is_refused() {
        let mut e = Enc::domain("intranet.ballot.v1");
        e.fixed(&[1u8; 32]);
        let encoded = e.finish();

        // The decoder half of the property `Enc::domain` exists to provide:
        // bytes written as one type must not be readable as another.
        assert_eq!(
            Dec::domain(&encoded, "intranet.entry.v1").unwrap_err(),
            DecodeError::WrongDomain {
                expected: "intranet.entry.v1"
            }
        );
    }

    #[test]
    fn an_absurd_sequence_count_does_not_allocate() {
        // A peer sending a count of `u64::MAX` and no items must get a parse
        // error rather than an allocation attempt. This is the difference
        // between a malformed message and a remote memory-exhaustion vector,
        // and it is why `seq` checks the count before building the vector.
        let mut e = Enc::new();
        e.u64(u64::MAX);
        let encoded = e.finish();

        let mut d = Dec::new(&encoded);
        assert_eq!(
            d.seq(|d| d.u8()).unwrap_err(),
            DecodeError::ImplausibleLength {
                claimed: u64::MAX,
                remaining: 0
            }
        );
    }

    #[test]
    fn an_absurd_byte_length_does_not_allocate() {
        let mut e = Enc::new();
        e.u64(1 << 60);
        let encoded = e.finish();

        let mut d = Dec::new(&encoded);
        assert!(matches!(
            d.bytes().unwrap_err(),
            DecodeError::ImplausibleLength { .. }
        ));
    }

    #[test]
    fn a_non_canonical_boolean_is_refused() {
        // `0x02` would be a second byte string decoding to `true`, which breaks
        // the injectivity the whole encoding rests on.
        let mut e = Enc::new();
        e.u8(2);
        let encoded = e.finish();

        assert_eq!(
            Dec::new(&encoded).bool().unwrap_err(),
            DecodeError::InvalidBool(2)
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut e = Enc::new();
        e.u8(1).u8(2);
        let encoded = e.finish();

        let mut d = Dec::new(&encoded);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(
            d.finish().unwrap_err(),
            DecodeError::TrailingBytes { remaining: 1 }
        );
    }

    #[test]
    fn truncation_is_reported_as_an_early_end() {
        let mut e = Enc::new();
        e.u32(5);
        let mut encoded = e.finish();
        encoded.pop();

        assert!(matches!(
            Dec::new(&encoded).u32().unwrap_err(),
            DecodeError::UnexpectedEnd { needed: 4, remaining: 3 }
        ));
    }
}
