//! Exact structural probe for one self-describing value, without materializing it.
//!
//! # The idea
//!
//! A normal decode materializes the value; a skip discards it. This module
//! occupies the space in between: it walks the wire format (tags, marker
//! varints, container framing) and reports the **exact** byte length, container
//! count, element count, and maximum nesting depth of the *next value* — with
//! zero allocation and without ever building a value.
//!
//! That makes it a schema-agnostic **preflight probe**: a gateway can decide
//! "should I decode this frame?" from its exact shape before spending any
//! memory on it, route by shape, or hand off a frame whose exact length it
//! already knows.
//!
//! # Consistency contract
//!
//! The probe is deliberately a **byte-exact mirror** of the decoder:
//!
//! - It reads with the same `take` semantics (checked arithmetic, the same
//!   byte limit, the same `UnexpectedEnd` boundary).
//! - Lengths follow the same `IntEncoding` (marker varint under `Variable`,
//!   fixed `u64` under `Fixed`).
//! - It rejects everything the decoder rejects: invalid tags, non-canonical
//!   varints, container terminators in value position, byte/collection/depth
//!   limit violations, and (per `TrailingBytes`) trailing data.
//! - A value accepted by `probe` decodes with the same byte count; a value
//!   rejected by `probe` is rejected by `deserialize` for the same reason.
//!
//! The drift-guard tests pin this by asserting, over a broad value sweep,
//! that `probe`'s byte count equals the encoder's output length and that
//! acceptance matches `deserialize`.
//!
//! # Example
//!
//! ```
//! use rustbinary::{options, Error};
//!
//! let frame = options().serialize(&vec![1u32, 2, 3]).unwrap();
//! let probe = options().probe(&frame)?;
//! assert_eq!(probe.bytes(), frame.len());
//! assert_eq!(probe.containers(), 1);
//! assert_eq!(probe.elements(), 3);
//! # Ok::<(), rustbinary::Error>(())
//! ```

use crate::canonical::decode_varint_le;
use crate::config::{Config, IntEncoding, TrailingBytes};
use crate::error::{Error, Result};
use crate::tags::{
    MARKER_U128, MARKER_U16, MARKER_U32, MARKER_U64, TAG_ARRAY, TAG_END, TAG_F32, TAG_F64,
    TAG_FALSE, TAG_I128, TAG_I64, TAG_NULL, TAG_OBJECT, TAG_STRING, TAG_TRUE, TAG_U128, TAG_U64,
};

/// Exact structural footprint of one self-describing value.
///
/// Produced by [`Config::probe`]; the metrics are a pure function of the input
/// bytes and the configuration, so two probes of the same frame always agree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Probe {
    bytes: usize,
    containers: u64,
    elements: u64,
    depth: usize,
}

impl Probe {
    /// Exact number of bytes the value occupies in the input.
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Number of array/object containers nested inside the value.
    pub const fn containers(self) -> u64 {
        self.containers
    }

    /// Total entries across every container: array elements plus object
    /// key-value pairs (each pair counts once, matching the decoder's
    /// collection-limit accounting).
    pub const fn elements(self) -> u64 {
        self.elements
    }

    /// Maximum container nesting depth (0 for a scalar value).
    pub const fn depth(self) -> usize {
        self.depth
    }

    /// Whether the value fits an input/work budget of `max_bytes` bytes.
    pub const fn fits_input(self, max_bytes: u64) -> bool {
        (self.bytes as u64) <= max_bytes
    }

    /// Whether the value's nesting fits a depth budget of `max_depth` levels.
    pub const fn fits_depth(self, max_depth: usize) -> bool {
        self.depth <= max_depth
    }

    /// Whether the value fits a [`crate::bounded::Budget`]'s input, work, and
    /// depth limits.
    ///
    /// The probe knows the exact byte count and shape; the budget supplies the
    /// policy. Allocation cannot be decided here (it needs the type's
    /// [`crate::DecodeBounded`] algebra), but input/work/depth are exact.
    #[cfg(feature = "bounded")]
    pub const fn fits_budget(self, budget: crate::bounded::Budget) -> bool {
        (self.bytes as u64) <= budget.max_input()
            && (self.bytes as u64) <= budget.max_work()
            && self.depth <= budget.max_depth()
    }
}

/// Walks one self-describing value and reports its exact structural footprint.
///
/// Allocation-free and side-effect free: the walker holds only the input
/// borrow, a cursor, and counters.
pub fn probe(config: Config, input: &[u8]) -> Result<Probe> {
    let mut walker = Walker {
        input,
        cursor: 0,
        config,
        containers: 0,
        elements: 0,
        depth: 0,
        max_depth: 0,
    };
    walker.value()?;
    if config.trailing == TrailingBytes::Reject && walker.cursor != input.len() {
        return Err(Error::TrailingBytes {
            remaining: input.len() - walker.cursor,
        });
    }
    Ok(Probe {
        bytes: walker.cursor,
        containers: walker.containers,
        elements: walker.elements,
        depth: walker.max_depth,
    })
}

struct Walker<'a> {
    input: &'a [u8],
    cursor: usize,
    config: Config,
    containers: u64,
    elements: u64,
    depth: usize,
    max_depth: usize,
}

impl<'a> Walker<'a> {
    /// Advances `len` bytes with the decoder's exact boundary semantics:
    /// checked arithmetic, the byte limit, and the input boundary.
    fn take(&mut self, len: usize) -> Result<()> {
        let end = self.cursor.checked_add(len).ok_or(Error::UnexpectedEnd)?;
        if let Some(limit) = self.config.limit {
            if end as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        if end > self.input.len() {
            return Err(Error::UnexpectedEnd);
        }
        self.cursor = end;
        Ok(())
    }

    fn byte(&mut self) -> Result<u8> {
        self.take(1)?;
        Ok(self.input[self.cursor - 1])
    }

    fn peek(&self) -> Result<u8> {
        self.input
            .get(self.cursor)
            .copied()
            .ok_or(Error::UnexpectedEnd)
    }

    /// Reads one marker varint (canonical little-endian), validating the
    /// marker and canonical width exactly like the decoder's LE path.
    fn varint(&mut self) -> Result<u128> {
        let marker = self.byte()?;
        if marker <= 250 {
            return Ok(marker as u128);
        }
        let payload_len = match marker {
            MARKER_U16 => 2,
            MARKER_U32 => 4,
            MARKER_U64 => 8,
            MARKER_U128 => 16,
            other => return Err(Error::InvalidVarintMarker(other)),
        };
        let end = self
            .cursor
            .checked_add(payload_len)
            .ok_or(Error::UnexpectedEnd)?;
        if let Some(limit) = self.config.limit {
            if end as u64 > limit {
                return Err(Error::SizeLimit { limit });
            }
        }
        let bytes = self
            .input
            .get(self.cursor..end)
            .ok_or(Error::UnexpectedEnd)?;
        self.cursor = end;
        match decode_varint_le(marker, bytes) {
            Some(value) => Ok(value),
            None => Err(Error::NonCanonicalVarint),
        }
    }

    /// Reads a numeric payload following `IntEncoding`, mirroring
    /// `Decoder::unsigned`. Endianness does not affect the byte width, so the
    /// probe only needs the width, never the value.
    fn number(&mut self, fixed_bytes: usize) -> Result<()> {
        if self.config.integers == IntEncoding::Variable && fixed_bytes > 1 {
            self.varint().map(|_| ())
        } else {
            self.take(fixed_bytes)
        }
    }

    /// Reads a length prefix following `IntEncoding`, mirroring
    /// `Decoder::length` (strings are bounded by the byte limit; the
    /// collection limit applies to element counts, not string bytes).
    fn length(&mut self) -> Result<u64> {
        if self.config.integers == IntEncoding::Variable {
            u64::try_from(self.varint()?).map_err(|_| Error::IntegerOverflow { target: "u64" })
        } else {
            self.take(8)?;
            Ok(0)
        }
    }

    /// Walks one complete value.
    fn value(&mut self) -> Result<()> {
        let tag = self.byte()?;
        match tag {
            TAG_NULL | TAG_FALSE | TAG_TRUE => Ok(()),
            TAG_U64 | TAG_I64 => self.number(8),
            TAG_U128 | TAG_I128 => self.number(16),
            TAG_F64 => self.take(8),
            TAG_F32 => self.take(4),
            TAG_STRING => {
                let len = usize::try_from(self.length()?)
                    .map_err(|_| Error::IntegerOverflow { target: "usize" })?;
                self.take(len)
            }
            TAG_ARRAY => self.container(false),
            TAG_OBJECT => self.container(true),
            TAG_END => Err(Error::Custom(
                "unexpected end-of-container terminator".into(),
            )),
            _ => Err(Error::Custom("invalid value tag".into())),
        }
    }

    /// Walks one container (array or object) and its entries.
    fn container(&mut self, is_object: bool) -> Result<()> {
        self.containers += 1;
        if self.depth >= self.config.depth_limit {
            return Err(Error::Custom("decoder nesting depth limit exceeded".into()));
        }
        self.depth += 1;
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
        let mut count = 0u64;
        loop {
            let tag = self.peek()?;
            if tag == TAG_END {
                // Consume the terminator exactly like `exit_container`.
                self.take(1)?;
                break;
            }
            count += 1;
            if let Some(limit) = self.config.collection_limit {
                if count > limit {
                    return Err(Error::CollectionLimit { limit });
                }
            }
            if is_object {
                let key_tag = self.byte()?;
                if key_tag != TAG_STRING {
                    return Err(Error::Custom("invalid object key".into()));
                }
                let key_len = usize::try_from(self.length()?)
                    .map_err(|_| Error::IntegerOverflow { target: "usize" })?;
                self.take(key_len)?;
            }
            self.value()?;
        }
        self.elements += count;
        self.depth -= 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::ToOwned;
    use alloc::vec;
    use alloc::vec::Vec;

    fn value_for_scalars() -> Vec<nextjson::Value> {
        use nextjson::{Number, Value};
        vec![
            Value::Null,
            Value::Bool(true),
            Value::Number(Number::U64(0)),
            Value::Number(Number::U64(251)),
            Value::Number(Number::U64(u64::MAX)),
            Value::Number(Number::I64(-1)),
            Value::Number(Number::F64(1.5)),
            Value::String("hello".into()),
        ]
    }

    #[test]
    fn probe_matches_encoder_byte_accounting() {
        let config = crate::options();
        for value in value_for_scalars() {
            let bytes = config.serialize(&value).unwrap();
            let probe = probe(config, &bytes).unwrap();
            assert_eq!(probe.bytes(), bytes.len(), "byte accounting for {value:?}");
            assert_eq!(probe.containers(), 0);
            assert_eq!(probe.elements(), 0);
            assert_eq!(probe.depth(), 0);
        }
    }

    #[test]
    fn probe_reports_nested_shape() {
        use nextjson::{Number, Value};
        let config = crate::options();
        // [ [1, 2], {"a": 3} ] — 3 containers, 5 entries total.
        let object = Value::Object(
            [("a".to_owned(), Value::Number(Number::U64(3)))]
                .into_iter()
                .collect(),
        );
        let frame = config
            .serialize(&Value::Array(vec![
                Value::Array(vec![
                    Value::Number(Number::U64(1)),
                    Value::Number(Number::U64(2)),
                ]),
                object,
            ]))
            .unwrap();
        let probe = probe(config, &frame).unwrap();
        assert_eq!(probe.bytes(), frame.len());
        assert_eq!(probe.containers(), 3); // outer + inner array + object
        assert_eq!(probe.elements(), 5); // 2 (outer) + 2 (inner array) + 1 (object pair)
        assert_eq!(probe.depth(), 2);
    }

    #[test]
    fn probe_acceptance_matches_deserialize() {
        let config = crate::options().with_limit(64).with_collection_limit(8);
        let frame = config.serialize(&vec![1u64, 2, 3, 4]).unwrap();
        for cut in 0..frame.len() {
            let decoded = config.deserialize::<Vec<u64>>(&frame[..cut]);
            let probed = probe(config, &frame[..cut]);
            assert_eq!(
                probed.is_ok(),
                decoded.is_ok(),
                "acceptance drift at cut {cut}"
            );
            if let Ok(probe) = probed {
                assert_eq!(probe.bytes(), frame.len().min(cut));
            }
        }
        assert_eq!(probe(config, &frame).unwrap().bytes(), frame.len());
    }

    #[test]
    fn probe_enforces_limits_like_decode() {
        let encoded = crate::options().serialize(&vec![1u64, 2, 3]).unwrap();
        let config = crate::options().with_collection_limit(2);
        assert!(matches!(
            probe(config, &encoded),
            Err(Error::CollectionLimit { limit: 2 })
        ));
        assert!(matches!(
            config.deserialize::<Vec<u64>>(&encoded),
            Err(Error::CollectionLimit { limit: 2 })
        ));

        let deep = crate::options().serialize(&vec![vec![1u64]]).unwrap();
        let config = crate::options().with_depth_limit(1);
        assert!(probe(config, &deep).is_err());
        assert!(config.deserialize::<Vec<Vec<u64>>>(&deep).is_err());

        let wide = crate::options().serialize(&vec![1u64; 4]).unwrap();
        let config = crate::options().with_limit(8);
        assert!(probe(config, &wide).is_err());
        assert!(config.deserialize::<Vec<u64>>(&wide).is_err());
    }

    #[test]
    fn probe_rejects_malformed_and_trailing() {
        let config = crate::options();
        // Non-canonical varint.
        assert!(matches!(
            probe(config, &[TAG_U64, MARKER_U16, 5, 0]),
            Err(Error::NonCanonicalVarint)
        ));
        // Invalid marker.
        assert!(matches!(
            probe(config, &[TAG_U64, 255]),
            Err(Error::InvalidVarintMarker(255))
        ));
        // Terminator in value position.
        assert!(matches!(probe(config, &[TAG_END]), Err(Error::Custom(_))));
        // Truncated string.
        assert!(matches!(
            probe(config, &[TAG_STRING, 5, b'a']),
            Err(Error::UnexpectedEnd)
        ));
        // Trailing bytes are rejected by default and allowed on request.
        let mut frame = config.serialize(&7u64).unwrap();
        frame.push(0);
        assert!(matches!(
            probe(config, &frame),
            Err(Error::TrailingBytes { remaining: 1 })
        ));
        assert_eq!(
            probe(config.allow_trailing_bytes(), &frame)
                .unwrap()
                .bytes(),
            config.serialize(&7u64).unwrap().len()
        );
    }

    #[test]
    fn probe_walks_large_frames_without_allocating() {
        let config = crate::options();
        let frame = config
            .serialize(&(0..10_000u64).collect::<Vec<_>>())
            .unwrap();
        let probe = probe(config, &frame).unwrap();
        assert_eq!(probe.bytes(), frame.len());
        assert_eq!(probe.containers(), 1);
        assert_eq!(probe.elements(), 10_000);
        assert_eq!(probe.depth(), 1);
    }

    #[cfg(feature = "bounded")]
    #[test]
    fn probe_integrates_with_budget() {
        use crate::bounded::Budget;
        let config = crate::options();
        let frame = config.serialize(&vec![1u64, 2, 3]).unwrap();
        let probe = probe(config, &frame).unwrap();
        assert!(probe.fits_budget(Budget::default()));
        assert!(probe.fits_budget(Budget::default().with_max_input(frame.len() as u64)));
        assert!(!probe.fits_budget(Budget::default().with_max_input(frame.len() as u64 - 1)));
        assert!(!probe.fits_budget(Budget::default().with_max_depth(0)));
        assert!(probe.fits_input(frame.len() as u64));
        assert!(probe.fits_depth(1));
    }
}
