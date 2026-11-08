//! Allocation-free structural inspection using the self-describing decoder's parser.
//! Reports consumed bytes, containers, elements and maximum depth, with the same
//! wire validation and limits as decoding. Target-type compatibility and work
//! spent on speculative deserialization still require a full decode.
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

use crate::config::Config;
use crate::error::Result;

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
    values: u64,
    max_collection_len: u64,
}

impl Probe {
    pub(crate) const fn new(
        bytes: usize,
        containers: u64,
        elements: u64,
        depth: usize,
        values: u64,
        max_collection_len: u64,
    ) -> Self {
        Self {
            bytes,
            containers,
            elements,
            depth,
            values,
            max_collection_len,
        }
    }
    /// Tokens including keys and container starts; terminators are excluded.
    pub const fn values(self) -> u64 {
        self.values
    }

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

    /// Largest entry count of any single array or object.
    pub const fn max_collection_len(self) -> u64 {
        self.max_collection_len
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

    /// Checks input, minimum read work, depth, visits and per-collection limits.
    ///
    /// The probe knows the exact byte count and shape; the budget supplies the
    /// policy. Allocation and custom trait work cannot be decided here. This checks
    /// necessary parser conditions, not whether typed decoding will succeed.
    #[cfg(feature = "bounded")]
    pub const fn fits_budget(self, budget: crate::bounded::Budget) -> bool {
        (self.bytes as u64) <= budget.max_input()
            && (self.bytes as u64) <= budget.max_work()
            && self.depth <= budget.max_depth()
            && self.values <= budget.max_values()
            && self.max_collection_len <= budget.max_collection()
    }
}

/// Walks one self-describing value and reports its exact structural footprint.
///
/// Allocation-free and side-effect free: the walker holds only the input
/// borrow, a cursor, and counters.
pub fn probe(config: Config, input: &[u8]) -> Result<Probe> {
    crate::decoder::probe(input, config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::{MARKER_U16, TAG_END, TAG_STRING, TAG_U64};
    use crate::Error;
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
