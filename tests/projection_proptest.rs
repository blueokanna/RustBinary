//! Property tests for the projectable self-authenticating record format.
//!
//! These complement the exhaustive boundary tests in `src/projection.rs` by
//! randomizing the *shape* of the input: arbitrary field counts, payloads,
//! queries, and single-byte corruptions, always through the public API. Every
//! property here is a statement about projection soundness:
//!
//! - `prove` + `verify` against the trusted anchor returns exactly the
//!   queried projection (never more, never less, never wrong bytes).
//! - Tampering any header or field byte is detected by `verify`.
//! - Parsing arbitrary bytes never panics and either succeeds canonically or
//!   returns a structured error.

#![cfg(feature = "projection")]

use proptest::prelude::*;

use rustbinary::{prove, verify, ProjectedRecord, Projection, ProjectionLimits, RecordBuilder};

/// A strategy for a canonical record: sorted, de-duplicated `(field_id,
/// payload)` pairs. Sorting and de-duplication mirror what `RecordBuilder`
/// enforces, so every generated record is constructible.
fn record_strategy() -> impl Strategy<Value = Vec<(u32, Vec<u8>)>> {
    prop::collection::vec(
        (any::<u32>(), prop::collection::vec(any::<u8>(), 0..64)),
        1..64,
    )
    .prop_map(|mut pairs| {
        pairs.sort_unstable_by_key(|(id, _)| *id);
        pairs.dedup_by_key(|(id, _)| *id);
        pairs
    })
}

/// Builds a record from sorted unique pairs and returns (record, anchor).
fn build(pairs: &[(u32, Vec<u8>)]) -> (Vec<u8>, [u8; 32]) {
    let mut builder = RecordBuilder::new(7);
    for (id, payload) in pairs {
        builder.insert(*id, payload).unwrap();
    }
    let record = builder.finish().unwrap();
    let parsed = ProjectedRecord::parse(&record, &ProjectionLimits::new()).unwrap();
    let anchor = *parsed.root();
    drop(parsed);
    (record, anchor)
}

proptest! {
    /// For any record and any query (an arbitrary subset of its fields), the
    /// proof verifies and returns exactly the queried projection with the
    /// authentic payload bytes.
    #[test]
    fn prove_verify_returns_exact_projection(
        pairs in record_strategy(),
        query_mask in any::<u64>(),
    ) {
        let (record, anchor) = build(&pairs);
        let all_ids: Vec<u32> = pairs.iter().map(|(id, _)| *id).collect();
        let query = Projection::new(
            all_ids
                .iter()
                .enumerate()
                .filter(|(i, _)| query_mask & (1u64 << (i % 64)) != 0)
                .map(|(_, id)| *id),
        );
        if query.is_empty() {
            // An empty query cannot produce a proof; that is the documented
            // behavior.
            prop_assert!(matches!(
                prove(&record, &query, &ProjectionLimits::new()),
                Err(rustbinary::ProjectionError::InvalidQuery)
            ));
            return Ok(());
        }
        let proof = prove(&record, &query, &ProjectionLimits::new()).unwrap();
        let verified = verify(&proof, &anchor, 7).unwrap();
        // Exactly the queried fields, in canonical record order, with the
        // original payload bytes.
        let expected: Vec<(u32, &[u8])> = pairs
            .iter()
            .filter(|(id, _)| query.contains(*id))
            .map(|(id, payload)| (*id, payload.as_slice()))
            .collect();
        prop_assert_eq!(verified.len(), expected.len());
        for (v, (eid, epayload)) in verified.iter().zip(expected.iter()) {
            prop_assert_eq!(v.field_id, *eid);
            prop_assert_eq!(v.payload, *epayload);
        }
    }

    /// Tampering any header or field byte of a record makes every proof fail
    /// against the original trusted anchor.
    #[test]
    fn any_single_byte_tamper_is_detected(
        pairs in record_strategy(),
        pos in any::<usize>(),
    ) {
        let (mut record, anchor) = build(&pairs);
        // The trailing 32 bytes are the stored root (metadata, not trust);
        // they are excluded, exactly as the unit tests document.
        let body_len = record.len() - 32;
        if body_len == 0 {
            return Ok(());
        }
        let pos = pos % body_len;
        record[pos] ^= 0x01;
        let query = Projection::new(pairs.iter().map(|(id, _)| *id));
        if let Ok(parsed) = ProjectedRecord::parse(&record, &ProjectionLimits::new()) {
            match parsed.prove(&query) {
                Ok(proof) => {
                    let result = verify(&proof, &anchor, 7);
                    prop_assert!(
                        result.is_err(),
                        "tamper at byte {pos} was not detected"
                    );
                }
                Err(_) => {
                    // The tampered record no longer exposes any queried field;
                    // nothing can be verified, which is equally safe.
                }
            }
        }
        // parse may reject the tampered record; that is equally safe.
    }

    /// Parsing arbitrary byte strings never panics: it either returns a
    /// canonical record or a structured error.
    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let result = std::panic::catch_unwind(|| {
            ProjectedRecord::parse(&data, &ProjectionLimits::new())
        });
        prop_assert!(result.is_ok(), "parse panicked on arbitrary bytes");
    }

    /// A record's stored root always validates against its own fields
    /// (self-consistency), and the proof root equals the stored root.
    #[test]
    fn stored_root_matches_recomputed_root(pairs in record_strategy()) {
        let (record, _) = build(&pairs);
        let parsed = ProjectedRecord::parse(&record, &ProjectionLimits::new()).unwrap();
        prop_assert!(parsed.verify_root().is_ok());
        let proof = parsed
            .prove(&Projection::new(pairs.iter().map(|(id, _)| *id)))
            .unwrap();
        prop_assert_eq!(proof.claimed_root(), parsed.root());
    }
}
