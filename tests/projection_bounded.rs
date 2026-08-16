//! End-to-end integration coverage for the `projection` and `bounded`
//! features through the crate's public API, exactly as a downstream
//! application would use them.

#![cfg(all(feature = "projection", feature = "bounded"))]

use rustbinary::{
    decode_bounded, prove, verify, Budget, DecodeBounded, Decoded, ProjectedRecord, Projection,
    ProjectionLimits, RecordBuilder, VerifiedField,
};

/// A projection proof that travels without the record: the verifier only sees
/// the proof and the trusted anchor.
#[test]
fn projection_proof_is_a_self_contained_witness() {
    let mut builder = RecordBuilder::new(7);
    builder.insert_str(1, "alpha").unwrap();
    builder.insert_varint(2, 42).unwrap();
    builder.insert_bytes(3, b"\x00\x01").unwrap();
    let record = builder.finish().unwrap();

    // The trusted anchor comes from an authenticated source.
    let parsed = ProjectedRecord::parse(&record, &ProjectionLimits::new()).unwrap();
    let anchor = *parsed.root();

    let query = Projection::new([2]);
    let proof = prove(&record, &query, &ProjectionLimits::new()).unwrap();
    let verified: Vec<VerifiedField<'_>> = verify(&proof, &anchor, 7).unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].field_id, 2);
    assert_eq!(verified[0].as_varint().unwrap(), 42);
    // The verifier never needed the record bytes.
    drop(record);
}

/// `decode_bounded` returns evidence of resource use that satisfies the
/// documented guarantees.
#[test]
fn bounded_decode_returns_resource_evidence() {
    #[derive(nextjson::NsonSerialize, nextjson::NsonDeserialize, DecodeBounded)]
    struct Packet {
        sequence: u64,
        payload: Vec<u8>,
    }

    let packet = Packet {
        sequence: 1,
        payload: vec![0u8; 64],
    };
    let bytes = rustbinary::options().serialize(&packet).unwrap();

    let budget = Budget::from_type::<Packet>().with_max_alloc(1 << 16);
    let decoded: Decoded<Packet> = decode_bounded::<Packet>(&bytes, budget).unwrap();
    assert_eq!(decoded.value.sequence, 1);
    assert_eq!(decoded.value.payload.len(), 64);
    // read is exact and bounded by the budget.
    assert_eq!(decoded.use_.read as usize, bytes.len());
    assert!(decoded.use_.read <= budget.max_input());
    assert!(decoded.use_.read <= budget.max_work());
    // dynamic allocation ceiling: read + structural cap <= max_input + max_alloc.
    assert!(decoded.use_.alloc_bound <= budget.max_input() + budget.max_alloc());
    // static algebra: depth is derived (object + array).
    assert_eq!(<Packet as DecodeBounded>::MAX_DEPTH, 2);
    assert_eq!(decoded.use_.depth_bound, 2);

    // A budget too small for the input is rejected before decoding.
    let tight = budget.with_max_input((bytes.len() - 1) as u64);
    assert!(matches!(
        decode_bounded::<Packet>(&bytes, tight),
        Err(rustbinary::DecodeError::Budget(
            rustbinary::BudgetExceeded::Input { .. }
        ))
    ));
}

/// A tampered record is rejected end-to-end: parse may succeed, but every
/// proof against the original trusted anchor fails.
#[test]
fn tampered_record_is_rejected_against_the_anchor() {
    let mut builder = RecordBuilder::new(7);
    builder.insert_varint(1, 100).unwrap();
    builder.insert_varint(2, 200).unwrap();
    builder.insert_bytes(3, b"payload").unwrap();
    let record = builder.finish().unwrap();
    let parsed = ProjectedRecord::parse(&record, &ProjectionLimits::new()).unwrap();
    let anchor = *parsed.root();

    // Tamper a field payload byte (the third field's first byte).
    let mut tampered = record;
    tampered[30] ^= 0x01;
    let query = Projection::new([1, 2, 3]);
    if let Ok(parsed) = ProjectedRecord::parse(&tampered, &ProjectionLimits::new()) {
        if let Ok(proof) = parsed.prove(&query) {
            assert!(matches!(
                verify(&proof, &anchor, 7),
                Err(rustbinary::ProjectionError::RootMismatch)
            ));
        }
    }
}

/// Schema version is bound into the root: a proof produced under one version
/// is rejected when the verifier expects another.
#[test]
fn schema_version_is_bound_end_to_end() {
    let mut builder = RecordBuilder::new(3);
    builder.insert_varint(1, 9).unwrap();
    let record = builder.finish().unwrap();
    let parsed = ProjectedRecord::parse(&record, &ProjectionLimits::new()).unwrap();
    let anchor = *parsed.root();

    let proof = prove(&record, &Projection::new([1]), &ProjectionLimits::new()).unwrap();
    // Correct version and anchor verify.
    assert!(verify(&proof, &anchor, 3).is_ok());
    // A wrong expected version is rejected before any payload is returned.
    assert!(matches!(
        verify(&proof, &anchor, 4),
        Err(rustbinary::ProjectionError::RootMismatch)
    ));
    // A wrong anchor is rejected.
    let wrong = [0x11u8; 32];
    assert!(matches!(
        verify(&proof, &wrong, 3),
        Err(rustbinary::ProjectionError::RootMismatch)
    ));
    // Untrusted verification only checks internal consistency.
    assert!(rustbinary::verify_untrusted(&proof).is_ok());
}

/// A collection budget that cannot cover the decoded elements is rejected
/// with the collection limit derived from the allocation budget.
#[test]
fn allocation_budget_rejects_oversized_collections() {
    #[derive(nextjson::NsonSerialize, nextjson::NsonDeserialize, DecodeBounded)]
    struct Blob {
        data: Vec<u8>,
    }
    let value = Blob {
        data: vec![0u8; 100],
    };
    let bytes = rustbinary::options().serialize(&value).unwrap();
    // Blob is an object (level 1) containing a Vec<u8> (level 2): the
    // per-element structural ceiling is size_of::<u8>() * depth = 1 * 2, so
    // the derived collection limit is max_alloc / 2. 199 -> 99 elements
    // (cannot hold 100), 200 -> 100 (exactly enough).
    let tight = Budget::default().with_max_alloc(199);
    assert!(matches!(
        decode_bounded::<Blob>(&bytes, tight),
        Err(rustbinary::DecodeError::Codec(
            rustbinary::Error::CollectionLimit { limit: 99 }
        ))
    ));
    let exact = Budget::default().with_max_alloc(200);
    assert!(decode_bounded::<Blob>(&bytes, exact).is_ok());
}
