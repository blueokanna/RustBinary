use rustbinary::{options, Error};

#[cfg(feature = "bounded")]
#[test]
fn probe_budget_checks_each_collection_separately() {
    let frame = options().serialize(&vec![vec![1u8; 4]; 2]).unwrap();
    let probe = options().probe(&frame).unwrap();
    assert_eq!(probe.elements(), 10);
    assert_eq!(probe.max_collection_len(), 4);
    assert!(!probe.fits_budget(rustbinary::Budget::default().with_max_collection(3)));
    assert!(probe.fits_budget(rustbinary::Budget::default().with_max_collection(4)));
}

#[cfg(feature = "bounded")]
#[test]
fn allocation_admission_includes_dynamic_payload_and_token_weights() {
    use rustbinary::{decode_bounded, Budget, BudgetExceeded, DecodeError};
    let text = options().serialize(&"payload").unwrap();
    assert!(matches!(
        decode_bounded::<String>(&text, Budget::default().with_max_alloc(0)),
        Err(DecodeError::Budget(BudgetExceeded::Alloc { limit: 0 }))
    ));
    let text_budget = Budget::default().with_max_alloc(text.len() as u64);
    assert_eq!(
        decode_bounded::<String>(&text, text_budget)
            .unwrap()
            .use_
            .alloc_estimate,
        text.len() as u64
    );
    let bytes = options()
        .serialize(&vec![vec![1u64, 2], vec![3, 4]])
        .unwrap();
    let baseline = decode_bounded::<Vec<Vec<u64>>>(&bytes, Budget::default()).unwrap();
    let estimate = baseline.use_.alloc_estimate;
    let exact = Budget::default().with_max_alloc(estimate);
    assert_eq!(
        decode_bounded::<Vec<Vec<u64>>>(&bytes, exact)
            .unwrap()
            .use_
            .alloc_estimate,
        estimate
    );
    assert!(decode_bounded::<Vec<Vec<u64>>>(&bytes, exact.with_max_alloc(estimate - 1)).is_err());
}

// Deliberately retries reads to exercise the custom-deserializer trust boundary.
#[derive(Debug)]
struct Retry;

impl<'de> nextjson::NsonDeserialize<'de> for Retry {
    fn nextdecode_into<D: nextjson::FormatDecoder<'de>>(
        decoder: &mut D,
        out: &mut nextjson::de::DecodeSlot<Self>,
    ) -> Result<(), D::Error> {
        decoder.peek_token()?;
        let mark = decoder.save();
        decoder.bool()?;
        decoder.restore(mark);
        decoder.bool()?;
        out.write(Self);
        Ok(())
    }
}

#[test]
fn lookahead_checkpoints_preserve_values_but_do_not_refund_work() {
    let bytes = options().serialize(&true).unwrap();
    assert!(options().deserialize::<Retry>(&bytes).is_ok());
    assert!(matches!(
        options()
            .with_decode_work_limit(1)
            .deserialize::<Retry>(&bytes),
        Err(Error::WorkLimit { limit: 1 })
    ));
    assert!(matches!(
        options().with_value_limit(1).deserialize::<Retry>(&bytes),
        Err(Error::ValueLimit { limit: 1 })
    ));
}

#[derive(Debug)]
struct SwallowsError;

impl<'de> nextjson::NsonDeserialize<'de> for SwallowsError {
    fn nextdecode_into<D: nextjson::FormatDecoder<'de>>(
        decoder: &mut D,
        out: &mut nextjson::de::DecodeSlot<Self>,
    ) -> Result<(), D::Error> {
        let mark = decoder.save();
        decoder.bool()?;
        decoder.restore(mark);
        let _ = decoder.bool();
        decoder.restore(mark);
        let _ = decoder.string();
        out.write(Self);
        Ok(())
    }
}

#[test]
fn custom_error_recovery_cannot_clear_exhaustion() {
    let bytes = options().serialize(&true).unwrap();
    assert!(matches!(
        options()
            .with_decode_work_limit(1)
            .deserialize::<SwallowsError>(&bytes),
        Err(Error::WorkLimit { limit: 1 })
    ));
    assert!(matches!(
        options()
            .with_value_limit(1)
            .deserialize::<SwallowsError>(&bytes),
        Err(Error::ValueLimit { limit: 1 })
    ));
}

#[cfg(feature = "bounded")]
#[test]
fn schema_metadata_cannot_certify_custom_allocations() {
    struct Allocating(Vec<u8>);
    impl<'de> nextjson::NsonDeserialize<'de> for Allocating {
        fn nextdecode_into<D: nextjson::FormatDecoder<'de>>(
            decoder: &mut D,
            out: &mut nextjson::de::DecodeSlot<Self>,
        ) -> Result<(), D::Error> {
            decoder.unit()?;
            out.write(Self(vec![0; 4096]));
            Ok(())
        }
    }
    impl rustbinary::DecodeBounded for Allocating {
        const MAX_INPUT: usize = 1;
        const MAX_ALLOC: usize = 0;
        const MAX_DEPTH: usize = 0;
        const MAX_WORK: usize = 1;
    }
    let decoded = rustbinary::decode_bounded::<Allocating>(
        &[0],
        rustbinary::Budget::from_type::<Allocating>(),
    )
    .unwrap();
    assert_eq!(decoded.use_.alloc_estimate, 0);
    // The estimate comes from trusted metadata, not allocator instrumentation.
    assert!(decoded.value.0.capacity() >= 4096);
}

#[cfg(feature = "entropy")]
#[test]
fn canonical_replay_accepts_a_different_valid_message() {
    let config = options().with_entropy_encoding().without_raw_fallback();
    let model = rustbinary::Model::from_uniform(256).unwrap();
    let original = config.compress(b"original", &model).unwrap();
    let replacement = config.compress(b"replaced", &model).unwrap();
    assert_ne!(original, replacement);
    assert_eq!(
        config.decompress(&replacement, &model).unwrap(),
        b"replaced"
    );
}

#[derive(Debug, nextjson::NsonDeserialize)]
struct Empty {}

#[test]
fn unknown_fields_obey_all_parser_limits() {
    let value = nextjson::json!({"ignored": [[1, 2, 3], [4, 5, 6]]});
    let bytes = options().serialize(&value).unwrap();
    assert!(options()
        .with_depth_limit(2)
        .deserialize::<Empty>(&bytes)
        .is_err());
    assert!(matches!(
        options()
            .with_collection_limit(2)
            .deserialize::<Empty>(&bytes),
        Err(Error::CollectionLimit { limit: 2 })
    ));
    assert!(matches!(
        options().with_value_limit(5).deserialize::<Empty>(&bytes),
        Err(Error::ValueLimit { limit: 5 })
    ));
    assert!(matches!(
        options()
            .with_limit(bytes.len() as u64 - 1)
            .deserialize::<Empty>(&bytes),
        Err(Error::SizeLimit { .. })
    ));
    assert!(options().deserialize::<Empty>(&bytes).is_ok());
}

#[test]
fn global_limit_counts_siblings_and_nested_branches() {
    let values = vec![vec![0u8; 4]; 4];
    let bytes = options().serialize(&values).unwrap();
    let config = options().with_collection_limit(4).with_value_limit(20);
    assert!(matches!(
        config.deserialize::<Vec<Vec<u8>>>(&bytes),
        Err(Error::ValueLimit { limit: 20 })
    ));
    assert_eq!(
        config
            .with_value_limit(21)
            .deserialize::<Vec<Vec<u8>>>(&bytes)
            .unwrap(),
        values
    );
    assert_eq!(options().probe(&bytes).unwrap().values(), 21);
}

#[test]
fn probe_uses_decoder_endianness_lengths_and_utf8_checks() {
    for config in [
        options(),
        options().with_big_endian(),
        options().with_fixint_encoding(),
        options().with_fixint_encoding().with_big_endian(),
    ] {
        let value = (251u64, "a".repeat(300));
        let bytes = config.serialize(&value).unwrap();
        assert_eq!(config.probe(&bytes).unwrap().bytes(), bytes.len());
        assert_eq!(config.deserialize::<(u64, String)>(&bytes).unwrap(), value);
        let mut invalid = config.serialize("x").unwrap();
        *invalid.last_mut().unwrap() = 0xff;
        assert!(matches!(config.probe(&invalid), Err(Error::InvalidUtf8(_))));
    }
}

#[test]
fn zero_collection_limit_accepts_empty_and_rejects_first_entry() {
    let config = options().with_collection_limit(0);
    let empty = options().serialize(&Vec::<u8>::new()).unwrap();
    assert!(config.deserialize::<Vec<u8>>(&empty).unwrap().is_empty());
    let one = options().serialize(&vec![1u8]).unwrap();
    assert!(matches!(
        config.deserialize::<Vec<u8>>(&one),
        Err(Error::CollectionLimit { limit: 0 })
    ));
}

#[cfg(feature = "bounded")]
#[test]
fn bounded_borrowing_and_static_storage_admission() {
    use rustbinary::{decode_bounded, Budget, BudgetExceeded, DecodeError};
    let bytes = options().serialize("borrowed").unwrap();
    let decoded = decode_bounded::<&str>(&bytes, Budget::default()).unwrap();
    assert_eq!(decoded.value.as_ptr(), bytes[2..].as_ptr());
    assert_eq!(decoded.use_.alloc_estimate, 0);
    let phantom = core::marker::PhantomData::<u64>;
    let encoded = options().serialize(&phantom).unwrap();
    assert_eq!(encoded, [0]);
    assert!(decode_bounded::<core::marker::PhantomData<u64>>(
        &encoded,
        Budget::from_type::<core::marker::PhantomData<u64>>()
    )
    .is_ok());
    #[cfg(feature = "static-size")]
    assert_eq!(
        <core::marker::PhantomData<u64> as rustbinary::StaticSize>::MAX_SIZE,
        encoded.len()
    );
    let bytes = options().serialize(&7u64).unwrap();
    assert!(matches!(
        decode_bounded::<Box<u64>>(&bytes, Budget::default().with_max_alloc(0)),
        Err(DecodeError::Budget(BudgetExceeded::Alloc { limit: 0 }))
    ));
}

#[cfg(feature = "bounded")]
#[test]
fn budget_from_config_preserves_independent_collection_and_visit_limits() {
    use rustbinary::{decode_bounded, Budget, DecodeError};
    let config = options().with_collection_limit(4).with_value_limit(21);
    let values = vec![vec![0u8; 4]; 4];
    let bytes = options().serialize(&values).unwrap();
    let budget = Budget::from_config(config);
    assert_eq!(budget.max_collection(), 4);
    assert_eq!(budget.max_values(), 21);
    assert_eq!(
        decode_bounded::<Vec<Vec<u8>>>(&bytes, budget)
            .unwrap()
            .value,
        values
    );
    let bytes = options().serialize(&vec![0u8; 5]).unwrap();
    assert!(matches!(
        decode_bounded::<Vec<u8>>(&bytes, budget),
        Err(DecodeError::Codec(Error::CollectionLimit { limit: 4 }))
    ));
}

#[cfg(feature = "projection")]
#[test]
fn verification_requires_the_callers_exact_query() {
    use rustbinary::{
        prove, verify_query, ProjectedRecord, Projection, ProjectionLimits, RecordBuilder,
    };
    let mut builder = RecordBuilder::new(7);
    builder.insert_varint(1, 10).unwrap();
    builder.insert_varint(2, 20).unwrap();
    let bytes = builder.finish().unwrap();
    let limits = ProjectionLimits::new();
    let root = *ProjectedRecord::parse(&bytes, &limits).unwrap().root();
    let proof = prove(&bytes, &Projection::new([1]), &limits).unwrap();
    assert!(verify_query(&proof, &root, 7, &Projection::new([1])).is_ok());
    for query in [
        Projection::new([2]),
        Projection::new([1, 2]),
        Projection::new([1, 99]),
    ] {
        assert!(verify_query(&proof, &root, 7, &query).is_err());
    }
}
