#![cfg(feature = "entropy")]

use rustbinary::{options, Error, Model};

#[test]
fn declared_symbol_count_is_checked_before_allocating() {
    let model = Model::from_uniform(1).unwrap();
    let mut frame = options()
        .with_entropy_encoding()
        .compress(&[0], &model)
        .unwrap();
    let codec = options().with_collection_limit(4).with_entropy_encoding();
    for count in [5u64, 0xe000000000001, u64::MAX] {
        frame[8..16].copy_from_slice(&count.to_le_bytes());
        assert!(matches!(
            codec.decompress(&frame, &model),
            Err(Error::CollectionLimit { limit: 4 })
        ));
        assert!(matches!(
            codec.decode_sequence(&[], &frame),
            Err(Error::CollectionLimit { limit: 4 })
        ));
    }
}

#[test]
fn frame_and_decoded_byte_limits_are_independent() {
    let model = Model::from_uniform(1).unwrap();
    let source = options().with_entropy_encoding();
    let codec = options()
        .with_limit(32)
        .with_collection_limit(64)
        .with_entropy_encoding();
    let frame = source.compress(&[0; 32], &model).unwrap();
    assert_eq!(codec.decompress(&frame, &model).unwrap(), [0; 32]);
    let frame = source.compress(&[0; 33], &model).unwrap();
    assert!(frame.len() < 32);
    assert!(matches!(
        codec.decompress(&frame, &model),
        Err(Error::SizeLimit { limit: 32 })
    ));
    assert!(matches!(
        codec.compress(&[0; 33], &model),
        Err(Error::SizeLimit { limit: 32 })
    ));

    let models = [&model; 9];
    let frame = source.encode_sequence(&models, &[0; 9]).unwrap();
    assert!(matches!(
        codec.decode_sequence(&models, &frame),
        Err(Error::SizeLimit { limit: 32 })
    ));
    assert!(matches!(
        codec.encode_sequence(&models, &[0; 9]),
        Err(Error::SizeLimit { limit: 32 })
    ));
    let frame = codec.encode_sequence(&models[..8], &[0; 8]).unwrap();
    assert_eq!(codec.decode_sequence(&models[..8], &frame).unwrap(), [0; 8]);
}

#[test]
fn raw_frames_and_encoders_obey_collection_limits() {
    let model = Model::from_uniform(256).unwrap();
    let source = options().with_entropy_encoding();
    let frame = source.compress(&[1, 2, 3], &model).unwrap();
    let codec = options().with_collection_limit(2).with_entropy_encoding();
    assert!(matches!(
        codec.decompress(&frame, &model),
        Err(Error::CollectionLimit { limit: 2 })
    ));
    assert!(matches!(
        codec.compress(&[1, 2, 3], &model),
        Err(Error::CollectionLimit { limit: 2 })
    ));
    assert!(matches!(
        codec.encode_sequence(&[&model; 3], &[1, 2, 3]),
        Err(Error::CollectionLimit { limit: 2 })
    ));
}
