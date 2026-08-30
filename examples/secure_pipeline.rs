use std::collections::BTreeMap;

use nextjson::{NsonDeserialize, NsonSerialize};
use rustbinary::{
    core::{Error, ErrorCategory},
    pipeline::EncryptionKey,
};

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
struct AuditBatch {
    tenant: String,
    attributes: BTreeMap<String, String>,
    rows: Vec<String>,
}

fn main() -> rustbinary::Result<()> {
    let value = AuditBatch {
        tenant: "tenant-17".into(),
        attributes: BTreeMap::from([
            ("region".into(), "ap-east".into()),
            ("source".into(), "gateway".into()),
        ]),
        rows: vec!["stable repeated audit record".into(); 1024],
    };

    let pipeline = rustbinary::options()
        .with_limit(4 * 1024 * 1024)
        .with_collection_limit(20_000)
        .with_cbor_format()
        .with_deterministic_encoding()
        .with_compression(5)
        .with_compression_threshold(512)
        .with_encryption(EncryptionKey::new([0x6d; 32]));

    let first = pipeline.serialize(&value)?;
    let second = pipeline.serialize(&value)?;
    assert_eq!(&first[..4], b"RBX1");
    assert_ne!(first, second, "fresh AEAD nonces must change the frame");
    assert_eq!(pipeline.deserialize::<AuditBatch>(&first)?, value);

    let mut tampered = first.clone();
    let last = tampered.last_mut().ok_or(Error::UnexpectedEnd)?;
    *last ^= 1;
    let authentication_error = pipeline.deserialize::<AuditBatch>(&tampered).unwrap_err();
    assert!(matches!(&authentication_error, Error::Encryption));
    assert_eq!(authentication_error.category(), ErrorCategory::UserInput);

    let bounded = rustbinary::options()
        .with_limit(16)
        .with_collection_limit(4)
        .with_cbor_format()
        .with_deterministic_encoding()
        .with_encryption(EncryptionKey::new([0x7a; 32]));
    let limit_error = bounded.serialize(&value).unwrap_err();
    assert!(matches!(&limit_error, Error::SizeLimit { limit: 16 }));
    assert_eq!(limit_error.category(), ErrorCategory::Configuration);

    println!(
        "secure pipeline: {} encrypted bytes; fresh nonce produced {} different bytes",
        second.len(),
        first
            .iter()
            .zip(&second)
            .filter(|(left, right)| left != right)
            .count()
    );

    Ok(())
}
