use std::collections::BTreeMap;

use rustbinary::{EncryptionKey, Error};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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

    // Production keys must come from a KMS/HSM or a protected secret store.
    // A fixed key is used here only to make the executable self-contained.
    let pipeline = rustbinary::options()
        .with_limit(4 * 1024 * 1024)
        .with_collection_limit(20_000)
        .with_cbor_format()
        .with_deterministic_encoding()
        .with_zstd_compression(5)
        .with_compression_threshold(512)
        .with_encryption(EncryptionKey::new([0x6d; 32]));

    // The order is fixed: deterministic CBOR -> adaptive Zstandard -> AEAD.
    let first = pipeline.serialize(&value)?;
    let second = pipeline.serialize(&value)?;
    assert_eq!(&first[..4], b"RBX1");
    assert_ne!(first, second, "fresh AEAD nonces must change the frame");
    assert_eq!(pipeline.deserialize::<AuditBatch>(&first)?, value);

    // Header metadata is associated data and ciphertext is authenticated.
    let mut tampered = first;
    let last = tampered.last_mut().ok_or(Error::UnexpectedEnd)?;
    *last ^= 1;
    assert!(matches!(
        pipeline.deserialize::<AuditBatch>(&tampered),
        Err(Error::Encryption)
    ));

    Ok(())
}
