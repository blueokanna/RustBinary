#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    static MODEL: OnceLock<rustbinary::Model> = OnceLock::new();
    let model = MODEL.get_or_init(|| rustbinary::Model::from_uniform(256).unwrap());
    let config = rustbinary::options()
        .with_limit(1 << 16)
        .with_collection_limit(4096);
    let codec = config.with_entropy_encoding();
    let _ = codec.decompress(data, model);
    let limits = rustbinary::ProjectionLimits::new();
    if let Ok(record) = rustbinary::ProjectedRecord::parse(data, &limits) {
        let _ = record.verify_root();
    }

    let payload = &data[..data.len().min(4096)];
    let mut encoded = codec.compress(payload, model).unwrap();
    assert_eq!(codec.decompress(&encoded, model).unwrap(), payload);
    if let Some(&byte) = data.first() {
        let index = byte as usize % encoded.len();
        encoded[index] ^= data.last().copied().unwrap_or(1);
        let _ = codec.decompress(&encoded, model);
    }

    let mut builder = rustbinary::RecordBuilder::new(1);
    builder.insert_bytes(1, payload).unwrap();
    let mut encoded = builder.finish().unwrap();
    rustbinary::ProjectedRecord::parse(&encoded, &limits)
        .unwrap()
        .verify_root()
        .unwrap();
    if let Some(&byte) = data.first() {
        let index = byte as usize % encoded.len();
        encoded[index] ^= data.last().copied().unwrap_or(1);
        if let Ok(record) = rustbinary::ProjectedRecord::parse(&encoded, &limits) {
            let _ = record.verify_root();
        }
    }
});
