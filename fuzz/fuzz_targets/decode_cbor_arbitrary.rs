#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(nextjson::NsonDeserialize)]
struct Empty {}

fuzz_target!(|data: &[u8]| {
    let codec = rustbinary::options()
        .with_limit(1 << 16)
        .with_collection_limit(4096)
        .with_depth_limit(32)
        .with_cbor_format();
    let _ = codec.deserialize::<nextjson::Value>(data);
    let _ = codec.deserialize::<Empty>(data);
    let _ = codec.deserialize::<Vec<Option<u128>>>(data);
});
