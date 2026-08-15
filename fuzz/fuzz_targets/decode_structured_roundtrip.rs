//! Fuzz target: serialize/deserialize roundtrips over structured random data
//! must be lossless and must not panic.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run decode_structured_roundtrip
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use nextjson::{NsonDeserialize, NsonSerialize};
use rustbinary::Config;

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
struct Record<'a> {
    id: u64,
    #[njson(borrow)]
    name: &'a str,
    samples: Vec<i64>,
    flags: Vec<bool>,
    maybe: Option<u32>,
}

fuzz_target!(|data: &[u8]| {
    let config = Config::standard().with_collection_limit(4096).with_limit(1 << 20);
    // Split the input into a structured value and use the tail for strings.
    let mut name = String::from_utf8_lossy(data.get(..64.min(data.len())).unwrap_or(data))
        .into_owned();
    if name.is_empty() {
        name.push('x');
    }
    let record = Record {
        id: data.len() as u64,
        name: &name,
        samples: data
            .chunks(8)
            .map(|chunk| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(chunk);
                i64::from_le_bytes(bytes)
            })
            .collect(),
        flags: data.iter().map(|byte| byte & 1 == 0).collect(),
        maybe: if data.is_empty() { None } else { Some(data[0] as u32) },
    };
    let frame = config.serialize(&record).unwrap();
    let decoded: Record<'_> = config.deserialize(&frame).unwrap();
    assert_eq!(decoded.id, record.id);
    assert_eq!(decoded.name, record.name);
    assert_eq!(decoded.samples, record.samples);
    assert_eq!(decoded.flags, record.flags);
    assert_eq!(decoded.maybe, record.maybe);
});
