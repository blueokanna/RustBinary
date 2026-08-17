//! Fuzz target: the schema-guided compact profile decoder must never panic,
//! must never overrun configured limits, and must always either return a
//! value or a structured error on arbitrary bytes.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run decode_compact_arbitrary
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustbinary::{CompactBinary, ErrorCategory};

// A representative schema with every primitive family the compact profile
// supports: scalars, byte strings, float arrays, options, and nesting.
#[derive(Debug, PartialEq, CompactBinary)]
struct FuzzPacket {
    sequence: u64,
    delta: i32,
    label: String,
    payload: Vec<u8>,
    samples: Vec<f64>,
    status: Option<u8>,
}

#[derive(Debug, PartialEq, CompactBinary)]
enum FuzzEvent {
    Idle,
    Data(u64),
    Point { x: i64, y: i64 },
}

fuzz_target!(|data: &[u8]| {
    // Tight resource policies so a hostile length prefix cannot force a huge
    // allocation; the decoder must reject it instead.
    let config = rustbinary::options()
        .with_limit(1 << 20)
        .with_collection_limit(1 << 16)
        .with_compact_format();
    let result = config.deserialize::<FuzzPacket>(data);
    match result {
        Ok(_) => {}
        Err(error) => {
            let _ = error.category();
        }
    }
    let _ = config.deserialize::<FuzzEvent>(data);
    let _ = ErrorCategory::UserInput;
});
