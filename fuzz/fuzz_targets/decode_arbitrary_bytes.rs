//! Fuzz target: decoding arbitrary bytes must never panic, and must always
//! either return a value or a structured error.
//!
//! Run with:
//!
//! ```text
//! cargo +nightly fuzz run decode_arbitrary_bytes
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustbinary::{Config, ErrorCategory};

fuzz_target!(|data: &[u8]| {
    // Exercise both the strict compact profile and the legacy profile.
    let configs = [rustbinary::options(), rustbinary::legacy_options()];
    for config in configs {
        let result: Result<nextjson::Value, rustbinary::Error> = config.deserialize(data);
        match result {
            Ok(_) => {}
            Err(error) => {
                // Every error must carry a stable category; no panic allowed.
                let _ = error.category();
            }
        }
    }
    let _ = ErrorCategory::UserInput;
});
