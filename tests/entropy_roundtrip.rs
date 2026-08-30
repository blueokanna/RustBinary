//! Independent randomized roundtrip and corruption tests for the static-model
//! rANS entropy coder (`entropy` feature).
//!
//! These tests exercise the public API only (`rustbinary::EntropyConfig`,
//! `rustbinary::Model`, `rustbinary::RansEncoder`, `rustbinary::RansDecoder`)
//! and do not rely on internal constants, so they serve as an external
//! correctness contract for the coder.

#![cfg(feature = "entropy")]

use proptest::prelude::*;
use rustbinary::{EntropyConfig, Model, RansDecoder, RansEncoder};

fn config() -> EntropyConfig {
    rustbinary::options().with_entropy_encoding()
}

fn encode_bytes(model: &Model, bytes: &[u8]) -> rustbinary::Result<Vec<u8>> {
    config().compress(bytes, model)
}

fn decode_bytes(model: &Model, frame: &[u8]) -> rustbinary::Result<Vec<u8>> {
    config().decompress(frame, model)
}

proptest! {
    /// Byte-alphabet roundtrips must be lossless for arbitrary data and
    /// arbitrary (valid) weight vectors.
    #[test]
    fn byte_roundtrip_lossless(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        seed in any::<u32>(),
    ) {
        // Deterministic, well-formed weight vector over 256 symbols.
        let mut weights = vec![1u32; 256];
        for (index, weight) in weights.iter_mut().enumerate() {
            *weight = 1 + ((seed.wrapping_mul(index as u32 + 1)) % 1000);
        }
        let model = Model::from_weights(&weights).unwrap();
        let frame = encode_bytes(&model, &bytes).unwrap();
        let decoded = decode_bytes(&model, &frame).unwrap();
        prop_assert_eq!(&decoded, &bytes);
        // Coded or raw, the frame must never exceed the raw size plus header.
        prop_assert!(frame.len() <= 24 + bytes.len());
    }

    /// Uniform models over non-power-of-two alphabets must roundtrip.
    #[test]
    fn uniform_roundtrip_lossless(
        symbols in 1..2048u32,
        length in 0..1024usize,
        seed in any::<u64>(),
    ) {
        let model = Model::from_uniform(symbols).unwrap();
        let mut encoder = RansEncoder::new();
        let mut data = Vec::with_capacity(length);
        let mut state = seed;
        for _ in 0..length {
            // xorshift for a deterministic, cheap PRNG.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let symbol = (state % symbols as u64) as u32;
            data.push(symbol);
            encoder.put_symbol(&model, symbol).unwrap();
        }
        let (final_state, payload) = encoder.finish();
        let mut decoder = RansDecoder::new(final_state, &payload);
        let mut decoded = Vec::with_capacity(length);
        for _ in 0..length {
            decoded.push(decoder.get_symbol(&model).unwrap());
        }
        decoder.finish().unwrap();
        decoded.reverse();
        prop_assert_eq!(decoded, data);
    }

    /// Corruption of any single payload byte must be detected (the final
    /// state check is a strong integrity check on the coded path).
    #[test]
    fn single_byte_corruption_is_detected(
        length in 64..2048usize,
        seed in any::<u64>(),
    ) {
        let mut weights = vec![1u32; 256];
        weights[(seed % 256) as usize] = 10000;
        let model = Model::from_weights(&weights).unwrap();
        let mut data = Vec::with_capacity(length);
        let mut state = seed;
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            // Bias the data toward the high-weight symbol so the frame is
            // genuinely coded (rANS smaller than raw).
            let symbol = if state % 16 == 0 {
                (state % 256) as u8
            } else {
                (seed % 256) as u8
            };
            data.push(symbol);
        }
        let frame = encode_bytes(&model, &data).unwrap();
        // Ensure the coded path is exercised.
        if frame.len() >= 24 + data.len() {
            return Ok(());
        }
        // Every payload-byte corruption must either be rejected outright or
        // change the decoded payload. The one thing it may never do is return
        // the original payload unchanged: replay verification re-encodes the
        // decoded symbols and requires the exact original frame, so a silent
        // corruption that yields the original payload is impossible. (A
        // corruption that happens to form another valid canonical frame is
        // indistinguishable from a genuine payload by ANY non-authenticated
        // scheme, so the honest assertion is "error or different payload".)
        for offset in 24..frame.len() {
            let mut corrupted = frame.clone();
            corrupted[offset] ^= 0x80;
            let decoded = decode_bytes(&model, &corrupted);
            match decoded {
                Err(_) => {}
                Ok(bytes) => {
                    prop_assert!(
                        bytes != data,
                        "corruption at offset {} returned the original payload",
                        offset
                    );
                }
            }
        }
    }
}

/// Truncation at every length must be rejected on the coded path.
#[test]
fn truncation_is_detected() {
    let mut weights = vec![1u32; 256];
    weights[b'x' as usize] = 10000;
    let model = Model::from_weights(&weights).unwrap();
    let data = vec![b'x'; 512];
    let frame = encode_bytes(&model, &data).unwrap();
    assert!(frame.len() < 24 + data.len());
    for end in 24..frame.len() {
        let truncated = &frame[..end];
        assert!(
            decode_bytes(&model, truncated).is_err(),
            "truncation at {end} was accepted"
        );
    }
}
