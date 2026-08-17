//! Tests for the `AdaptiveMode` analysis-policy knob
//! (`Off` / `Heuristic` / `Exact`).
//!
//! The mode is size-only: every strategy is lossless, so all modes decode the
//! same values; they differ in how many scan passes the encoder performs and
//! how many bytes the frame occupies.

#![cfg(feature = "adaptive")]

use rustbinary::{AdaptiveConfig, AdaptiveMode, CollectionStrategy, StringStrategy};

fn codec(mode: AdaptiveMode) -> AdaptiveConfig {
    rustbinary::options()
        .with_adaptive_encoding()
        .with_adaptive_mode(mode)
}

#[test]
fn off_is_the_default() {
    assert_eq!(AdaptiveMode::default(), AdaptiveMode::Off);
    assert_eq!(
        rustbinary::options().with_adaptive_encoding().mode(),
        AdaptiveMode::Off
    );
}

#[test]
fn off_encodes_delta_friendly_data_raw() {
    let values: Vec<i64> = (0..256).map(|i| 1000 + i).collect();
    let bytes = codec(AdaptiveMode::Off).encode_i64_slice(&values).unwrap();
    assert_eq!(
        codec(AdaptiveMode::Off)
            .collection_strategy(&bytes)
            .unwrap(),
        CollectionStrategy::Raw
    );
    assert_eq!(bytes[0], 0, "raw strategy tag");
    assert_eq!(
        codec(AdaptiveMode::Off).decode_i64_vec(&bytes).unwrap(),
        values
    );
}

#[test]
fn off_encodes_ascii_strings_raw() {
    let text = "a".repeat(200);
    let bytes = codec(AdaptiveMode::Off).encode_string(&text).unwrap();
    assert_eq!(
        codec(AdaptiveMode::Off).string_strategy(&bytes).unwrap(),
        StringStrategy::RawUtf8
    );
    assert_eq!(
        codec(AdaptiveMode::Off).decode_string(&bytes).unwrap(),
        text
    );
}

#[test]
fn exact_picks_delta_for_delta_friendly_data() {
    let values: Vec<i64> = (0..256).map(|i| 1000 + i).collect();
    let bytes = codec(AdaptiveMode::Exact)
        .encode_i64_slice(&values)
        .unwrap();
    assert_eq!(
        codec(AdaptiveMode::Exact)
            .collection_strategy(&bytes)
            .unwrap(),
        CollectionStrategy::Delta
    );
    assert_eq!(
        codec(AdaptiveMode::Exact).decode_i64_vec(&bytes).unwrap(),
        values
    );
}

#[test]
fn exact_picks_rle_for_run_heavy_data() {
    let values: Vec<i64> = (0..512).map(|i| (i / 16) as i64).collect();
    let bytes = codec(AdaptiveMode::Exact)
        .encode_i64_slice(&values)
        .unwrap();
    assert_eq!(
        codec(AdaptiveMode::Exact)
            .collection_strategy(&bytes)
            .unwrap(),
        CollectionStrategy::RunLength
    );
    assert_eq!(
        codec(AdaptiveMode::Exact).decode_i64_vec(&bytes).unwrap(),
        values
    );
}

#[test]
fn exact_picks_raw_for_noisy_data() {
    // Alternating tiny / huge values: the deltas are all ~±1,000,000, so
    // delta and run-length both cost more than independent raw varints.
    let values: Vec<i64> = (0..512)
        .map(|i| {
            if i % 2 == 0 {
                (i / 2) as i64
            } else {
                1_000_000 + (i / 2) as i64
            }
        })
        .collect();
    let bytes = codec(AdaptiveMode::Exact)
        .encode_i64_slice(&values)
        .unwrap();
    assert_eq!(
        codec(AdaptiveMode::Exact)
            .collection_strategy(&bytes)
            .unwrap(),
        CollectionStrategy::Raw
    );
    assert_eq!(
        codec(AdaptiveMode::Exact).decode_i64_vec(&bytes).unwrap(),
        values
    );
}

#[test]
fn heuristic_matches_exact_when_the_sample_covers_the_input() {
    // Exactly `HEURISTIC_SAMPLE` elements: the sample is the whole input.
    let values: Vec<i64> = (0..rustbinary::HEURISTIC_SAMPLE as i64)
        .map(|i| 1000 + i)
        .collect();
    let heuristic = codec(AdaptiveMode::Heuristic)
        .encode_i64_slice(&values)
        .unwrap();
    let exact = codec(AdaptiveMode::Exact)
        .encode_i64_slice(&values)
        .unwrap();
    assert_eq!(heuristic, exact);
}

#[test]
fn heuristic_picks_delta_from_the_sample_prefix() {
    // A long ramp whose first `HEURISTIC_SAMPLE` elements are a clean delta
    // sequence: the sample alone must select delta.
    let values: Vec<i64> = (0..100_000).map(|i| 1000 + i % 10_000).collect();
    let bytes = codec(AdaptiveMode::Heuristic)
        .encode_i64_slice(&values)
        .unwrap();
    assert_eq!(
        codec(AdaptiveMode::Heuristic)
            .collection_strategy(&bytes)
            .unwrap(),
        CollectionStrategy::Delta
    );
    assert_eq!(
        codec(AdaptiveMode::Heuristic)
            .decode_i64_vec(&bytes)
            .unwrap(),
        values
    );
}

#[test]
fn all_modes_roundtrip_the_same_data() {
    let datasets: Vec<Vec<i64>> = vec![
        (0..500).map(|i| i * 3 - 2000).collect(),
        (0..500).map(|i| (i / 8) as i64).collect(),
        (0..500)
            .map(|i| ((i * 7919) % 100_000) as i64 - 50_000)
            .collect(),
    ];
    for values in &datasets {
        for mode in [
            AdaptiveMode::Off,
            AdaptiveMode::Heuristic,
            AdaptiveMode::Exact,
        ] {
            let codec = codec(mode);
            let bytes = codec.encode_i64_slice(values).unwrap();
            assert_eq!(
                codec.decode_i64_vec(&bytes).unwrap(),
                *values,
                "mode {mode:?}"
            );
        }
    }
}

#[test]
fn size_ordering_holds_on_compressible_data() {
    let ramp: Vec<i64> = (0..10_000).map(|i| 1000 + i).collect();
    let off = codec(AdaptiveMode::Off).encode_i64_slice(&ramp).unwrap();
    let heuristic = codec(AdaptiveMode::Heuristic)
        .encode_i64_slice(&ramp)
        .unwrap();
    let exact = codec(AdaptiveMode::Exact).encode_i64_slice(&ramp).unwrap();
    assert!(off.len() > heuristic.len());
    assert!(heuristic.len() >= exact.len());
    assert_eq!(
        codec(AdaptiveMode::Exact).decode_i64_vec(&off).unwrap(),
        ramp
    );
}

#[test]
fn string_modes_off_is_raw_heuristic_and_exact_are_ascii7() {
    let text = "abcdefghijklmnopqrstuvwxyz0123456789".repeat(8);
    let off = codec(AdaptiveMode::Off).encode_string(&text).unwrap();
    assert_eq!(
        codec(AdaptiveMode::Off).string_strategy(&off).unwrap(),
        StringStrategy::RawUtf8
    );
    let heuristic = codec(AdaptiveMode::Heuristic).encode_string(&text).unwrap();
    assert_eq!(
        codec(AdaptiveMode::Heuristic)
            .string_strategy(&heuristic)
            .unwrap(),
        StringStrategy::Ascii7
    );
    let exact = codec(AdaptiveMode::Exact).encode_string(&text).unwrap();
    assert_eq!(
        codec(AdaptiveMode::Exact).string_strategy(&exact).unwrap(),
        StringStrategy::Ascii7
    );
    // All three decoders agree on the same text regardless of the frame.
    for bytes in [&off, &heuristic, &exact] {
        assert_eq!(
            codec(AdaptiveMode::Exact).decode_string(bytes).unwrap(),
            text
        );
    }
}
