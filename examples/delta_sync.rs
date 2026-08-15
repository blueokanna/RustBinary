//! Differential frames and IBLT set reconciliation for gossip.
//!
//! Run: `cargo run --example delta_sync --features reconcile`
//!
//! Two complementary mechanisms:
//!
//! - [`rustbinary::DeltaConfig`] encodes a value relative to a negotiated
//!   baseline (`value - base`), and a deterministic HPACK-style dynamic table
//!   turns repeated values into table references.
//! - [`rustbinary::Iblt`] reconciles unordered sets: two peers encode their
//!   sets, one side subtracts, and peeling recovers exactly the symmetric
//!   difference.

use rustbinary::{encode_set, reconcile, DeltaTable};

fn main() -> rustbinary::Result<()> {
    // --- 1. Baseline-relative integer deltas -------------------------------
    let config = rustbinary::options().with_delta_encoding();
    let baseline: i128 = 1_000_000_000;
    let new_value: i128 = 1_000_000_137;
    let delta = config.encode_delta(baseline, new_value)?;
    let decoded = config.decode_delta(baseline, &delta)?;
    assert_eq!(decoded, new_value);
    println!(
        "delta frame: {} bytes for a +{} change against the baseline",
        delta.len(),
        new_value - baseline
    );

    // --- 2. HPACK-style dynamic table --------------------------------------
    let mut sender = DeltaTable::new(16);
    let mut receiver = DeltaTable::new(16);
    let updates: Vec<&[u8]> = vec![
        b"consensus/height/1_000_000",
        b"consensus/height/1_000_001",
        b"consensus/height/1_000_002",
        b"consensus/height/1_000_001", // repeated -> 1-byte table reference
        b"consensus/height/1_000_002", // repeated -> table reference
    ];
    let frame = config.encode_updates(&mut sender, &updates)?;
    let decoded_updates = config.decode_updates(&mut receiver, &frame)?;
    assert_eq!(decoded_updates, updates);
    println!(
        "update frame: {} bytes for 5 updates (repeated keys become references); \
         both tables converged: {}",
        frame.len(),
        sender.len() == receiver.len()
    );

    // --- 3. IBLT set reconciliation ----------------------------------------
    let common: Vec<(u64, u64)> = (0..500).map(|i| (i * 7 + 1, i)).collect();
    let mut mine_set = common.clone();
    mine_set.extend((1000..1010).map(|i| (i, i * 3)));
    let mut theirs_set = common.clone();
    theirs_set.extend((2000..2005).map(|i| (i, i * 5)));

    let mine = encode_set(&mine_set, 1024);
    let theirs = encode_set(&theirs_set, 1024);
    let difference = reconcile(&mine, &theirs)?;
    let only_mine: Vec<(u64, u64)> = difference
        .iter()
        .filter(|entry| entry.present_in_self)
        .map(|entry| (entry.key, entry.value))
        .collect();
    let only_theirs: Vec<(u64, u64)> = difference
        .iter()
        .filter(|entry| !entry.present_in_self)
        .map(|entry| (entry.key, entry.value))
        .collect();
    println!(
        "IBLT difference: {} entries in mine only, {} in theirs only",
        only_mine.len(),
        only_theirs.len()
    );
    assert_eq!(only_mine.len(), 10);
    assert_eq!(only_theirs.len(), 5);
    Ok(())
}
