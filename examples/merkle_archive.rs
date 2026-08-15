//! Merkle-verified memory-mapped archives with self-contained proofs.
//!
//! Run: `cargo run --example merkle_archive --features archive`
//!
//! Every archive (format v2) carries a SHA-256 Merkle root over fixed-size
//! payload blocks. This example shows both access modes:
//!
//! - full [`rustbinary::archive::MappedArchive::open`] (validate everything
//!   once), and
//! - header-only opening + per-range [`rustbinary::archive::MerkleProof`]
//!   verification, the O(log n) light-client flow.

use rustbinary::archive::{
    build, ArchiveError, ArchiveLimits, ArchiveSchema, MappedArchive, OwnedArchive,
};

#[derive(rustbinary::archive::Archive, rustbinary::archive::Serialize)]
struct Ledger {
    epoch: u64,
    // 64 KiB of state so the archive spans many Merkle blocks.
    state: Vec<u8>,
}

impl ArchiveSchema for Ledger {
    const SCHEMA_ID: u64 = 0x4c45_4447_4552_0001;
}

fn main() -> Result<(), ArchiveError> {
    let limits = ArchiveLimits::new().with_merkle_block_size(256);
    let ledger = Ledger {
        epoch: 7,
        state: (0..65_536).map(|i| (i * 13 % 251) as u8).collect(),
    };
    let archive: OwnedArchive<Ledger> = build(&ledger, limits)?;
    println!(
        "archive: {} bytes, {} Merkle blocks of {} bytes, root {}",
        archive.as_bytes().len(),
        archive.header().block_count(),
        archive.header().block_size(),
        hex_prefix(&archive.root_digest())
    );

    // Proofs are self-contained: blocks + siblings + root. A light client
    // that only holds the root can verify a range without the file.
    let proof = archive.proof_for(0, 1024)?;
    proof.verify()?;
    let extracted = proof.extract()?;
    assert_eq!(extracted, &archive.payload()[..1024]);
    println!(
        "range [0, 1024) verified: {} proof blocks, {} sibling hashes",
        proof.block_count(),
        proof.siblings().len()
    );

    // Write the archive and re-open it fully.
    let path = std::env::temp_dir().join("rustbinary-merkle-example.rba");
    let _ = std::fs::remove_file(&path);
    archive.write_new(&path)?;
    // SAFETY: unique owned path, no concurrent writer.
    let mapped = unsafe { MappedArchive::<Ledger>::open(&path, limits) }?;
    let _ = std::fs::remove_file(&path);
    println!(
        "mapped epoch={} root matches: {}",
        mapped.root().epoch,
        mapped.root_digest() == archive.root_digest()
    );

    // A tampered payload is caught by proof verification even in header-only
    // mode (the forensic-on-access path). The corrupted byte must fall inside
    // the proved range for the proof to be invalidated.
    let mut tampered = archive.as_bytes().to_vec();
    tampered[rustbinary::archive::PAYLOAD_OFFSET + 4200] ^= 0x40;
    let tampered_path = std::env::temp_dir().join("rustbinary-merkle-tampered.rba");
    let _ = std::fs::remove_file(&tampered_path);
    std::fs::write(&tampered_path, &tampered).unwrap();
    // SAFETY: unique owned path, no concurrent writer.
    let header_only = unsafe { MappedArchive::<Ledger>::open_header_only(&tampered_path, limits) }?;
    let _ = std::fs::remove_file(&tampered_path);
    let bad_proof = header_only.proof_for(4096, 512)?;
    println!(
        "tampered range verification failed as expected: {}",
        bad_proof.verify().is_err()
    );
    Ok(())
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
