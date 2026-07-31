use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Partition {
    sequence: u64,
    payload: Vec<u8>,
}

fn main() -> rustbinary::Result<()> {
    let values = (0..256)
        .map(|sequence| Partition {
            sequence,
            payload: vec![sequence as u8; 1024],
        })
        .collect::<Vec<_>>();

    let base = rustbinary::options()
        .with_limit(2 * 1024 * 1024)
        .with_collection_limit(4096);
    let single = base
        .with_parallel_serialization()
        .with_worker_count(NonZeroUsize::MIN);
    let parallel = base
        .with_parallel_serialization()
        .with_worker_count(NonZeroUsize::new(4).expect("four is non-zero"));

    // Scheduling never affects bytes: each item has an ordered length-table slot.
    let canonical = single.serialize_batch(&values)?;
    assert_eq!(parallel.serialize_batch(&values)?, canonical);
    assert_eq!(parallel.deserialize_batch::<Partition>(&canonical)?, values);

    Ok(())
}
