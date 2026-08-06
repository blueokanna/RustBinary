use std::num::NonZeroUsize;

use rustbinary::core::{Error, ErrorCategory};
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

    let truncated = &canonical[..canonical.len() - 1];
    let truncated_error = parallel
        .deserialize_batch::<Partition>(truncated)
        .unwrap_err();
    assert!(matches!(&truncated_error, Error::UnexpectedEnd));
    assert_eq!(truncated_error.category(), ErrorCategory::UserInput);

    let bounded = rustbinary::options()
        .with_limit(2 * 1024 * 1024)
        .with_collection_limit(2)
        .with_parallel_serialization();
    let collection_error = bounded.serialize_batch(&values).unwrap_err();
    assert!(matches!(
        &collection_error,
        Error::CollectionLimit { limit: 2 }
    ));
    assert_eq!(collection_error.category(), ErrorCategory::Configuration);

    println!(
        "parallel batch: {} records, {} frame bytes, deterministic across 1 and 4 workers",
        values.len(),
        canonical.len()
    );

    Ok(())
}
