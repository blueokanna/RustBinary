use std::{num::NonZeroUsize, thread};

use crate::{Config, Error, Result, TrailingBytes};

const MAGIC: &[u8; 4] = b"RBP1";
const VERSION: u16 = 1;
const HEADER_SIZE: usize = 16;

/// Ordered parallel batch codec over a base binary configuration.
///
/// Elements are encoded independently on scoped worker threads. The frame
/// stores an ordered length table, so scheduling cannot affect output bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParallelConfig {
    base: Config,
    workers: NonZeroUsize,
}

impl ParallelConfig {
    pub(crate) fn new(base: Config) -> Self {
        Self {
            base,
            workers: thread::available_parallelism().unwrap_or(NonZeroUsize::MIN),
        }
    }

    /// Returns the underlying wire and resource configuration.
    pub const fn base_config(self) -> Config {
        self.base
    }

    /// Uses at most `workers` scoped threads.
    pub const fn with_worker_count(mut self, workers: NonZeroUsize) -> Self {
        self.workers = workers;
        self
    }

    /// Returns the configured worker ceiling.
    pub const fn worker_count(self) -> NonZeroUsize {
        self.workers
    }

    /// Encodes an ordered collection as a deterministic parallel batch frame.
    pub fn serialize_batch<T: nextjson::NsonSerialize + Sync>(
        self,
        values: &[T],
    ) -> Result<Vec<u8>> {
        self.enforce_collection_limit(values.len())?;
        let payloads = parallel_map(values, self.workers.get(), |value| {
            self.base.serialize(value)
        })?;

        let table_size = values
            .len()
            .checked_mul(size_of::<u64>())
            .ok_or(Error::InvalidFrame("parallel length table overflow"))?;
        let mut required = HEADER_SIZE
            .checked_add(table_size)
            .ok_or(Error::InvalidFrame("parallel frame size overflow"))?;
        for payload in &payloads {
            required = required
                .checked_add(payload.len())
                .ok_or(Error::InvalidFrame("parallel frame size overflow"))?;
        }
        self.enforce_byte_limit(required)?;

        let mut output = Vec::new();
        output
            .try_reserve_exact(required)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&VERSION.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&(values.len() as u64).to_le_bytes());
        for payload in &payloads {
            output.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        }
        for payload in payloads {
            output.extend_from_slice(&payload);
        }
        debug_assert_eq!(output.len(), required);
        Ok(output)
    }

    /// Validates and decodes an ordered parallel batch frame.
    pub fn deserialize_batch<T: for<'de> nextjson::NsonDeserialize<'de> + Send>(
        self,
        input: &[u8],
    ) -> Result<Vec<T>> {
        self.enforce_byte_limit(input.len())?;
        let mut cursor = FrameCursor::new(input);
        if cursor.take(4)? != MAGIC {
            return Err(Error::InvalidFrame("bad parallel batch magic"));
        }
        if cursor.u16()? != VERSION {
            return Err(Error::InvalidFrame("unsupported parallel batch version"));
        }
        if cursor.u16()? != 0 {
            return Err(Error::InvalidFrame("unsupported parallel batch flags"));
        }
        let count = usize::try_from(cursor.u64()?)
            .map_err(|_| Error::IntegerOverflow { target: "usize" })?;
        self.enforce_collection_limit(count)?;

        let table_size = count
            .checked_mul(size_of::<u64>())
            .ok_or(Error::InvalidFrame("parallel length table overflow"))?;
        if table_size > cursor.remaining() {
            return Err(Error::UnexpectedEnd);
        }
        let mut lengths = Vec::new();
        lengths
            .try_reserve_exact(count)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        for _ in 0..count {
            lengths.push(
                usize::try_from(cursor.u64()?)
                    .map_err(|_| Error::IntegerOverflow { target: "usize" })?,
            );
        }

        let payload_bytes = lengths.iter().try_fold(0usize, |total, length| {
            total
                .checked_add(*length)
                .ok_or(Error::InvalidFrame("parallel payload size overflow"))
        })?;
        if payload_bytes > cursor.remaining() {
            return Err(Error::UnexpectedEnd);
        }
        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(count)
            .map_err(|_| Error::SizeLimit { limit: u64::MAX })?;
        for length in lengths {
            payloads.push(cursor.take(length)?);
        }
        cursor.finish(self.base.trailing)?;

        parallel_map(&payloads, self.workers.get(), |payload| {
            self.base.deserialize::<T>(payload)
        })
    }

    fn enforce_byte_limit(self, length: usize) -> Result<()> {
        if self.base.limit.is_some_and(|limit| length as u64 > limit) {
            return Err(Error::SizeLimit {
                limit: self.base.limit.expect("checked as some"),
            });
        }
        Ok(())
    }

    fn enforce_collection_limit(self, length: usize) -> Result<()> {
        if self
            .base
            .collection_limit
            .is_some_and(|limit| length as u64 > limit)
        {
            return Err(Error::CollectionLimit {
                limit: self.base.collection_limit.expect("checked as some"),
            });
        }
        Ok(())
    }
}

fn parallel_map<I, O, F>(items: &[I], workers: usize, operation: F) -> Result<Vec<O>>
where
    I: Sync,
    O: Send,
    F: Fn(&I) -> Result<O> + Sync,
{
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let worker_count = workers.min(items.len());
    let chunk_size = items.len().div_ceil(worker_count);
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for chunk in items.chunks(chunk_size) {
            let operation = &operation;
            handles
                .push(scope.spawn(move || chunk.iter().map(operation).collect::<Result<Vec<O>>>()));
        }
        let mut output = Vec::with_capacity(items.len());
        for handle in handles {
            let mut chunk = handle.join().map_err(|_| Error::ParallelWorkerPanic)??;
            output.append(&mut chunk);
        }
        Ok(output)
    })
}

struct FrameCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> FrameCursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    const fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::UnexpectedEnd)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(Error::UnexpectedEnd)?;
        self.position = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("fixed width"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed width"),
        ))
    }

    fn finish(self, trailing: TrailingBytes) -> Result<()> {
        if trailing == TrailingBytes::Reject && self.position != self.input.len() {
            return Err(Error::TrailingBytes {
                remaining: self.input.len() - self.position,
            });
        }
        Ok(())
    }
}
