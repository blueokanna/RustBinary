//! Validates the nextjson event contract independently of the wire format.

use crate::{tags::MAX_DEPTH, Config, Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Array,
    Object,
}

#[derive(Clone, Copy)]
struct Frame {
    kind: Kind,
    pending: bool,
    entries: u64,
}

pub(crate) struct EncodeState {
    frames: [Frame; MAX_DEPTH],
    depth: usize,
    root_written: bool,
    config: Config,
}

impl EncodeState {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            frames: [Frame {
                kind: Kind::Array,
                pending: false,
                entries: 0,
            }; MAX_DEPTH],
            depth: 0,
            root_written: false,
            config,
        }
    }

    pub(crate) fn value(&mut self) -> Result<()> {
        if self.depth == 0 {
            if self.root_written {
                return Err(Error::Custom("multiple root values".into()));
            }
            self.root_written = true;
        } else {
            let frame = &mut self.frames[self.depth - 1];
            if !frame.pending {
                return Err(Error::Custom(
                    "value requires an array separator or object key".into(),
                ));
            }
            frame.pending = false;
        }
        Ok(())
    }

    pub(crate) fn begin(&mut self, kind: Kind) -> Result<()> {
        if self.depth >= self.config.depth_limit {
            return Err(Error::DepthLimit {
                limit: self.config.depth_limit,
            });
        }
        self.value()?;
        self.frames[self.depth] = Frame {
            kind,
            pending: false,
            entries: 0,
        };
        self.depth += 1;
        Ok(())
    }

    pub(crate) fn entry(&mut self, kind: Kind) -> Result<()> {
        let index = self
            .depth
            .checked_sub(1)
            .ok_or_else(|| Error::Custom("entry outside a container".into()))?;
        let frame = &mut self.frames[index];
        if frame.kind != kind || frame.pending {
            return Err(Error::Custom("invalid container entry event".into()));
        }
        let entries = frame
            .entries
            .checked_add(1)
            .ok_or(Error::CollectionLimit { limit: u64::MAX })?;
        if let Some(limit) = self.config.collection_limit {
            if entries > limit {
                return Err(Error::CollectionLimit { limit });
            }
        }
        frame.entries = entries;
        frame.pending = true;
        Ok(())
    }

    pub(crate) fn end(&mut self, kind: Kind) -> Result<()> {
        let index = self
            .depth
            .checked_sub(1)
            .ok_or_else(|| Error::Custom("container end without matching start".into()))?;
        let frame = self.frames[index];
        if frame.kind != kind || frame.pending {
            return Err(Error::Custom(
                "mismatched or incomplete container end".into(),
            ));
        }
        self.depth = index;
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if !self.root_written || self.depth != 0 {
            return Err(Error::Custom(
                "encoder requires one complete root value".into(),
            ));
        }
        Ok(())
    }
}
