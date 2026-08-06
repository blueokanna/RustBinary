//! Validated relative-pointer archives for read-only memory mapping.
//!
//! This module is deliberately separate from the Serde stream codec. Archive
//! values use rkyv's flat, relative-pointer layout and can be accessed in place
//! after one structural validation pass. RustBinary adds a stable envelope,
//! explicit application schema identifiers, resource limits, and a read-only
//! mmap owner.
//!
//! Mapped files must be immutable for the complete lifetime of a
//! [`MappedArchive`](crate::archive::MappedArchive). The operating system cannot enforce that requirement
//! against every other process, so opening a file mapping is an unsafe
//! operation with a precise safety contract.

use core::{fmt, marker::PhantomData, mem::align_of, ops::Range};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
};

use memmap2::{Mmap, MmapOptions};
use rkyv::{
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    rancor::Error as RkyvError,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    Portable,
};

use crate::ErrorCategory;

/// Re-exported derives and traits used to define archive-native types.
pub use rkyv::{Archive, Deserialize, Serialize};

const MAGIC: [u8; 8] = *b"RBARCV01";
const FORMAT_VERSION: u16 = 1;
const FORMAT_FLAGS: u16 = 0x0003;
const HEADER_LEN: usize = 64;
const PAYLOAD_OFFSET: usize = HEADER_LEN;
const MAX_ARCHIVE_ALIGNMENT: usize = 64;

/// Default maximum size accepted for one archive file: 1 GiB.
pub const DEFAULT_ARCHIVE_SIZE_LIMIT: u64 = 1024 * 1024 * 1024;

/// Resource policy applied before allocation, validation, or mapping access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    max_file_size: u64,
}

impl ArchiveLimits {
    /// Creates a policy with the conservative 1 GiB default file limit.
    pub const fn new() -> Self {
        Self {
            max_file_size: DEFAULT_ARCHIVE_SIZE_LIMIT,
        }
    }

    /// Sets the maximum complete archive size, including the envelope.
    pub const fn with_max_file_size(mut self, max_file_size: u64) -> Self {
        self.max_file_size = max_file_size;
        self
    }

    /// Returns the configured complete-file limit.
    pub const fn max_file_size(self) -> u64 {
        self.max_file_size
    }
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable application identity for an archive root type.
///
/// The identifier is chosen and versioned by the application. It must change
/// whenever the archived field layout changes incompatibly. Zero is reserved
/// and rejected so an omitted schema decision cannot silently reach storage.
pub trait ArchiveSchema: Archive {
    /// Non-zero application-controlled schema identifier.
    const SCHEMA_ID: u64;
}

/// Parsed RustBinary archive envelope metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveHeader {
    schema_id: u64,
    payload_len: u64,
    file_len: u64,
}

impl ArchiveHeader {
    /// Returns the envelope format version.
    pub const fn format_version(self) -> u16 {
        FORMAT_VERSION
    }

    /// Returns the application-controlled root schema identifier.
    pub const fn schema_id(self) -> u64 {
        self.schema_id
    }

    /// Returns the rkyv payload length in bytes.
    pub const fn payload_len(self) -> u64 {
        self.payload_len
    }

    /// Returns the complete envelope and payload length.
    pub const fn file_len(self) -> u64 {
        self.file_len
    }
}

/// Failure while building, validating, writing, or mapping an archive.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArchiveError {
    /// File or mapping I/O failed.
    Io(io::Error),
    /// The configured complete-file limit was exceeded.
    SizeLimit {
        /// Configured maximum size.
        limit: u64,
        /// Size that was supplied or required.
        actual: u64,
    },
    /// The envelope is truncated or violates the format contract.
    InvalidHeader(&'static str),
    /// The root type uses the reserved zero application schema identifier.
    InvalidSchemaId,
    /// The application schema does not match the requested root type.
    SchemaMismatch {
        /// Schema required by the requested type.
        expected: u64,
        /// Schema stored in the archive envelope.
        actual: u64,
    },
    /// The root's alignment exceeds the archive envelope guarantee.
    UnsupportedAlignment {
        /// Alignment required by the archived root.
        required: usize,
        /// Maximum alignment guaranteed by the envelope.
        supported: usize,
    },
    /// The native value could not be converted to an archive layout.
    Serialization(String),
    /// The relative-pointer graph or an archived value failed byte validation.
    Validation(String),
}

impl ArchiveError {
    /// Returns the stable operational responsibility for this failure.
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Io(_) | Self::SizeLimit { .. } | Self::UnsupportedAlignment { .. } => {
                ErrorCategory::Configuration
            }
            Self::InvalidHeader(_) | Self::SchemaMismatch { .. } | Self::Validation(_) => {
                ErrorCategory::Protocol
            }
            Self::InvalidSchemaId => ErrorCategory::Configuration,
            Self::Serialization(_) => ErrorCategory::UserInput,
        }
    }
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "archive I/O error: {error}"),
            Self::SizeLimit { limit, actual } => write!(
                f,
                "archive size {actual} exceeds the configured limit of {limit} bytes"
            ),
            Self::InvalidHeader(reason) => write!(f, "invalid archive header: {reason}"),
            Self::InvalidSchemaId => {
                f.write_str("archive root uses the reserved zero schema identifier")
            }
            Self::SchemaMismatch { expected, actual } => write!(
                f,
                "archive schema mismatch: expected {expected:#018x}, found {actual:#018x}"
            ),
            Self::UnsupportedAlignment {
                required,
                supported,
            } => write!(
                f,
                "archived root requires {required}-byte alignment; at most {supported} is supported"
            ),
            Self::Serialization(message) => write!(f, "archive serialization failed: {message}"),
            Self::Validation(message) => write!(f, "archive validation failed: {message}"),
        }
    }
}

impl std::error::Error for ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Immutable, aligned archive bytes owned by the current process.
pub struct OwnedArchive<T: ArchiveSchema> {
    bytes: AlignedVec<MAX_ARCHIVE_ALIGNMENT>,
    payload: Range<usize>,
    header: ArchiveHeader,
    marker: PhantomData<T>,
}

impl<T: ArchiveSchema> OwnedArchive<T> {
    /// Returns the parsed envelope metadata.
    pub const fn header(&self) -> ArchiveHeader {
        self.header
    }

    /// Returns the complete versioned archive bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the validated rkyv payload bytes without the envelope.
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload.clone()]
    }

    /// Creates a new immutable archive file and flushes its contents.
    ///
    /// Existing files are never overwritten. If writing or syncing fails, the
    /// newly created partial file is removed before returning the error.
    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<(), ArchiveError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let result = (|| {
            file.write_all(self.as_bytes())?;
            file.sync_all()
        })();
        if let Err(error) = result {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(ArchiveError::Io(error));
        }
        Ok(())
    }
}

impl<T> OwnedArchive<T>
where
    T: ArchiveSchema,
    T::Archived: Portable,
{
    /// Returns the archived root without allocating or deserializing.
    pub fn root(&self) -> &T::Archived {
        // SAFETY: `build` validates the immutable private payload before
        // constructing `OwnedArchive`; callers can only borrow these bytes.
        unsafe { rkyv::access_unchecked::<T::Archived>(self.payload()) }
    }
}

/// Read-only owner for a validated memory-mapped archive.
pub struct MappedArchive<T: ArchiveSchema> {
    map: Mmap,
    payload: Range<usize>,
    header: ArchiveHeader,
    marker: PhantomData<T>,
}

impl<T> MappedArchive<T>
where
    T: ArchiveSchema,
    T::Archived: Portable + for<'a> CheckBytes<HighValidator<'a, RkyvError>>,
{
    /// Opens, maps, and fully validates an immutable archive file.
    ///
    /// # Safety
    ///
    /// No process may modify or truncate the file for the complete lifetime of
    /// the returned mapping. Writers must publish immutable files under a new
    /// path and replace references to the path, never mutate a mapped file in
    /// place. Violating this condition can invalidate Rust references and cause
    /// undefined behavior.
    pub unsafe fn open(
        path: impl AsRef<Path>,
        limits: ArchiveLimits,
    ) -> Result<Self, ArchiveError> {
        let file = File::open(path)?;
        let metadata_len = file.metadata()?.len();
        check_size_limit(metadata_len, limits)?;
        if metadata_len < HEADER_LEN as u64 {
            return Err(ArchiveError::InvalidHeader(
                "file is shorter than the envelope",
            ));
        }

        // SAFETY: The caller guarantees external immutability for the mapping
        // lifetime, which is the platform requirement not expressible in Rust.
        let map = unsafe { MmapOptions::new().map(&file) }?;
        let (header, payload) = validate_archive::<T>(&map, limits)?;
        Ok(Self {
            map,
            payload,
            header,
            marker: PhantomData,
        })
    }

    /// Returns the parsed envelope metadata.
    pub const fn header(&self) -> ArchiveHeader {
        self.header
    }

    /// Returns the complete mapped file bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.map
    }

    /// Returns the mapped rkyv payload bytes without the envelope.
    pub fn payload(&self) -> &[u8] {
        &self.map[self.payload.clone()]
    }

    /// Returns the archived root without allocation or deserialization.
    pub fn root(&self) -> &T::Archived {
        // SAFETY: `open` structurally validates the read-only payload, and its
        // safety contract requires the mapped file to remain immutable.
        unsafe { rkyv::access_unchecked::<T::Archived>(self.payload()) }
    }
}

/// Builds and validates an aligned, versioned archive in owned memory.
pub fn build<T>(value: &T, limits: ArchiveLimits) -> Result<OwnedArchive<T>, ArchiveError>
where
    T: ArchiveSchema
        + for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RkyvError>>,
    T::Archived: Portable + for<'a> CheckBytes<HighValidator<'a, RkyvError>>,
{
    validate_schema_id::<T>()?;
    validate_alignment::<T>()?;

    let payload = rkyv::to_bytes::<RkyvError>(value)
        .map_err(|error| ArchiveError::Serialization(error.to_string()))?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| ArchiveError::SizeLimit {
        limit: limits.max_file_size(),
        actual: u64::MAX,
    })?;
    let file_len = (HEADER_LEN as u64)
        .checked_add(payload_len)
        .ok_or(ArchiveError::SizeLimit {
            limit: limits.max_file_size(),
            actual: u64::MAX,
        })?;
    check_size_limit(file_len, limits)?;

    let header = ArchiveHeader {
        schema_id: T::SCHEMA_ID,
        payload_len,
        file_len,
    };
    let capacity = usize::try_from(file_len).map_err(|_| ArchiveError::SizeLimit {
        limit: limits.max_file_size(),
        actual: file_len,
    })?;
    let mut bytes = AlignedVec::<MAX_ARCHIVE_ALIGNMENT>::with_capacity(capacity);
    bytes.extend_from_slice(&encode_header(header));
    bytes.extend_from_slice(&payload);

    let (_, payload_range) = validate_archive::<T>(&bytes, limits)?;
    Ok(OwnedArchive {
        bytes,
        payload: payload_range,
        header,
        marker: PhantomData,
    })
}

/// Validates an archive slice and returns its zero-copy root view.
///
/// This function performs structural validation on every call. Use
/// [`OwnedArchive::root`] or [`MappedArchive::root`] when validation should be
/// paid once and subsequent accesses should be constant-time.
pub fn access<T>(bytes: &[u8], limits: ArchiveLimits) -> Result<&T::Archived, ArchiveError>
where
    T: ArchiveSchema,
    T::Archived: Portable + for<'a> CheckBytes<HighValidator<'a, RkyvError>>,
{
    let (_, payload) = validate_archive::<T>(bytes, limits)?;
    rkyv::access::<T::Archived, RkyvError>(&bytes[payload])
        .map_err(|error| ArchiveError::Validation(error.to_string()))
}

fn validate_archive<T>(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<(ArchiveHeader, Range<usize>), ArchiveError>
where
    T: ArchiveSchema,
    T::Archived: Portable + for<'a> CheckBytes<HighValidator<'a, RkyvError>>,
{
    validate_schema_id::<T>()?;
    validate_alignment::<T>()?;
    let header = parse_header(bytes, limits)?;
    if header.schema_id != T::SCHEMA_ID {
        return Err(ArchiveError::SchemaMismatch {
            expected: T::SCHEMA_ID,
            actual: header.schema_id,
        });
    }
    let payload_len = usize::try_from(header.payload_len)
        .map_err(|_| ArchiveError::InvalidHeader("payload length does not fit usize"))?;
    let payload_end = PAYLOAD_OFFSET
        .checked_add(payload_len)
        .ok_or(ArchiveError::InvalidHeader("payload range overflows usize"))?;
    let payload = PAYLOAD_OFFSET..payload_end;
    let payload_bytes = &bytes[payload.clone()];
    let required_alignment = align_of::<T::Archived>();
    if !(payload_bytes.as_ptr() as usize).is_multiple_of(required_alignment) {
        return Err(ArchiveError::Validation(
            "payload base does not satisfy archived root alignment".into(),
        ));
    }
    rkyv::access::<T::Archived, RkyvError>(payload_bytes)
        .map_err(|error| ArchiveError::Validation(error.to_string()))?;
    Ok((header, payload))
}

fn parse_header(bytes: &[u8], limits: ArchiveLimits) -> Result<ArchiveHeader, ArchiveError> {
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    check_size_limit(actual, limits)?;
    if bytes.len() < HEADER_LEN {
        return Err(ArchiveError::InvalidHeader(
            "file is shorter than the envelope",
        ));
    }
    if bytes[..8] != MAGIC {
        return Err(ArchiveError::InvalidHeader("magic does not match"));
    }
    if read_u16(bytes, 8) != FORMAT_VERSION {
        return Err(ArchiveError::InvalidHeader("unsupported format version"));
    }
    if read_u16(bytes, 10) != FORMAT_FLAGS {
        return Err(ArchiveError::InvalidHeader("format flags do not match"));
    }
    if read_u32(bytes, 12) != HEADER_LEN as u32 {
        return Err(ArchiveError::InvalidHeader("header length does not match"));
    }
    let schema_id = read_u64(bytes, 16);
    if schema_id == 0 {
        return Err(ArchiveError::InvalidHeader("schema identifier is zero"));
    }
    let payload_len = read_u64(bytes, 24);
    if read_u64(bytes, 32) != PAYLOAD_OFFSET as u64 {
        return Err(ArchiveError::InvalidHeader("payload offset does not match"));
    }
    let file_len = read_u64(bytes, 40);
    if file_len != actual {
        return Err(ArchiveError::InvalidHeader(
            "declared file length does not match",
        ));
    }
    let expected_file_len =
        (HEADER_LEN as u64)
            .checked_add(payload_len)
            .ok_or(ArchiveError::InvalidHeader(
                "declared payload length overflows",
            ))?;
    if expected_file_len != file_len {
        return Err(ArchiveError::InvalidHeader(
            "declared payload length does not match",
        ));
    }
    if bytes[48..HEADER_LEN].iter().any(|&byte| byte != 0) {
        return Err(ArchiveError::InvalidHeader(
            "reserved header bytes are non-zero",
        ));
    }
    Ok(ArchiveHeader {
        schema_id,
        payload_len,
        file_len,
    })
}

fn encode_header(header: ArchiveHeader) -> [u8; HEADER_LEN] {
    let mut bytes = [0_u8; HEADER_LEN];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&FORMAT_FLAGS.to_le_bytes());
    bytes[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&header.schema_id.to_le_bytes());
    bytes[24..32].copy_from_slice(&header.payload_len.to_le_bytes());
    bytes[32..40].copy_from_slice(&(PAYLOAD_OFFSET as u64).to_le_bytes());
    bytes[40..48].copy_from_slice(&header.file_len.to_le_bytes());
    bytes
}

fn check_size_limit(actual: u64, limits: ArchiveLimits) -> Result<(), ArchiveError> {
    if actual > limits.max_file_size() {
        Err(ArchiveError::SizeLimit {
            limit: limits.max_file_size(),
            actual,
        })
    } else {
        Ok(())
    }
}

fn validate_schema_id<T: ArchiveSchema>() -> Result<(), ArchiveError> {
    if T::SCHEMA_ID == 0 {
        Err(ArchiveError::InvalidSchemaId)
    } else {
        Ok(())
    }
}

fn validate_alignment<T: ArchiveSchema>() -> Result<(), ArchiveError>
where
    T::Archived: Portable,
{
    let required = align_of::<T::Archived>();
    if required > MAX_ARCHIVE_ALIGNMENT {
        Err(ArchiveError::UnsupportedAlignment {
            required,
            supported: MAX_ARCHIVE_ALIGNMENT,
        })
    } else {
        Ok(())
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut value = [0_u8; 2];
    value.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(value)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0_u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

    struct TemporaryArchive(PathBuf);

    impl TemporaryArchive {
        fn new() -> Self {
            let id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "rustbinary-archive-test-{}-{id}.rba",
                std::process::id()
            )))
        }
    }

    impl Drop for TemporaryArchive {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[derive(Archive, Serialize)]
    struct Root {
        sequence: u64,
        name: String,
        samples: Vec<i32>,
    }

    impl ArchiveSchema for Root {
        const SCHEMA_ID: u64 = 0x5255_5354_4249_4e31;
    }

    #[derive(Archive, Serialize)]
    struct OtherRoot {
        sequence: u64,
        name: String,
        samples: Vec<i32>,
    }

    impl ArchiveSchema for OtherRoot {
        const SCHEMA_ID: u64 = 0x5255_5354_4249_4e32;
    }

    #[derive(Archive)]
    struct InvalidSchemaRoot;

    impl ArchiveSchema for InvalidSchemaRoot {
        const SCHEMA_ID: u64 = 0;
    }

    fn value() -> Root {
        Root {
            sequence: 42,
            name: "mapped".into(),
            samples: vec![-7, 0, 11, 65_536],
        }
    }

    fn expect_error<T>(result: Result<T, ArchiveError>) -> ArchiveError {
        match result {
            Ok(_) => panic!("expected archive operation to fail"),
            Err(error) => error,
        }
    }

    #[test]
    fn owned_archive_validates_and_borrows_relative_fields() {
        let archive = build(&value(), ArchiveLimits::new()).unwrap();
        const GOLDEN: &[u8] = &[
            0x52, 0x42, 0x41, 0x52, 0x43, 0x56, 0x30, 0x31, 0x01, 0x00, 0x03, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x31, 0x4e, 0x49, 0x42, 0x54, 0x53, 0x55, 0x52, 0x28, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf9, 0xff, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2a, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x6d, 0x61, 0x70, 0x70, 0x65, 0x64, 0xff, 0xff, 0xe0, 0xff,
            0xff, 0xff, 0x04, 0x00, 0x00, 0x00,
        ];
        assert_eq!(archive.as_bytes(), GOLDEN);
        let root = archive.root();
        assert_eq!(root.sequence, 42);
        assert_eq!(root.name.as_str(), "mapped");
        assert_eq!(root.samples.as_slice(), [-7, 0, 11, 65_536]);

        let start = archive.as_bytes().as_ptr() as usize;
        let end = start + archive.as_bytes().len();
        let name = root.name.as_bytes().as_ptr() as usize;
        let samples = root.samples.as_ptr() as usize;
        assert!((start..end).contains(&name));
        assert!((start..end).contains(&samples));
        assert_eq!(
            access::<Root>(archive.as_bytes(), ArchiveLimits::new())
                .unwrap()
                .sequence,
            42
        );
    }

    #[test]
    fn envelope_rejects_corruption_schema_drift_and_resource_abuse() {
        let archive = build(&value(), ArchiveLimits::new()).unwrap();
        let schema_error = expect_error(access::<OtherRoot>(
            archive.as_bytes(),
            ArchiveLimits::new(),
        ));
        assert!(matches!(schema_error, ArchiveError::SchemaMismatch { .. }));
        assert_eq!(schema_error.category(), ErrorCategory::Protocol);

        let limit_error = expect_error(access::<Root>(
            archive.as_bytes(),
            ArchiveLimits::new().with_max_file_size(16),
        ));
        assert!(matches!(limit_error, ArchiveError::SizeLimit { .. }));
        assert_eq!(limit_error.category(), ErrorCategory::Configuration);

        let schema_id_error = expect_error(access::<InvalidSchemaRoot>(
            archive.as_bytes(),
            ArchiveLimits::new(),
        ));
        assert!(matches!(schema_id_error, ArchiveError::InvalidSchemaId));
        assert_eq!(schema_id_error.category(), ErrorCategory::Configuration);
        assert!(matches!(
            access::<Root>(&archive.as_bytes()[..32], ArchiveLimits::new()),
            Err(ArchiveError::InvalidHeader(_))
        ));

        let mut corrupted = archive.as_bytes().to_vec();
        corrupted[0] ^= 1;
        assert!(matches!(
            access::<Root>(&corrupted, ArchiveLimits::new()),
            Err(ArchiveError::InvalidHeader("magic does not match"))
        ));

        let mut reserved = archive.as_bytes().to_vec();
        reserved[63] = 1;
        assert!(matches!(
            access::<Root>(&reserved, ArchiveLimits::new()),
            Err(ArchiveError::InvalidHeader(
                "reserved header bytes are non-zero"
            ))
        ));

        let mut invalid_graph = AlignedVec::<MAX_ARCHIVE_ALIGNMENT>::new();
        invalid_graph.extend_from_slice(archive.as_bytes());
        invalid_graph[PAYLOAD_OFFSET..].fill(0xff);
        assert!(matches!(
            access::<Root>(&invalid_graph, ArchiveLimits::new()),
            Err(ArchiveError::Validation(_))
        ));
    }

    #[test]
    fn file_archive_maps_and_accesses_fields_in_place() {
        let file = TemporaryArchive::new();
        let archive = build(&value(), ArchiveLimits::new()).unwrap();
        archive.write_new(&file.0).unwrap();

        // SAFETY: This test owns the unique file path and never opens a writer
        // while the map is alive. The cleanup guard removes it only after drop.
        let mapped = unsafe { MappedArchive::<Root>::open(&file.0, ArchiveLimits::new()) }.unwrap();
        let root = mapped.root();
        assert_eq!(root.name.as_str(), "mapped");
        assert_eq!(root.samples.as_slice(), [-7, 0, 11, 65_536]);

        let start = mapped.as_bytes().as_ptr() as usize;
        let end = start + mapped.as_bytes().len();
        assert!((start..end).contains(&(root.name.as_bytes().as_ptr() as usize)));
        assert!((start..end).contains(&(root.samples.as_ptr() as usize)));
    }
}
