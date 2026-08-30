//! Projectable self-authenticating binary records.
//!
//! # Problem model
//!
//! A *self-authenticating record* `P` is a canonical byte string that encodes
//! a set of named fields, each a `(field_id, payload)` pair. A *projection
//! query* `q` selects a subset of fields. A *projection proof* `π` lets a
//! verifier learn the values of **exactly** the fields in `q`, tied to a
//! trusted root, without scanning or decoding the rest of the record.
//!
//! The guarantee this module provides is **projection soundness**:
//!
//! ```text
//! Verify(P, π, q) = v   ⟹   v = Project_q(Decode(P))
//! ```
//!
//! where `Decode(P)` is the unique canonical decoding of `P` (uniqueness
//! follows from the format's canonicality: strictly increasing `field_id`s,
//! fixed-width headers, no duplicate fields), and `Project_q` extracts the
//! fields selected by `q`. Fields outside `q` are never read, yet their
//! authenticity is still guaranteed: each is bound into the Merkle root by its
//! leaf hash, so a tampered or substituted unread field changes the root and
//! fails verification.
//!
//! # Construction
//!
//! - **Canonical field framing**: `field_id` (u32 LE) + `payload_len` (u32 LE)
//!   + `payload`. Records require strictly increasing `field_id`s, so every
//!   record has exactly one valid encoding and `Decode` is a function.
//! - **Leaf hashes**: `H(LEAF_DOMAIN ‖ field_id‖ payload_len ‖ payload)`.
//! - **Schema binding**: the record root is `H(SCHEMA_DOMAIN ‖ schema_version
//!   ‖ merkle_root)`, so a proof cannot be replayed against a different schema
//!   version.
//! - **Merkle tree**: complete binary tree over the leaf hashes (padded to a
//!   power of two with zero hashes). `prove` extracts a *batch* proof: for the
//!   queried leaves, the minimal set of sibling hashes that reconstructs the
//!   root.
//!
//! # The verification contract
//!
//! `verify` never touches the record. It recomputes the root from the proof's
//! queried leaves and siblings, and requires the result to equal the caller's
//! **trusted anchor** (the record root as committed by an authenticated
//! source, e.g. a block header). The anchor is the trust base: this module
//! provides integrity binding, not keyed authentication. `verify_untrusted`
//! only checks internal consistency and detects corruption, not
//! authenticity — never use it where authenticity is required.
//!
//! # Honest complexity
//!
//! - `prove`: O(n) time (the record is read once), O(n) memory for the tree.
//! - Proof size: O(|q| · log(n/|q|)) sibling hashes worst case; O(log n) for a
//!   single field or a contiguous field range.
//! - `verify`: O(|q|) payload bytes read plus O(|q| · log(n/|q|)) hashes;
//!   O(|q| + log n) hash operations with the batch aggregation.
//!
//! The Merkle construction means the format targets records with moderate
//! field counts (tens of thousands at most); for payload-heavy records the
//! per-field hash cost is negligible, for tiny records the fixed 32-byte root
//! dominates.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::fmt;

use crate::canonical::{decode_varint_le, encode_varint_le, zigzag_decode, zigzag_encode};
use crate::hash;

/// The in-tree BLAKE3 implementation is the only hash primitive used by this
/// module (byte-for-byte compatible with the official crate).
fn blake3(input: &[u8]) -> [u8; 32] {
    hash::blake3(input)
}

/// Stable application field identifier inside one record.
///
/// Field identifiers are scoped to the application schema that a record's
/// `schema_version` names; this module treats them as opaque `u32` values and
/// only enforces record-local canonical ordering.
pub type FieldId = u32;

/// Four-byte magic: `RBPJ` (RustBinary Projection).
const MAGIC: [u8; 4] = *b"RBPJ";
/// Current wire format version.
const FORMAT_VERSION: u16 = 1;
/// Format flag: the record carries a Merkle-authenticated root.
const FLAG_MERKLE: u16 = 0x0001;
/// Fixed header size: magic(4) + version(2) + flags(2) + field_count(4) +
/// schema_version(4).
const HEADER_LEN: usize = 16;
/// Size of the trailing authenticated root.
const AUTH_LEN: usize = 32;
/// Domain tag for leaf hashes over a `(field_id, payload_len, payload)` triple.
const LEAF_DOMAIN: u8 = 0x00;
/// Domain tag for the schema-binding root.
const SCHEMA_DOMAIN: u8 = 0x01;
/// Domain tag for Merkle internal node hashes.
const NODE_DOMAIN: u8 = 0x02;

/// Default maximum number of fields in one record.
pub const DEFAULT_MAX_FIELDS: u64 = 262_144;
/// Default maximum payload length of one field.
pub const DEFAULT_MAX_PAYLOAD_LEN: u64 = 16 * 1024 * 1024;
/// Default maximum serialized record length.
pub const DEFAULT_MAX_RECORD_LEN: u64 = 256 * 1024 * 1024;

/// Errors produced by the projection format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionError {
    /// The record does not start with the projection magic.
    BadMagic,
    /// The record uses an unsupported wire-format version.
    UnsupportedVersion(u16),
    /// The record uses unsupported flags (only the Merkle flag is valid).
    UnsupportedFlags(u16),
    /// The input ended inside the header or a field.
    UnexpectedEnd,
    /// Bytes follow the authenticated root.
    TrailingBytes,
    /// Fields are not in strictly increasing `field_id` order.
    NonCanonicalOrder,
    /// A field was inserted twice with the same `field_id`.
    DuplicateField(FieldId),
    /// The record exceeds the configured field-count limit.
    FieldLimit {
        /// The configured limit that was exceeded.
        limit: u64,
    },
    /// A field payload exceeds the configured payload-length limit.
    PayloadLimit {
        /// The configured limit that was exceeded.
        limit: u64,
    },
    /// The record exceeds the configured total-length limit.
    RecordLimit {
        /// The configured limit that was exceeded.
        limit: u64,
    },
    /// The query is empty or selects no field present in the record.
    InvalidQuery,
    /// The proof is missing a sibling hash needed to reconstruct the root.
    IncompleteProof,
    /// The recomputed root does not match the claimed root or the anchor.
    ///
    /// Raised on tampering, on a substituted proof, and on any mismatch
    /// between the proof and the trusted anchor.
    RootMismatch,
    /// A verified payload failed type-specific decoding (varint, UTF-8, bool).
    InvalidPayload,
    /// Internal tree-geometry error (index outside the tree).
    TreeGeometry,
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "projection record has an invalid magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported projection version {v}"),
            Self::UnsupportedFlags(flags) => write!(f, "unsupported projection flags {flags:#06x}"),
            Self::UnexpectedEnd => write!(f, "unexpected end of projection record"),
            Self::TrailingBytes => write!(f, "trailing bytes after projection record"),
            Self::NonCanonicalOrder => write!(f, "fields are not in strictly increasing order"),
            Self::DuplicateField(id) => write!(f, "duplicate field id {id}"),
            Self::FieldLimit { limit } => write!(f, "field count exceeds limit {limit}"),
            Self::PayloadLimit { limit } => write!(f, "field payload exceeds limit {limit}"),
            Self::RecordLimit { limit } => write!(f, "record length exceeds limit {limit}"),
            Self::InvalidQuery => write!(f, "projection query cannot produce a proof"),
            Self::IncompleteProof => write!(f, "projection proof is missing sibling hashes"),
            Self::RootMismatch => write!(
                f,
                "projection root mismatch (tampered record, substituted proof, or wrong anchor)"
            ),
            Self::InvalidPayload => write!(f, "invalid field payload"),
            Self::TreeGeometry => write!(f, "internal projection tree-geometry error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProjectionError {}

/// Resource policy applied before allocation or parsing of projection data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    max_fields: u64,
    max_payload_len: u64,
    max_record_len: u64,
}

impl ProjectionLimits {
    /// Creates the conservative default policy.
    pub const fn new() -> Self {
        Self {
            max_fields: DEFAULT_MAX_FIELDS,
            max_payload_len: DEFAULT_MAX_PAYLOAD_LEN,
            max_record_len: DEFAULT_MAX_RECORD_LEN,
        }
    }

    /// Sets the maximum number of fields in one record.
    pub const fn with_max_fields(mut self, limit: u64) -> Self {
        self.max_fields = limit;
        self
    }

    /// Sets the maximum payload length of one field.
    pub const fn with_max_payload_len(mut self, limit: u64) -> Self {
        self.max_payload_len = limit;
        self
    }

    /// Sets the maximum serialized record length.
    pub const fn with_max_record_len(mut self, limit: u64) -> Self {
        self.max_record_len = limit;
        self
    }

    /// Returns the configured field-count limit.
    pub const fn max_fields(self) -> u64 {
        self.max_fields
    }

    /// Returns the configured per-field payload limit.
    pub const fn max_payload_len(self) -> u64 {
        self.max_payload_len
    }

    /// Returns the configured record-length limit.
    pub const fn max_record_len(self) -> u64 {
        self.max_record_len
    }
}

impl Default for ProjectionLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// A projection query: an ordered set of field identifiers.
///
/// Constructed with [`Projection::new`], which sorts and de-duplicates the
/// input, so a query always has set semantics regardless of caller order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Projection {
    fields: Vec<FieldId>,
}

impl Projection {
    /// Builds a query from an iterator of field identifiers.
    ///
    /// The result is sorted and de-duplicated; order and duplicates in the
    /// input do not affect the query.
    pub fn new<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = FieldId>,
    {
        let mut fields: Vec<FieldId> = iter.into_iter().collect();
        fields.sort_unstable();
        fields.dedup();
        Self { fields }
    }

    /// The empty query.
    pub const fn empty() -> Self {
        Self { fields: Vec::new() }
    }

    /// Returns the sorted, de-duplicated field identifiers.
    pub fn fields(&self) -> &[FieldId] {
        &self.fields
    }

    /// Whether the query selects `field_id`.
    pub fn contains(&self, field_id: FieldId) -> bool {
        self.fields.binary_search(&field_id).is_ok()
    }

    /// Number of selected fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether no field is selected.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// One field extracted by a proof, before type-specific decoding.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProofLeaf {
    /// 0-based position of the field within the record's canonical field list.
    pub index: u32,
    /// Field identifier.
    pub field_id: FieldId,
    /// The raw payload bytes, copied out of the record.
    pub payload: Vec<u8>,
}

/// One sibling hash needed to reconstruct the Merkle root.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProofSibling {
    /// 1-based heap node index of the sibling.
    pub index: usize,
    /// The sibling hash.
    pub hash: [u8; 32],
}

/// A self-contained projection proof (witness) for a query.
///
/// The proof carries the queried leaves (payloads included), the minimal
/// sibling set, the record's schema version and field count, and the claimed
/// root. A verifier needs **only** this proof plus a trusted anchor.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProjectionProof {
    schema_version: u32,
    field_count: u32,
    leaves: Vec<ProofLeaf>,
    siblings: Vec<ProofSibling>,
    claimed_root: [u8; 32],
}

impl ProjectionProof {
    /// The schema version bound into the proof's root.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The number of fields in the source record.
    pub fn field_count(&self) -> u32 {
        self.field_count
    }

    /// The leaves extracted for the queried fields.
    pub fn leaves(&self) -> &[ProofLeaf] {
        &self.leaves
    }

    /// The sibling hashes that reconstruct the root.
    pub fn siblings(&self) -> &[ProofSibling] {
        &self.siblings
    }

    /// The root claimed by this proof (must equal the trusted anchor on
    /// verification).
    pub fn claimed_root(&self) -> &[u8; 32] {
        &self.claimed_root
    }

    /// Number of sibling hashes in this proof.
    pub fn sibling_count(&self) -> usize {
        self.siblings.len()
    }
}

/// A field whose authenticity and value were verified against the anchor.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct VerifiedField<'a> {
    /// Field identifier.
    pub field_id: FieldId,
    /// The verified payload bytes.
    pub payload: &'a [u8],
}

impl VerifiedField<'_> {
    /// Decodes the payload as a canonical marker-varint (`u128`).
    ///
    /// Rejects non-canonical encodings (a payload narrower than its marker's
    /// minimum value) and trailing bytes.
    pub fn as_varint(&self) -> Result<u128, ProjectionError> {
        decode_canonical_varint(self.payload)
    }

    /// Decodes the payload as a ZigZag canonical marker-varint (`i128`).
    pub fn as_signed(&self) -> Result<i128, ProjectionError> {
        Ok(zigzag_decode(self.as_varint()?))
    }

    /// Decodes the payload as UTF-8 text.
    pub fn as_str(&self) -> Result<&str, ProjectionError> {
        core::str::from_utf8(self.payload).map_err(|_| ProjectionError::InvalidPayload)
    }

    /// Returns the raw payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.payload
    }

    /// Decodes the payload as a single boolean byte (`0` or `1`).
    pub fn as_bool(&self) -> Result<bool, ProjectionError> {
        match self.payload {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(ProjectionError::InvalidPayload),
        }
    }
}

/// Canonical builder for self-authenticating records.
///
/// Fields must be inserted in strictly increasing `field_id` order (the
/// canonical form); inserting an out-of-order or duplicate id is an error.
#[derive(Debug)]
pub struct RecordBuilder {
    schema_version: u32,
    limits: ProjectionLimits,
    fields: Vec<(FieldId, Vec<u8>)>,
    encoded_len: u64,
}

impl RecordBuilder {
    /// Creates a builder for `schema_version` with default limits.
    pub fn new(schema_version: u32) -> Self {
        Self::with_limits(schema_version, ProjectionLimits::new())
    }

    /// Creates a builder with explicit resource limits.
    pub fn with_limits(schema_version: u32, limits: ProjectionLimits) -> Self {
        Self {
            schema_version,
            limits,
            fields: Vec::new(),
            encoded_len: (HEADER_LEN + AUTH_LEN) as u64,
        }
    }

    /// Number of fields inserted so far.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether no field has been inserted yet.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The configured schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Inserts a raw-payload field.
    ///
    /// `field_id` must be strictly greater than every previously inserted id.
    pub fn insert(&mut self, field_id: FieldId, payload: &[u8]) -> Result<(), ProjectionError> {
        let id = field_id;
        if let Some(&(last, _)) = self.fields.last() {
            if id <= last {
                if id == last {
                    return Err(ProjectionError::DuplicateField(id));
                }
                return Err(ProjectionError::NonCanonicalOrder);
            }
        }
        let field_count = u64::try_from(self.fields.len() + 1)
            .map_err(|_| ProjectionError::FieldLimit { limit: u64::MAX })?;
        if field_count > self.limits.max_fields {
            return Err(ProjectionError::FieldLimit {
                limit: self.limits.max_fields,
            });
        }
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| ProjectionError::PayloadLimit { limit: u64::MAX })?;
        if payload_len > self.limits.max_payload_len {
            return Err(ProjectionError::PayloadLimit {
                limit: self.limits.max_payload_len,
            });
        }
        // Encoded contribution: field_id(4) + payload_len(4) + payload.
        let contribution = payload_len
            .checked_add(8)
            .ok_or(ProjectionError::RecordLimit { limit: u64::MAX })?;
        let encoded_len = self
            .encoded_len
            .checked_add(contribution)
            .ok_or(ProjectionError::RecordLimit { limit: u64::MAX })?;
        if encoded_len > self.limits.max_record_len {
            return Err(ProjectionError::RecordLimit {
                limit: self.limits.max_record_len,
            });
        }
        self.encoded_len = encoded_len;
        self.fields.push((field_id, payload.to_vec()));
        Ok(())
    }

    /// Inserts a field encoded as a canonical marker-varint.
    pub fn insert_varint(&mut self, field_id: FieldId, value: u128) -> Result<(), ProjectionError> {
        let (bytes, len) = encode_varint_le(value);
        self.insert(field_id, &bytes[..len])
    }

    /// Inserts a field encoded as a ZigZag canonical marker-varint.
    pub fn insert_signed(&mut self, field_id: FieldId, value: i128) -> Result<(), ProjectionError> {
        self.insert_varint(field_id, zigzag_encode(value))
    }

    /// Inserts a UTF-8 text field.
    pub fn insert_str(&mut self, field_id: FieldId, value: &str) -> Result<(), ProjectionError> {
        self.insert(field_id, value.as_bytes())
    }

    /// Inserts a raw byte-string field.
    pub fn insert_bytes(&mut self, field_id: FieldId, value: &[u8]) -> Result<(), ProjectionError> {
        self.insert(field_id, value)
    }

    /// Inserts a boolean field (single `0`/`1` byte).
    pub fn insert_bool(&mut self, field_id: FieldId, value: bool) -> Result<(), ProjectionError> {
        self.insert(field_id, &[u8::from(value)])
    }

    /// Serializes the canonical self-authenticating record.
    pub fn finish(self) -> Result<Vec<u8>, ProjectionError> {
        let field_count = self.fields.len() as u32;
        let leaves = merkle_leaves(self.fields.iter().map(|(id, p)| (*id, p.as_slice())));
        let merkle = merkle_root(&leaves);
        let root = schema_root(self.schema_version, &merkle);
        let mut out = Vec::new();
        // try_reserve is not const; the header/footer sizes are fixed.
        out.try_reserve(self.encoded_len as usize)
            .map_err(|_| ProjectionError::RecordLimit { limit: u64::MAX })?;
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&FLAG_MERKLE.to_le_bytes());
        out.extend_from_slice(&field_count.to_le_bytes());
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        for (field_id, payload) in &self.fields {
            out.extend_from_slice(&field_id.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
        out.extend_from_slice(&root);
        debug_assert_eq!(out.len() as u64, self.encoded_len);
        Ok(out)
    }
}

/// A parsed, validated self-authenticating record.
#[derive(Debug)]
pub struct Record<'a> {
    schema_version: u32,
    fields: Vec<ParsedField<'a>>,
    root: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct ParsedField<'a> {
    field_id: FieldId,
    payload: &'a [u8],
}

impl<'a> Record<'a> {
    /// Parses and validates one record from `input`.
    ///
    /// Rejects malformed headers, non-canonical field order, resource-limit
    /// violations, and trailing bytes. The returned record borrows `input`;
    /// `prove` extracts an owned proof from it.
    pub fn parse(input: &'a [u8], limits: &ProjectionLimits) -> Result<Self, ProjectionError> {
        let parsed = parse_record(input, limits)?;
        Ok(Self {
            schema_version: parsed.schema_version,
            fields: parsed.fields,
            root: parsed.root,
        })
    }

    /// The record's schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Number of fields in the record.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// The record's authenticated root.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Recomputes the root from the record's own fields and compares it to the
    /// stored root. Detects accidental corruption (not authenticity; the
    /// stored root itself must come from a trusted source).
    pub fn verify_root(&self) -> Result<(), ProjectionError> {
        let leaves = merkle_leaves(self.fields.iter().map(|f| (f.field_id, f.payload)));
        let merkle = merkle_root(&leaves);
        let root = schema_root(self.schema_version, &merkle);
        if root == self.root {
            Ok(())
        } else {
            Err(ProjectionError::RootMismatch)
        }
    }

    /// Builds a projection proof for `query`.
    ///
    /// O(n) in the record size; the proof is self-contained and can be
    /// shipped to a verifier that never sees the record.
    pub fn prove(&self, query: &Projection) -> Result<ProjectionProof, ProjectionError> {
        if query.is_empty() {
            return Err(ProjectionError::InvalidQuery);
        }
        let leaf_count = leaf_count(self.fields.len() as u64) as usize;
        let leaves: Vec<[u8; 32]> =
            merkle_leaves(self.fields.iter().map(|f| (f.field_id, f.payload)));
        let tree = build_tree(&leaves);
        let mut selected = BTreeSet::new();
        let mut proof_leaves = Vec::with_capacity(query.len());
        for (index, field) in self.fields.iter().enumerate() {
            if query.contains(field.field_id) {
                selected.insert(index as u32);
                proof_leaves.push(ProofLeaf {
                    index: index as u32,
                    field_id: field.field_id,
                    payload: field.payload.to_vec(),
                });
            }
        }
        if selected.is_empty() {
            return Err(ProjectionError::InvalidQuery);
        }
        let siblings = aggregate_siblings(&tree, leaf_count, &selected);
        let merkle = merkle_root(&leaves);
        let root = schema_root(self.schema_version, &merkle);
        Ok(ProjectionProof {
            schema_version: self.schema_version,
            field_count: self.fields.len() as u32,
            leaves: proof_leaves,
            siblings,
            claimed_root: root,
        })
    }

    /// Iterates the record's fields in canonical order.
    pub fn fields(&self) -> impl Iterator<Item = (FieldId, &'a [u8])> + '_ {
        self.fields.iter().map(|f| (f.field_id, f.payload))
    }
}

/// Parses and proves in one step.
pub fn prove(
    record: &[u8],
    query: &Projection,
    limits: &ProjectionLimits,
) -> Result<ProjectionProof, ProjectionError> {
    Record::parse(record, limits)?.prove(query)
}

/// Verifies a proof against a trusted anchor and returns the queried fields.
///
/// # Soundness
///
/// If this returns `Ok(v)`, then `v` equals the projection of the unique
/// canonical record whose root is `anchor`, restricted to `query`. The record
/// itself is never read. `expected_schema_version` must match the schema
/// version bound into the anchor; a mismatch is rejected before any payload
/// is returned.
///
/// # Trust
///
/// `anchor` must come from an authenticated source. This module binds
/// integrity; it does not perform keyed authentication.
pub fn verify<'a>(
    proof: &'a ProjectionProof,
    anchor: &[u8; 32],
    expected_schema_version: u32,
) -> Result<Vec<VerifiedField<'a>>, ProjectionError> {
    if proof.schema_version != expected_schema_version {
        return Err(ProjectionError::RootMismatch);
    }
    let recomputed = recompute_proof_root(proof)?;
    if recomputed != proof.claimed_root || recomputed != *anchor {
        return Err(ProjectionError::RootMismatch);
    }
    Ok(proof
        .leaves
        .iter()
        .map(|leaf| VerifiedField {
            field_id: leaf.field_id,
            payload: &leaf.payload,
        })
        .collect())
}

/// Verifies a proof for internal consistency only.
///
/// Checks that the proof's leaves and siblings reconstruct a root equal to the
/// claimed root. This detects corruption and inconsistent proofs but **not**
/// substitution by an attacker (an attacker can forge a self-consistent
/// proof). Only use where corruption detection, not authenticity, is required.
pub fn verify_untrusted(
    proof: &ProjectionProof,
) -> Result<Vec<VerifiedField<'_>>, ProjectionError> {
    let recomputed = recompute_proof_root(proof)?;
    if recomputed != proof.claimed_root {
        return Err(ProjectionError::RootMismatch);
    }
    Ok(proof
        .leaves
        .iter()
        .map(|leaf| VerifiedField {
            field_id: leaf.field_id,
            payload: &leaf.payload,
        })
        .collect())
}

/// Reconstructs the root from a proof's leaves and siblings.
///
/// Also enforces the proof's internal canonicality (sorted positions, sorted
/// field ids, positions within the field count) so that a malformed proof is
/// rejected before any hash is combined.
fn recompute_proof_root(proof: &ProjectionProof) -> Result<[u8; 32], ProjectionError> {
    let field_count = proof.field_count as u64;
    let leaf_count = leaf_count(field_count);
    // The heap-layout tree size (`2 * leaf_count`) must fit `usize` so the
    // index arithmetic below cannot overflow. Proofs always come from real
    // records (bounded by `ProjectionLimits`), so this only guards malformed
    // proof values.
    let leaf_count = usize::try_from(leaf_count).map_err(|_| ProjectionError::TreeGeometry)?;
    let tree_size = leaf_count
        .checked_mul(2)
        .ok_or(ProjectionError::TreeGeometry)?;
    // Canonicality of the proof's leaves: strictly increasing positions and
    // strictly increasing field ids, all positions within the field count.
    let mut prev_index: Option<u32> = None;
    let mut prev_id: Option<FieldId> = None;
    for leaf in &proof.leaves {
        if (leaf.index as u64) >= field_count {
            return Err(ProjectionError::TreeGeometry);
        }
        if let Some(prev) = prev_index {
            if leaf.index <= prev {
                return Err(ProjectionError::NonCanonicalOrder);
            }
        }
        if let Some(prev) = prev_id {
            if leaf.field_id <= prev {
                return Err(ProjectionError::NonCanonicalOrder);
            }
        }
        prev_index = Some(leaf.index);
        prev_id = Some(leaf.field_id);
    }
    let siblings: BTreeMap<usize, [u8; 32]> =
        proof.siblings.iter().map(|s| (s.index, s.hash)).collect();
    if siblings.len() != proof.siblings.len() {
        // Duplicate sibling indices: the proof is malformed.
        return Err(ProjectionError::IncompleteProof);
    }
    let mut frontier: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
    for leaf in &proof.leaves {
        let node = leaf_count
            .checked_add(leaf.index as usize)
            .ok_or(ProjectionError::TreeGeometry)?;
        if node >= tree_size {
            return Err(ProjectionError::TreeGeometry);
        }
        let hash = leaf_hash(leaf.field_id, &leaf.payload);
        if frontier.insert(node, hash).is_some() {
            // Two leaves claim the same position: malformed proof.
            return Err(ProjectionError::TreeGeometry);
        }
    }
    if frontier.is_empty() {
        // A proof without leaves cannot reconstruct any root.
        return Err(ProjectionError::IncompleteProof);
    }
    let merkle = combine_frontier(&frontier, &siblings, node_hash)?;
    Ok(schema_root(proof.schema_version, &merkle))
}

/// Reconstructs the Merkle root from a set of leaf hashes and the sibling
/// hashes that cover the remaining leaves.
///
/// This is the algebraic core of proof verification, isolated from I/O so the
/// Kani harnesses can prove the tree geometry sound for any hash function and
/// any hash values: given the leaves of a subset `S` of a complete binary tree
/// in heap layout and the minimal sibling set covering `T \ S`, it reproduces
/// the root `tree[1]` if and only if every sibling was provided.
pub(crate) fn combine_frontier<H>(
    frontier: &BTreeMap<usize, [u8; 32]>,
    siblings: &BTreeMap<usize, [u8; 32]>,
    node_hash: H,
) -> Result<[u8; 32], ProjectionError>
where
    H: Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
{
    if frontier.is_empty() {
        // An empty frontier can never converge to the root; reject instead of
        // looping forever.
        return Err(ProjectionError::IncompleteProof);
    }
    let mut frontier = frontier.clone();
    while !(frontier.len() == 1 && frontier.contains_key(&1)) {
        let keys: Vec<usize> = frontier.keys().copied().collect();
        let mut next: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
        let mut k = 0;
        while k < keys.len() {
            let i = keys[k];
            let j = i ^ 1;
            if let Some(&hj) = frontier.get(&j) {
                // Both children present; `i` is the left (even) child.
                let left = frontier[&i];
                let parent = node_hash(&left, &hj);
                next.insert(i / 2, parent);
                k += 1; // skip the sibling; it is handled by this pair.
            } else {
                let sh = siblings
                    .get(&j)
                    .copied()
                    .ok_or(ProjectionError::IncompleteProof)?;
                let parent = if i % 2 == 0 {
                    node_hash(&frontier[&i], &sh)
                } else {
                    node_hash(&sh, &frontier[&i])
                };
                next.insert(i / 2, parent);
            }
            k += 1;
        }
        frontier = next;
    }
    let merkle = *frontier
        .values()
        .next()
        .ok_or(ProjectionError::IncompleteProof)?;
    Ok(merkle)
}

/// Decodes a canonical marker-varint payload, requiring full consumption.
pub(crate) fn decode_canonical_varint(bytes: &[u8]) -> Result<u128, ProjectionError> {
    let (&marker, rest) = bytes.split_first().ok_or(ProjectionError::InvalidPayload)?;
    let expected_len = varint_len(marker).ok_or(ProjectionError::InvalidPayload)?;
    if rest.len() != expected_len - 1 {
        return Err(ProjectionError::InvalidPayload);
    }
    decode_varint_le(marker, rest).ok_or(ProjectionError::InvalidPayload)
}

/// Encoded byte length of a canonical varint marker (marker byte included).
const fn varint_len(marker: u8) -> Option<usize> {
    match marker {
        0..=250 => Some(1),
        251 => Some(3),
        252 => Some(5),
        253 => Some(9),
        254 => Some(17),
        _ => None,
    }
}

/// Number of Merkle leaves for `field_count` fields: the next power of two,
/// with a minimum of one.
pub(crate) const fn leaf_count(field_count: u64) -> u64 {
    if field_count == 0 {
        1
    } else {
        field_count.next_power_of_two()
    }
}

/// Computes the leaf hashes of a field list in canonical order.
fn merkle_leaves<'a, I>(fields: I) -> Vec<[u8; 32]>
where
    I: IntoIterator<Item = (FieldId, &'a [u8])>,
{
    let collected: Vec<(FieldId, &'a [u8])> = fields.into_iter().collect();
    let leaf_count = leaf_count(collected.len() as u64) as usize;
    let mut leaves = Vec::with_capacity(leaf_count);
    leaves.extend(
        collected
            .into_iter()
            .map(|(id, payload)| leaf_hash(id, payload)),
    );
    leaves.resize(leaf_count, [0u8; 32]);
    leaves
}

/// Builds the complete Merkle tree (1-based heap layout) from the leaves.
///
/// `tree[0]` is unused; leaves occupy `tree[L..2L]`, internal nodes
/// `tree[1..L]`, root at `tree[1]`.
pub(crate) fn build_tree(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let l = leaves.len();
    let mut tree = alloc::vec![
        [0u8; 32];
        2 * l
    ];
    tree[l..].copy_from_slice(leaves);
    for i in (1..l).rev() {
        tree[i] = node_hash(&tree[2 * i], &tree[2 * i + 1]);
    }
    tree
}

/// Computes the Merkle root from a complete leaf set.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let l = leaves.len();
    debug_assert!(l.is_power_of_two());
    if l == 1 {
        return leaves[0];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        level = next;
    }
    level[0]
}

/// Collects the minimal sibling set that reconstructs the root from the
/// queried leaves, using the standard batch aggregation over a heap layout.
pub(crate) fn aggregate_siblings(
    tree: &[[u8; 32]],
    leaf_count: usize,
    queried: &BTreeSet<u32>,
) -> Vec<ProofSibling> {
    if queried.is_empty() {
        return Vec::new();
    }
    let mut frontier: BTreeSet<usize> = queried.iter().map(|&i| leaf_count + i as usize).collect();
    let mut siblings = Vec::new();
    while !(frontier.len() == 1 && frontier.contains(&1)) {
        let mut next: BTreeSet<usize> = BTreeSet::new();
        for &i in &frontier {
            let j = i ^ 1;
            if !frontier.contains(&j) {
                siblings.push(ProofSibling {
                    index: j,
                    hash: tree[j],
                });
            }
            next.insert(i / 2);
        }
        frontier = next;
    }
    siblings
}

/// Leaf hash over a `(field_id, payload_len, payload)` triple.
///
/// The payload length field is bounded to `u32::MAX` defensively; the full
/// payload bytes are always hashed, so a length that cannot fit `u32` cannot
/// produce a hash collision (both sides compute the identical hash).
fn leaf_hash(field_id: FieldId, payload: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(9 + payload.len());
    input.push(LEAF_DOMAIN);
    input.extend_from_slice(&field_id.to_le_bytes());
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    input.extend_from_slice(&len.to_le_bytes());
    input.extend_from_slice(payload);
    blake3(&input)
}

/// Merkle internal node hash.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 65];
    input[0] = NODE_DOMAIN;
    input[1..33].copy_from_slice(left);
    input[33..65].copy_from_slice(right);
    blake3(&input)
}

/// Schema-binding root: `H(SCHEMA_DOMAIN ‖ schema_version ‖ merkle_root)`.
pub fn schema_root(schema_version: u32, merkle: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 37];
    input[0] = SCHEMA_DOMAIN;
    input[1..5].copy_from_slice(&schema_version.to_le_bytes());
    input[5..37].copy_from_slice(merkle);
    blake3(&input)
}

/// Internal parse result with an owned view into the input.
struct ParsedRecord<'a> {
    schema_version: u32,
    fields: Vec<ParsedField<'a>>,
    root: [u8; 32],
}

/// Bounds-checked record parser. Never panics on hostile input.
fn parse_record<'a>(
    input: &'a [u8],
    limits: &ProjectionLimits,
) -> Result<ParsedRecord<'a>, ProjectionError> {
    let total = u64::try_from(input.len()).unwrap_or(u64::MAX);
    if total > limits.max_record_len {
        return Err(ProjectionError::RecordLimit {
            limit: limits.max_record_len,
        });
    }
    if input.len() < HEADER_LEN + AUTH_LEN {
        return Err(ProjectionError::UnexpectedEnd);
    }
    if input[0..4] != MAGIC {
        return Err(ProjectionError::BadMagic);
    }
    let version = u16::from_le_bytes([input[4], input[5]]);
    if version != FORMAT_VERSION {
        return Err(ProjectionError::UnsupportedVersion(version));
    }
    let flags = u16::from_le_bytes([input[6], input[7]]);
    if flags != FLAG_MERKLE {
        return Err(ProjectionError::UnsupportedFlags(flags));
    }
    let field_count = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    let schema_version = u32::from_le_bytes([input[12], input[13], input[14], input[15]]);
    if field_count as u64 > limits.max_fields {
        return Err(ProjectionError::FieldLimit {
            limit: limits.max_fields,
        });
    }
    let mut cursor = HEADER_LEN;
    let mut fields: Vec<ParsedField<'a>> = Vec::new();
    fields
        .try_reserve(field_count as usize)
        .map_err(|_| ProjectionError::FieldLimit { limit: u64::MAX })?;
    let mut prev_id: Option<FieldId> = None;
    for _ in 0..field_count {
        let id = read_u32(input, &mut cursor)?;
        let len = read_u32(input, &mut cursor)?;
        if len as u64 > limits.max_payload_len {
            return Err(ProjectionError::PayloadLimit {
                limit: limits.max_payload_len,
            });
        }
        if let Some(prev) = prev_id {
            if id <= prev {
                return Err(ProjectionError::NonCanonicalOrder);
            }
        }
        prev_id = Some(id);
        let payload_end = cursor
            .checked_add(len as usize)
            .ok_or(ProjectionError::UnexpectedEnd)?;
        let payload = input
            .get(cursor..payload_end)
            .ok_or(ProjectionError::UnexpectedEnd)?;
        cursor = payload_end;
        fields.push(ParsedField {
            field_id: id,
            payload,
        });
    }
    let root_bytes = input
        .get(cursor..cursor + AUTH_LEN)
        .ok_or(ProjectionError::UnexpectedEnd)?;
    cursor += AUTH_LEN;
    if cursor != input.len() {
        return Err(ProjectionError::TrailingBytes);
    }
    let root: [u8; 32] = root_bytes
        .try_into()
        .map_err(|_| ProjectionError::UnexpectedEnd)?;
    Ok(ParsedRecord {
        schema_version,
        fields,
        root,
    })
}

/// Reads a little-endian `u32`, advancing `cursor`.
///
/// Uses checked arithmetic so a malformed length cannot wrap `cursor`.
fn read_u32(input: &[u8], cursor: &mut usize) -> Result<u32, ProjectionError> {
    let end = cursor
        .checked_add(4)
        .ok_or(ProjectionError::UnexpectedEnd)?;
    let bytes = input
        .get(*cursor..end)
        .ok_or(ProjectionError::UnexpectedEnd)?;
    *cursor = end;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn build_fixture() -> (Vec<u8>, [u8; 32], u32) {
        let mut builder = RecordBuilder::new(7);
        builder.insert_str(1, "alpha").unwrap();
        builder.insert_varint(2, 42).unwrap();
        builder.insert_signed(3, -1_000).unwrap();
        builder.insert_bytes(4, b"\x00\x01\x02").unwrap();
        builder.insert_bool(5, true).unwrap();
        builder.insert_varint(9, u128::MAX).unwrap();
        let record = builder.finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        let root = *parsed.root();
        let version = parsed.schema_version();
        drop(parsed);
        (record, root, version)
    }

    fn query(ids: &[u32]) -> Projection {
        Projection::new(ids.iter().copied())
    }

    #[test]
    fn full_roundtrip_verifies_against_anchor() {
        let (record, anchor, version) = build_fixture();
        let proof = prove(&record, &query(&[1, 3, 9]), &ProjectionLimits::new()).unwrap();
        assert_eq!(proof.field_count(), 6);
        assert_eq!(proof.schema_version(), 7);
        let verified = verify(&proof, &anchor, version).unwrap();
        let ids: Vec<u32> = verified.iter().map(|f| f.field_id).collect();
        assert_eq!(ids, vec![1, 3, 9]);
        assert_eq!(verified[0].as_str().unwrap(), "alpha");
        assert_eq!(verified[1].as_signed().unwrap(), -1_000);
        assert_eq!(verified[2].as_varint().unwrap(), u128::MAX);
    }

    #[test]
    fn skipping_unknown_fields_does_not_break_semantics() {
        let (record, anchor, version) = build_fixture();
        // Query only field 2; fields 1,3,4,5,9 must not affect its value.
        let proof = prove(&record, &query(&[2]), &ProjectionLimits::new()).unwrap();
        let verified = verify(&proof, &anchor, version).unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].field_id, 2);
        assert_eq!(verified[0].as_varint().unwrap(), 42);
    }

    #[test]
    fn single_field_proof_is_logarithmic() {
        let mut builder = RecordBuilder::new(1);
        for i in 0..64 {
            builder.insert_varint(i, i as u128).unwrap();
        }
        let record = builder.finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        let proof = parsed.prove(&query(&[42])).unwrap();
        // 64 leaves -> tree height 6; a single leaf needs exactly 6 siblings.
        assert_eq!(proof.sibling_count(), 6);
        let verified = verify(&proof, parsed.root(), 1).unwrap();
        assert_eq!(verified[0].as_varint().unwrap(), 42);
    }

    #[test]
    fn batch_proof_is_smaller_than_per_leaf_sum() {
        let mut builder = RecordBuilder::new(1);
        for i in 0..64 {
            builder.insert_varint(i, i as u128).unwrap();
        }
        let record = builder.finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        // A contiguous range of 8 leaves needs fewer than 8*6 siblings.
        let proof = parsed
            .prove(&query(&[8, 9, 10, 11, 12, 13, 14, 15]))
            .unwrap();
        assert!(proof.sibling_count() < 8 * 6);
        let verified = verify(&proof, parsed.root(), 1).unwrap();
        assert_eq!(verified.len(), 8);
        assert_eq!(verified[0].as_varint().unwrap(), 8);
        assert_eq!(verified[7].as_varint().unwrap(), 15);
    }

    #[test]
    fn tampering_any_byte_fails_verification() {
        let (record, anchor, version) = build_fixture();
        // Tamper a single byte at representative offsets: a header byte, a
        // queried field's payload, and an unqueried field's payload.
        for (label, pos) in [
            ("header schema byte", 15usize),
            ("queried payload", 37usize),
            ("unqueried payload", 69usize),
        ] {
            let mut tampered = record.clone();
            tampered[pos] ^= 0x01;
            let proof = prove(&tampered, &query(&[2]), &ProjectionLimits::new()).unwrap();
            assert!(
                matches!(
                    verify(&proof, &anchor, version),
                    Err(ProjectionError::RootMismatch)
                ),
                "{label} must fail"
            );
        }
    }

    #[test]
    fn tampering_an_unqueried_field_is_detected() {
        let (record, anchor, version) = build_fixture();
        // Tamper a field NOT in the query: the sibling hashes still bind it.
        let mut tampered = record;
        // Field 9's payload begins after header + 5 prior fields (each 8-byte
        // header + payload). Find the byte range by re-parsing.
        let parsed = Record::parse(&tampered, &ProjectionLimits::new()).unwrap();
        let target: Vec<(FieldId, &[u8])> = parsed.fields().collect();
        // Locate field 9's first payload byte in the raw record: it follows
        // every earlier field. Compute offset by walking the canonical list.
        let mut offset = HEADER_LEN;
        for (id, payload) in &target {
            if *id == 9 {
                break;
            }
            offset += 8 + payload.len();
        }
        tampered[offset] ^= 0xff;
        let proof = prove(&tampered, &query(&[2]), &ProjectionLimits::new()).unwrap();
        assert!(matches!(
            verify(&proof, &anchor, version),
            Err(ProjectionError::RootMismatch)
        ));
    }

    #[test]
    fn schema_version_is_bound_into_the_root() {
        let (record, anchor, version) = build_fixture();
        let proof = prove(&record, &query(&[1]), &ProjectionLimits::new()).unwrap();
        // Wrong expected schema version is rejected.
        assert!(matches!(
            verify(&proof, &anchor, version.wrapping_add(1)),
            Err(ProjectionError::RootMismatch)
        ));
        // Wrong anchor is rejected.
        let wrong = [0xabu8; 32];
        assert!(matches!(
            verify(&proof, &wrong, version),
            Err(ProjectionError::RootMismatch)
        ));
        // Correct anchor + version succeeds.
        assert!(verify(&proof, &anchor, version).is_ok());
        // A record built under a different schema version has a different root.
        let mut other = RecordBuilder::new(version.wrapping_add(1));
        other.insert_varint(1, 1).unwrap();
        let other_record = other.finish().unwrap();
        assert_ne!(
            *Record::parse(&other_record, &ProjectionLimits::new())
                .unwrap()
                .root(),
            anchor
        );
    }

    #[test]
    fn builder_enforces_canonical_order_and_duplicates() {
        let mut builder = RecordBuilder::new(1);
        builder.insert_varint(1, 1).unwrap();
        assert!(matches!(
            builder.insert_varint(1, 2),
            Err(ProjectionError::DuplicateField(1))
        ));
        assert!(matches!(
            builder.insert_varint(0, 2),
            Err(ProjectionError::NonCanonicalOrder)
        ));
        builder.insert_varint(2, 2).unwrap();
    }

    #[test]
    #[cfg(feature = "std")]
    fn parser_rejects_non_canonical_and_corrupt_records() {
        let (record, _, _) = build_fixture();
        let limits = ProjectionLimits::new();
        // Corrupt magic.
        let mut bad = record.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            Record::parse(&bad, &limits),
            Err(ProjectionError::BadMagic)
        ));
        // Truncate at every prefix.
        for cut in 0..record.len() {
            assert!(
                std::panic::catch_unwind(|| Record::parse(&record[..cut], &limits)).is_ok(),
                "parse must not panic at cut {cut}"
            );
        }
        // Trailing bytes.
        let mut trailing = record.clone();
        trailing.push(0);
        assert!(matches!(
            Record::parse(&trailing, &limits),
            Err(ProjectionError::TrailingBytes)
        ));
        // Duplicate field ids in the wire (hand-crafted non-canonical record).
        let mut dup = Vec::new();
        dup.extend_from_slice(&MAGIC);
        dup.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        dup.extend_from_slice(&FLAG_MERKLE.to_le_bytes());
        dup.extend_from_slice(&2u32.to_le_bytes());
        dup.extend_from_slice(&1u32.to_le_bytes());
        for id in [5u32, 5u32] {
            dup.extend_from_slice(&id.to_le_bytes());
            dup.extend_from_slice(&1u32.to_le_bytes());
            dup.push(0xaa);
        }
        dup.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            Record::parse(&dup, &limits),
            Err(ProjectionError::NonCanonicalOrder)
        ));
    }

    #[test]
    fn empty_record_and_missing_field_are_handled() {
        let record = RecordBuilder::new(3).finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        assert_eq!(parsed.field_count(), 0);
        assert!(parsed.verify_root().is_ok());
        assert!(matches!(
            parsed.prove(&query(&[1])),
            Err(ProjectionError::InvalidQuery)
        ));
        let mut builder = RecordBuilder::new(3);
        builder.insert_varint(1, 1).unwrap();
        let record = builder.finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        assert!(matches!(
            parsed.prove(&query(&[2])),
            Err(ProjectionError::InvalidQuery)
        ));
    }

    #[test]
    fn empty_frontier_is_rejected_not_looped() {
        // `combine_frontier` must reject an empty frontier instead of looping
        // forever (defense in depth; the public API cannot build such a proof).
        let empty: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
        let siblings: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
        assert!(matches!(
            combine_frontier(&empty, &siblings, node_hash),
            Err(ProjectionError::IncompleteProof)
        ));
        // `aggregate_siblings` with no queried leaves returns no siblings.
        let leaves = [[0u8; 32]; 4];
        let tree = build_tree(&leaves);
        let queried: BTreeSet<u32> = BTreeSet::new();
        assert!(aggregate_siblings(&tree, 4, &queried).is_empty());
    }

    #[test]
    fn limits_are_enforced() {
        // Field-count limit (independent of the other limits).
        let field_limits = ProjectionLimits::new().with_max_fields(2);
        let mut builder = RecordBuilder::with_limits(1, field_limits);
        builder.insert_varint(1, 1).unwrap();
        builder.insert_varint(2, 2).unwrap();
        assert!(matches!(
            builder.insert_varint(3, 3),
            Err(ProjectionError::FieldLimit { limit: 2 })
        ));
        // Payload-length limit.
        let payload_limits = ProjectionLimits::new().with_max_payload_len(4);
        let mut builder = RecordBuilder::with_limits(1, payload_limits);
        assert!(matches!(
            builder.insert_bytes(1, &[0; 5]),
            Err(ProjectionError::PayloadLimit { limit: 4 })
        ));
        // Record-length limit: 48-byte envelope + one 16-byte field (exactly at
        // the 64-byte cap); a second field must be rejected.
        let record_limits = ProjectionLimits::new().with_max_record_len(64);
        let mut builder = RecordBuilder::with_limits(1, record_limits);
        builder.insert_bytes(1, &[0u8; 8]).unwrap();
        assert!(matches!(
            builder.insert_bytes(2, &[0u8; 1]),
            Err(ProjectionError::RecordLimit { limit: 64 })
        ));
        // The parser enforces the field-count limit independently of the
        // record-length limit.
        let parser_limits = ProjectionLimits::new().with_max_fields(2);
        let mut builder = RecordBuilder::new(1);
        for i in 0..4 {
            builder.insert_varint(i, i as u128).unwrap();
        }
        let record = builder.finish().unwrap();
        assert!(matches!(
            Record::parse(&record, &parser_limits),
            Err(ProjectionError::FieldLimit { limit: 2 })
        ));
    }

    #[test]
    fn verified_payload_helpers_reject_malformed_values() {
        let mut builder = RecordBuilder::new(1);
        builder.insert_varint(1, 5).unwrap();
        builder.insert_bool(2, false).unwrap();
        let record = builder.finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        let proof = parsed.prove(&query(&[1, 2])).unwrap();
        let verified = verify(&proof, parsed.root(), 1).unwrap();
        assert_eq!(verified[0].as_varint().unwrap(), 5);
        assert!(!verified[1].as_bool().unwrap());
        // Non-canonical varint: marker 251 with a value below 251.
        let bad = vec![251u8, 1, 0];
        assert_eq!(
            decode_canonical_varint(&bad),
            Err(ProjectionError::InvalidPayload)
        );
        // Truncated varint.
        assert_eq!(
            decode_canonical_varint(&[253, 0]),
            Err(ProjectionError::InvalidPayload)
        );
        // Trailing bytes in a varint payload.
        assert_eq!(
            decode_canonical_varint(&[250, 0]),
            Err(ProjectionError::InvalidPayload)
        );
    }

    #[test]
    fn proof_rejects_malformed_structure() {
        let (record, anchor, version) = build_fixture();
        // Fields 1 (index 0) and 5 (index 4) are non-adjacent, so the proof
        // genuinely needs sibling hashes.
        let proof = prove(&record, &query(&[1, 5]), &ProjectionLimits::new()).unwrap();
        assert!(proof.sibling_count() > 0);
        // A proof with an out-of-order field id fails canonicality.
        let mut bad = proof.clone();
        bad.leaves.reverse();
        assert!(matches!(
            verify(&bad, &anchor, version),
            Err(ProjectionError::NonCanonicalOrder)
        ));
        // A proof with a removed sibling fails reconstruction.
        let mut bad = proof.clone();
        bad.siblings.clear();
        assert!(matches!(
            verify(&bad, &anchor, version),
            Err(ProjectionError::IncompleteProof)
        ));
        // A proof with a duplicate sibling index is malformed.
        let mut bad = proof.clone();
        if let Some(s) = bad.siblings.first().copied() {
            bad.siblings.push(s);
        }
        assert!(matches!(
            verify(&bad, &anchor, version),
            Err(ProjectionError::IncompleteProof)
        ));
    }

    #[test]
    fn untrusted_verification_detects_corruption_only() {
        let (record, anchor, version) = build_fixture();
        let proof = prove(&record, &query(&[1]), &ProjectionLimits::new()).unwrap();
        assert!(verify_untrusted(&proof).is_ok());
        assert!(verify(&proof, &anchor, version).is_ok());
        // Corrupt a leaf: untrusted verification catches the inconsistency.
        let mut corrupt = proof.clone();
        corrupt.leaves[0].payload[0] ^= 0x01;
        assert!(matches!(
            verify_untrusted(&corrupt),
            Err(ProjectionError::RootMismatch)
        ));
        // A fully forged, self-consistent proof (root recomputed over forged
        // leaves) passes untrusted verification ...
        let mut forged = corrupt;
        forged.claimed_root = recompute_proof_root(&forged).unwrap();
        assert!(verify_untrusted(&forged).is_ok());
        // ... but is rejected against the original record's anchor.
        assert!(matches!(
            verify(&forged, &anchor, version),
            Err(ProjectionError::RootMismatch)
        ));
    }

    #[test]
    fn many_records_roundtrip_across_field_counts() {
        for n in [
            1usize, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100,
        ] {
            let mut builder = RecordBuilder::new(1);
            for i in 0..n {
                builder.insert_varint(i as u32, i as u128).unwrap();
            }
            let record = builder.finish().unwrap();
            let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
            assert!(parsed.verify_root().is_ok(), "field count {n}");
            for id in [0u32, n as u32 - 1, n as u32 / 2] {
                let proof = parsed.prove(&query(&[id])).unwrap();
                let verified = verify(&proof, parsed.root(), 1).unwrap();
                assert_eq!(verified[0].as_varint().unwrap(), id as u128);
            }
            // Full projection equals a full scan.
            let all: Vec<u32> = (0..n as u32).collect();
            let proof = parsed.prove(&query(&all)).unwrap();
            let verified = verify(&proof, parsed.root(), 1).unwrap();
            assert_eq!(verified.len(), n);
        }
    }

    // -----------------------------------------------------------------------
    // Exhaustive robustness: every truncation, every byte tamper, boundary
    // field ids / payloads / limits, adversarial proofs, helper edges.
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(feature = "std")]
    fn truncation_never_panics_across_record_shapes() {
        let shapes: Vec<Vec<u8>> = vec![
            RecordBuilder::new(1).finish().unwrap(),
            build_fixture().0,
            {
                let mut builder = RecordBuilder::new(7);
                for i in 0..17 {
                    builder.insert_varint(i, i as u128).unwrap();
                }
                builder.finish().unwrap()
            },
            {
                let mut builder = RecordBuilder::new(7);
                for i in 0..33 {
                    builder.insert_bytes(i, &[0u8; 7]).unwrap();
                }
                builder.finish().unwrap()
            },
        ];
        let limits = ProjectionLimits::new();
        for record in &shapes {
            for cut in 0..=record.len() {
                let result = std::panic::catch_unwind(|| Record::parse(&record[..cut], &limits));
                assert!(result.is_ok(), "parse panicked at cut {cut}");
            }
        }
    }

    #[test]
    fn every_header_or_field_byte_tamper_is_detected_by_verify() {
        let (record, anchor, version) = build_fixture();
        let query = query(&[1, 2, 3, 4, 5, 9]);
        // The trailing 32 bytes are the stored root (metadata, not trust);
        // tampering them is covered by `stored_root_is_metadata_not_trust`.
        let body_len = record.len() - AUTH_LEN;
        for pos in 0..body_len {
            let mut tampered = record.clone();
            tampered[pos] ^= 0x01;
            if let Ok(parsed) = Record::parse(&tampered, &ProjectionLimits::new()) {
                let proof = parsed.prove(&query).unwrap();
                assert!(
                    matches!(
                        verify(&proof, &anchor, version),
                        Err(ProjectionError::RootMismatch)
                    ),
                    "tamper at byte {pos} was not detected"
                );
            }
            // parse may reject the tampered record; that is equally safe.
        }
    }

    #[test]
    fn stored_root_is_metadata_not_trust() {
        let (mut record, anchor, version) = build_fixture();
        let len = record.len();
        record[len - 1] ^= 0x01;
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        // The self-check detects the corrupted stored root ...
        assert!(matches!(
            parsed.verify_root(),
            Err(ProjectionError::RootMismatch)
        ));
        // ... but proofs recompute the root from the fields, so the trusted
        // anchor (not the stored root) remains the trust base.
        let proof = parsed.prove(&query(&[2])).unwrap();
        assert!(verify(&proof, &anchor, version).is_ok());
    }

    #[test]
    fn verify_root_detects_field_corruption() {
        let (mut record, _, _) = build_fixture();
        // Field 9's payload starts at offset 69 in the fixture.
        record[69] ^= 0xff;
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        assert!(matches!(
            parsed.verify_root(),
            Err(ProjectionError::RootMismatch)
        ));
    }

    #[test]
    fn field_id_boundaries_roundtrip() {
        let mut builder = RecordBuilder::new(1);
        builder.insert_varint(0, 0).unwrap();
        builder.insert_varint(u32::MAX, 7).unwrap();
        let record = builder.finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        assert_eq!(parsed.field_count(), 2);
        let proof = parsed.prove(&query(&[0, u32::MAX])).unwrap();
        let verified = verify(&proof, parsed.root(), 1).unwrap();
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0].field_id, 0);
        assert_eq!(verified[0].as_varint().unwrap(), 0);
        assert_eq!(verified[1].field_id, u32::MAX);
        assert_eq!(verified[1].as_varint().unwrap(), 7);
    }

    #[test]
    fn payload_length_boundaries_roundtrip() {
        let mut builder = RecordBuilder::new(1);
        builder.insert_bytes(1, b"").unwrap();
        builder.insert_bytes(2, &[0u8; 1]).unwrap();
        let record = builder.finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        let proof = parsed.prove(&query(&[1, 2])).unwrap();
        let verified = verify(&proof, parsed.root(), 1).unwrap();
        assert_eq!(verified[0].as_bytes(), b"");
        assert_eq!(verified[1].as_bytes(), &[0u8; 1]);
    }

    #[test]
    fn limits_exact_boundaries_pass_and_one_more_fails() {
        // max_fields: exactly the limit passes, one more fails.
        let limits = ProjectionLimits::new().with_max_fields(2);
        let mut builder = RecordBuilder::with_limits(1, limits);
        builder.insert_varint(1, 1).unwrap();
        builder.insert_varint(2, 2).unwrap();
        assert!(matches!(
            builder.insert_varint(3, 3),
            Err(ProjectionError::FieldLimit { limit: 2 })
        ));
        let record = builder.finish().unwrap();
        assert!(Record::parse(&record, &limits).is_ok());
        // max_payload_len: exactly the limit passes, one more fails.
        let limits = ProjectionLimits::new().with_max_payload_len(4);
        let mut builder = RecordBuilder::with_limits(1, limits);
        builder.insert_bytes(1, &[0u8; 4]).unwrap();
        let record = builder.finish().unwrap();
        assert!(Record::parse(&record, &limits).is_ok());
        let mut builder = RecordBuilder::with_limits(1, limits);
        assert!(matches!(
            builder.insert_bytes(1, &[0u8; 5]),
            Err(ProjectionError::PayloadLimit { limit: 4 })
        ));
        // max_record_len: 48-byte envelope + a 16-byte field is exactly 64.
        let limits = ProjectionLimits::new().with_max_record_len(64);
        let mut builder = RecordBuilder::with_limits(1, limits);
        builder.insert_bytes(1, &[0u8; 8]).unwrap();
        let record = builder.finish().unwrap();
        assert_eq!(record.len(), 64);
        assert!(Record::parse(&record, &limits).is_ok());
    }

    #[test]
    fn proof_extra_unused_sibling_is_harmless() {
        let (record, anchor, version) = build_fixture();
        let proof = prove(&record, &query(&[1, 5]), &ProjectionLimits::new()).unwrap();
        // Append a sibling whose index is never consulted by this proof's
        // frontier path (the proof uses nodes 9, 13, 5, 7).
        let mut padded = proof.clone();
        padded.siblings.push(ProofSibling {
            index: 2,
            hash: [0xab; 32],
        });
        padded.siblings.push(ProofSibling {
            index: usize::MAX,
            hash: [0; 32],
        });
        assert!(verify(&padded, &anchor, version).is_ok());
    }

    #[test]
    fn proof_wrong_sibling_fails() {
        let (record, anchor, version) = build_fixture();
        let proof = prove(&record, &query(&[1, 5]), &ProjectionLimits::new()).unwrap();
        assert!(proof.sibling_count() > 0);
        let mut bad = proof.clone();
        bad.siblings[0].hash[0] ^= 0xff;
        assert!(matches!(
            verify(&bad, &anchor, version),
            Err(ProjectionError::RootMismatch)
        ));
    }

    #[test]
    fn partial_projection_returns_only_found_fields() {
        let (record, anchor, version) = build_fixture();
        // Field 7 is absent; only the present field is returned.
        let proof = prove(&record, &query(&[2, 7]), &ProjectionLimits::new()).unwrap();
        let verified = verify(&proof, &anchor, version).unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].field_id, 2);
        assert_eq!(verified[0].as_varint().unwrap(), 42);
    }

    #[test]
    fn query_deduplicates_and_sorts() {
        let query = Projection::new([5, 1, 5, 2, 1]);
        assert_eq!(query.fields(), &[1, 2, 5]);
        assert_eq!(query.len(), 3);
        assert!(!query.is_empty());
        assert!(query.contains(2));
        assert!(!query.contains(3));
        assert!(Projection::empty().is_empty());
        assert_eq!(Projection::empty().len(), 0);
    }

    #[test]
    fn schema_version_edges_roundtrip() {
        for version in [0u32, u32::MAX] {
            let mut builder = RecordBuilder::new(version);
            builder.insert_varint(1, 1).unwrap();
            let record = builder.finish().unwrap();
            let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
            assert_eq!(parsed.schema_version(), version);
            let proof = parsed.prove(&query(&[1])).unwrap();
            let verified = verify(&proof, parsed.root(), version).unwrap();
            assert_eq!(verified[0].as_varint().unwrap(), 1);
        }
    }

    #[test]
    fn record_bytes_are_deterministic() {
        let mut a = RecordBuilder::new(5);
        a.insert_varint(3, 9).unwrap();
        a.insert_str(7, "hello").unwrap();
        let record_a = a.finish().unwrap();
        let mut b = RecordBuilder::new(5);
        b.insert_varint(3, 9).unwrap();
        b.insert_str(7, "hello").unwrap();
        assert_eq!(record_a, b.finish().unwrap());
        // Header layout is fixed width.
        assert_eq!(&record_a[0..4], MAGIC);
        assert_eq!(
            u16::from_le_bytes([record_a[4], record_a[5]]),
            FORMAT_VERSION
        );
        assert_eq!(u16::from_le_bytes([record_a[6], record_a[7]]), FLAG_MERKLE);
        assert_eq!(u32::from_le_bytes(record_a[8..12].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(record_a[12..16].try_into().unwrap()), 5);
    }

    #[test]
    fn typed_helpers_cover_all_varint_widths_and_signed_extremes() {
        let mut builder = RecordBuilder::new(1);
        builder.insert_varint(1, 250).unwrap();
        builder.insert_varint(2, 251).unwrap();
        builder.insert_varint(3, 0xffff).unwrap();
        builder.insert_varint(4, 0x1_0000).unwrap();
        builder.insert_varint(5, 0xffff_ffff).unwrap();
        builder.insert_varint(6, 0x1_0000_0000).unwrap();
        builder.insert_varint(7, u64::MAX as u128).unwrap();
        builder.insert_varint(8, 0x1_0000_0000_0000_0000).unwrap();
        builder.insert_varint(9, u128::MAX).unwrap();
        builder.insert_signed(10, i128::MIN).unwrap();
        builder.insert_signed(11, i128::MAX).unwrap();
        let record = builder.finish().unwrap();
        let parsed = Record::parse(&record, &ProjectionLimits::new()).unwrap();
        let proof = parsed
            .prove(&query(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]))
            .unwrap();
        let verified = verify(&proof, parsed.root(), 1).unwrap();
        let expected = [
            250u128,
            251,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX as u128,
            0x1_0000_0000_0000_0000,
            u128::MAX,
        ];
        for (i, value) in expected.iter().enumerate() {
            assert_eq!(verified[i].as_varint().unwrap(), *value, "width {i}");
        }
        assert_eq!(verified[9].as_signed().unwrap(), i128::MIN);
        assert_eq!(verified[10].as_signed().unwrap(), i128::MAX);
    }

    #[test]
    fn typed_helpers_reject_malformed_payloads() {
        fn field(payload: &[u8]) -> VerifiedField<'_> {
            VerifiedField {
                field_id: 1,
                payload,
            }
        }
        // as_bool accepts exactly 0 or 1.
        assert_eq!(field(&[0]).as_bool(), Ok(false));
        assert_eq!(field(&[1]).as_bool(), Ok(true));
        assert!(matches!(
            field(&[]).as_bool(),
            Err(ProjectionError::InvalidPayload)
        ));
        assert!(matches!(
            field(&[0, 1]).as_bool(),
            Err(ProjectionError::InvalidPayload)
        ));
        // as_str requires valid UTF-8.
        assert_eq!(field(b"ok").as_str(), Ok("ok"));
        assert!(matches!(
            field(&[0xff, 0xfe]).as_str(),
            Err(ProjectionError::InvalidPayload)
        ));
        // as_varint rejects empty, reserved marker, truncation, and trailing
        // bytes.
        assert!(matches!(
            field(&[]).as_varint(),
            Err(ProjectionError::InvalidPayload)
        ));
        assert!(matches!(
            field(&[255]).as_varint(),
            Err(ProjectionError::InvalidPayload)
        ));
        assert!(matches!(
            field(&[253, 0]).as_varint(),
            Err(ProjectionError::InvalidPayload)
        ));
        assert!(matches!(
            field(&[250, 0]).as_varint(),
            Err(ProjectionError::InvalidPayload)
        ));
        // as_signed rejects non-canonical wide forms.
        assert!(matches!(
            field(&[251, 0, 0]).as_signed(),
            Err(ProjectionError::InvalidPayload)
        ));
    }

    #[test]
    fn proof_index_consistency_is_enforced() {
        let (record, anchor, version) = build_fixture();
        let proof = prove(&record, &query(&[1, 2]), &ProjectionLimits::new()).unwrap();
        // An index outside the field count is rejected.
        let mut bad = proof.clone();
        bad.leaves[0].index = proof.field_count(); // == field_count is invalid
        assert!(matches!(
            verify(&bad, &anchor, version),
            Err(ProjectionError::TreeGeometry)
        ));
        // Duplicate indices violate the strictly-increasing canonicality
        // check (the frontier duplicate guard is a second line of defense).
        let mut bad = proof.clone();
        bad.leaves[1].index = bad.leaves[0].index;
        assert!(matches!(
            verify(&bad, &anchor, version),
            Err(ProjectionError::NonCanonicalOrder)
        ));
    }

    #[test]
    fn every_query_subset_of_the_fixture_verifies() {
        let (record, anchor, version) = build_fixture();
        let all_ids = [1u32, 2, 3, 4, 5, 9];
        // Enumerate all 2^6 non-empty subsets.
        for mask in 1u32..(1 << all_ids.len()) {
            let ids: Vec<u32> = all_ids
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, id)| *id)
                .collect();
            let proof = prove(&record, &query(&ids), &ProjectionLimits::new()).unwrap();
            let verified = verify(&proof, &anchor, version).unwrap();
            assert_eq!(verified.len(), ids.len(), "subset {ids:?}");
            for (v, id) in verified.iter().zip(ids.iter()) {
                assert_eq!(v.field_id, *id);
            }
        }
    }
}
