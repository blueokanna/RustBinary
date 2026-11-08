//! In-tree zero-copy archive codec (replaces the `rkyv` dependency).
//!
//! # Layout
//!
//! The archive payload is a flat byte buffer with a **root-first, positive
//! relative-offset** layout — an original design distinct from rkyv's
//! root-at-end placement:
//!
//! ```text
//! payload:
//!   [ root skeleton (fixed-size fields)  ]  <- root lives at offset 0
//!   [ data region: string / vec bodies   ]
//! ```
//!
//! Every variable-width field in a struct is a
//! [`crate::archive_codec::RelPtr`]: a signed 32-bit
//! byte offset **from the field's own address** to its data. Because the data
//! region always follows the struct that references it, offsets are positive
//! and the pointer math is monotonic.
//!
//! - A `String` body is `u32 byte_len` followed by UTF-8 bytes.
//! - A `Vec<T>` body is `u32 count`, padding to `align_of::<T>()`, then
//!   `count` `T` elements. The padding keeps the element array aligned so
//!   [`crate::archive_codec::ArchivedVec::as_slice`] can build a `&[T]` without an unaligned
//!   read.
//! - Archived structs are fixed-size mirrors of their source (primitives
//!   inline, strings and vecs as [`crate::archive_codec::RelPtr`]), so a `Vec<Reading>` is a
//!   contiguous array of fixed-size [`crate::archive_codec::ArchivedVec`] elements.
//!
//! # Two-phase serialization
//!
//! A struct is written in two phases so that `Vec<T>` elements stay
//! contiguous: the **skeleton** phase writes the fixed-size fields (inline
//! primitives plus `RelPtr` placeholders for every variable-width field) and
//! records the placeholder positions; the **bodies** phase writes the actual
//! string/vec data and patches each placeholder. Nested structs recurse into
//! the same two phases through a shared position queue.
//!
//! # Safety model
//!
//! The only `unsafe` is `from_raw_parts` for slices of archived primitives
//! and `from_utf8_unchecked` for validated strings, both reached only after
//! [`crate::archive_codec::CheckBytes`] has proven every offset, length, and range in-bounds. The
//! backing buffer is `ALIGN`-aligned (see the archive envelope), so the root
//! and every element array start on an alignment boundary.
//!
//! Archived mirrors stay borrowed in place; copying a relative-pointer field
//! to another address would invalidate its targets.
//!
//! ```compile_fail
//! use rustbinary::archive::Archive;
//! #[derive(Archive)]
//! struct Record { text: String }
//! fn require_copy<T: Copy>() {}
//! require_copy::<ArchivedRecord>();
//! ```
//!
//! ```compile_fail
//! use rustbinary::archive::Archive;
//! #[derive(Archive)]
//! struct Record { text: String }
//! fn require_clone<T: Clone>() {}
//! require_clone::<ArchivedRecord>();
//! ```

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

/// A signed 32-bit byte offset from a field's own address to its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct RelPtr(i32);

impl RelPtr {
    /// Resolves the target address from the field's own address.
    pub(crate) fn resolve(&self, field: *const u8) -> Option<*const u8> {
        if self.0 < 0 {
            return None;
        }
        Some(field.wrapping_add(self.0 as usize))
    }

    /// Reads the offset from a 4-byte little-endian slice.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let value = i32::from_le_bytes(bytes.try_into().ok()?);
        if value < 0 {
            return None;
        }
        Some(Self(value))
    }

    /// The raw offset value.
    pub(crate) fn raw(&self) -> i32 {
        self.0
    }
}

/// The archived form of a UTF-8 string.
///
/// Body layout: `u32 byte_len` followed by UTF-8 bytes.
/// Relative pointers are tied to their address and must not be copied out.
///
/// ```compile_fail
/// use rustbinary::archive_codec::ArchivedString;
/// fn relocate(value: &ArchivedString) -> ArchivedString { *value }
/// ```
#[repr(transparent)]
pub struct ArchivedString {
    ptr: RelPtr,
}

impl ArchivedString {
    /// Resolves the string from the field's own address.
    ///
    /// # Safety
    ///
    /// The archive must have been validated with [`CheckBytes`] and the
    /// backing buffer must be immutable for the returned borrow.
    pub unsafe fn as_str_unchecked(&self) -> &str {
        let field = self as *const ArchivedString as *const u8;
        let data = unsafe { self.ptr.resolve(field).unwrap_unchecked() };
        let len = u32::from_le(unsafe { (data as *const u32).read_unaligned() }) as usize;
        unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(data.add(4), len)) }
    }

    /// Returns the string (requires prior [`CheckBytes`]).
    pub fn as_str(&self) -> &str {
        unsafe { self.as_str_unchecked() }
    }

    /// Returns the raw UTF-8 bytes (requires prior [`CheckBytes`]).
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Returns the byte length (requires prior [`CheckBytes`]).
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Whether the string is empty (requires prior [`CheckBytes`]).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The archived form of a `Vec<T>`.
///
/// Body layout: `u32 count` followed by `count` elements.
///
/// ```compile_fail
/// use rustbinary::archive_codec::ArchivedVec;
/// fn relocate(value: &ArchivedVec<u64>) -> ArchivedVec<u64> { *value }
/// ```
#[repr(transparent)]
pub struct ArchivedVec<T> {
    ptr: RelPtr,
    marker: PhantomData<T>,
}

impl<T: ArchivedValue> ArchivedVec<T> {
    /// Resolves the elements from the field's own address.
    ///
    /// # Safety
    ///
    /// The archive must have been validated with [`CheckBytes`] and the
    /// backing buffer must be immutable for the returned borrow.
    pub unsafe fn as_slice_unchecked(&self) -> &[T] {
        let field = self as *const ArchivedVec<T> as *const u8;
        let data = unsafe { self.ptr.resolve(field).unwrap_unchecked() };
        let count = u32::from_le(unsafe { (data as *const u32).read_unaligned() }) as usize;
        let padding = (core::mem::align_of::<T>()
            - (data.wrapping_add(4) as usize % core::mem::align_of::<T>()))
            % core::mem::align_of::<T>();
        let elements = unsafe { data.add(4 + padding).cast::<T>() };
        unsafe { core::slice::from_raw_parts(elements, count) }
    }

    /// Returns the elements as a slice (requires prior [`CheckBytes`]).
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: contract of the archive API: validate before access.
        unsafe { self.as_slice_unchecked() }
    }

    /// Returns a pointer to the first element (requires prior [`CheckBytes`]).
    pub fn as_ptr(&self) -> *const T {
        self.as_slice().as_ptr()
    }

    /// Returns an iterator over the elements (requires prior [`CheckBytes`]).
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }

    /// Returns the element count (requires prior [`CheckBytes`]).
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Whether the vector is empty (requires prior [`CheckBytes`]).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: ArchivedValue> core::ops::Index<usize> for ArchivedVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        &self.as_slice()[index]
    }
}

/// Marker for archived values whose in-memory representation is their wire
/// layout and which can therefore be read as a contiguous slice.
///
/// Implemented for archived primitives (`u64`, `i32`, ...) and for archived
/// structs whose fields are all [`ArchivedValue`] (generated by the derive).
/// Relative-pointer values must stay borrowed at their validated address.
///
/// # Safety
///
/// Implementing types must have `align_of::<Self>() <= 8`, and
/// their bytes must be a valid in-memory value for every possible byte
/// pattern. Safe accessors may rely only on invariants established by
/// `CheckBytes`; types with relative pointers must not permit safe relocation
/// (including through `Copy` or `Clone`) or mutation of the backing bytes.
pub unsafe trait ArchivedValue: 'static {}

macro_rules! archived_primitive {
    ($($t:ty),* $(,)?) => {$(
        unsafe impl ArchivedValue for $t {}
    )*};
}

archived_primitive!(u8, u16, u32, u64, i8, i16, i32, i64, f32, f64);

// `ArchivedString` is a single `RelPtr` (an `i32`): `'static`,
// 4-aligned, and every byte pattern is a valid offset value.
unsafe impl ArchivedValue for ArchivedString {}
// `ArchivedVec<T>` is a `RelPtr` plus a zero-sized marker:
// `'static` (via the `T: 'static` supertrait of `ArchivedValue`), 4-aligned,
// and every byte pattern is a valid offset value.
unsafe impl<T: ArchivedValue> ArchivedValue for ArchivedVec<T> {}

/// The archive schema contract: the archived mirror type.
pub trait Archive {
    /// The archived mirror type.
    type Archived;
}

/// The archival serialization contract.
///
/// A type that can be archived writes its fixed-size **skeleton** (inline
/// primitives plus `RelPtr` placeholders) in the skeleton phase, then its
/// variable-width **bodies** in the bodies phase. The two phases are separated
/// so that `Vec<T>` element arrays stay contiguous in memory.
pub trait ArchiveWrite {
    /// Writes the skeleton fields and records every placeholder position.
    fn write_skeleton(&self, serializer: &mut ArchiveSerializer, positions: &mut VecDeque<usize>);

    /// Writes the variable-width bodies and patches placeholders.
    fn write_bodies(
        &self,
        serializer: &mut ArchiveSerializer,
        positions: &mut VecDeque<usize>,
    ) -> Result<(), String>;
}

/// Serializer that produces the flat archive payload.
pub struct ArchiveSerializer {
    bytes: Vec<u8>,
}

impl Default for ArchiveSerializer {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveSerializer {
    /// Creates an empty serializer.
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// The current length of the output buffer.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the output buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Starts a fresh payload (root at offset 0).
    pub fn begin(&mut self) -> usize {
        self.bytes.clear();
        0
    }

    /// Writes a fixed-width `u8`.
    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Writes a fixed-width `u16`.
    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a fixed-width `u32`.
    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a fixed-width `u64`.
    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a fixed-width `i8`.
    pub fn write_i8(&mut self, value: i8) {
        self.bytes.push(value as u8);
    }

    /// Writes a fixed-width `i16`.
    pub fn write_i16(&mut self, value: i16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a fixed-width `i32`.
    pub fn write_i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a fixed-width `i64`.
    pub fn write_i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a fixed-width `f32`.
    pub fn write_f32(&mut self, value: f32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a fixed-width `f64`.
    pub fn write_f64(&mut self, value: f64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a fixed-width `bool`.
    pub fn write_bool(&mut self, value: bool) {
        self.bytes.push(value as u8);
    }

    /// Reserves a 4-byte placeholder for a [`RelPtr`] and returns the absolute
    /// position of the placeholder.
    pub fn reserve_ptr(&mut self) -> usize {
        let pos = self.bytes.len();
        self.bytes.extend_from_slice(&0i32.to_le_bytes());
        pos
    }

    /// Pads the output with zero bytes until the length is a multiple of
    /// `align`.
    ///
    /// The archived mirrors are `#[repr(C)]` structs, so the writer inserts
    /// the same padding between fields (and before `Vec<T>` element arrays)
    /// that the C ABI does. A zero `align` would divide by zero; the derive
    /// only ever passes real type alignments (1, 2, 4, or 8).
    pub fn align_to(&mut self, align: usize) {
        debug_assert!(align != 0 && align.is_power_of_two());
        let remainder = self.bytes.len() % align;
        if remainder != 0 {
            let pad = align - remainder;
            self.bytes.resize(self.bytes.len() + pad, 0);
        }
    }

    /// Appends a `String` body and patches the placeholder at `field_pos`.
    pub fn write_string_at(&mut self, field_pos: usize, value: &str) -> Result<(), String> {
        let data_pos = self.bytes.len();
        let len = u32::try_from(value.len()).map_err(|_| "archive string exceeds u32 length")?;
        self.patch_ptr(field_pos, data_pos)?;
        self.bytes.extend_from_slice(&len.to_le_bytes());
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    /// Appends a `Vec<T>` body (count + alignment padding + elements) and
    /// patches the placeholder.
    pub fn write_vec_at<T: Pod>(&mut self, field_pos: usize, values: &[T]) -> Result<(), String> {
        let data_pos = self.bytes.len();
        let count = u32::try_from(values.len()).map_err(|_| "archive vec exceeds u32 count")?;
        let elements_pos = checked_vec_elements_offset(data_pos, core::mem::align_of::<T>())?;
        self.patch_ptr(field_pos, data_pos)?;
        self.bytes.extend_from_slice(&count.to_le_bytes());
        while self.bytes.len() < elements_pos {
            self.bytes.push(0);
        }
        for value in values {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(())
    }

    /// Patches the placeholder at `field_pos` with the offset from
    /// `field_pos` to `data_pos`.
    pub fn patch_ptr(&mut self, field_pos: usize, data_pos: usize) -> Result<(), String> {
        let delta = data_pos
            .checked_sub(field_pos)
            .and_then(|delta| i32::try_from(delta).ok())
            .ok_or("archive relative offset is outside the positive i32 range")?;
        if data_pos > self.bytes.len() {
            return Err("archive pointer target out of bounds".into());
        }
        let end = field_pos
            .checked_add(4)
            .ok_or("archive pointer position overflow")?;
        self.bytes
            .get_mut(field_pos..end)
            .ok_or("archive pointer placeholder out of bounds")?
            .copy_from_slice(&delta.to_le_bytes());
        Ok(())
    }

    /// Returns the complete payload.
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Plain-data value serialized by its little-endian byte representation.
pub trait Pod: Sized {
    /// The little-endian byte representation.
    fn to_le_bytes(&self) -> Vec<u8>;
}

macro_rules! pod_impl {
    ($($t:ty),* $(,)?) => {$(
        impl Pod for $t {
            fn to_le_bytes(&self) -> Vec<u8> {
                <$t>::to_le_bytes(*self).to_vec()
            }
        }
    )*};
}

pod_impl!(u8, u16, u32, u64, i8, i16, i32, i64, f32, f64);

impl Pod for bool {
    fn to_le_bytes(&self) -> Vec<u8> {
        vec![*self as u8]
    }
}

/// Validates an archived value.
///
/// This is the in-tree replacement for rkyv's `check_archived_root`. It walks
/// the whole graph once, proving every offset, length, and range in-bounds,
/// and must run before the first access.
///
/// # Safety
///
/// Returning success must prove that `bytes` at `base` holds a fully valid,
/// aligned `Self`, including its complete skeleton and every reachable value.
/// All references exposed by safe accessors must remain inside `bytes`, with
/// valid alignment and representation, for the lifetime of that immutable
/// buffer. Implementations must not allow safe relocation of relative pointers
/// or interior mutation that invalidates these guarantees.
///
/// ```compile_fail
/// use rustbinary::archive_codec::CheckBytes;
/// struct Unchecked(bool);
/// impl CheckBytes for Unchecked {
///     fn check_at(_: &[u8], _: usize) -> Result<(), String> { Ok(()) }
/// }
/// ```
pub unsafe trait CheckBytes {
    /// Validates the archived value at `base` inside `bytes`.
    fn check_at(bytes: &[u8], base: usize) -> Result<(), String>;
}

std::thread_local! {
    // Shared by recursive generated validators on this thread. The outermost
    // guard resets the work counter, including when validation unwinds.
    static VALIDATION_STATE: core::cell::Cell<(usize, u64)> = const {
        core::cell::Cell::new((0, 0))
    };
}

/// Recursion and total-visit guard used by generated archive validators.
#[doc(hidden)]
pub struct ValidationGuard(PhantomData<*mut ()>);

impl ValidationGuard {
    /// Starts one validation step, capped at 128 active steps and one million
    /// visits per outermost call. The guard must live until child checks finish.
    pub fn enter() -> Result<Self, String> {
        VALIDATION_STATE.with(|state| {
            let (depth, visits) = state.get();
            if depth >= crate::tags::MAX_DEPTH {
                return Err("archive validation depth limit exceeded".into());
            }
            if visits >= crate::config::DEFAULT_COLLECTION_LIMIT {
                return Err("archive validation visit limit exceeded".into());
            }
            state.set((depth + 1, visits + 1));
            Ok(Self(PhantomData))
        })
    }
}

impl Drop for ValidationGuard {
    fn drop(&mut self) {
        VALIDATION_STATE.with(|state| {
            let (depth, visits) = state.get();
            state.set(if depth == 1 {
                (0, 0)
            } else {
                (depth - 1, visits)
            });
        });
    }
}

unsafe impl CheckBytes for ArchivedString {
    fn check_at(bytes: &[u8], base: usize) -> Result<(), String> {
        check_skeleton::<Self>(bytes, base)?;
        check_string_field(bytes, base)
    }
}

/// Reads the `RelPtr` at `field_pos` and bounds-checks its target plus
/// `header` bytes (the `u32` length) inside `bytes`.
pub(crate) fn checked_field(bytes: &[u8], field_pos: usize) -> Option<usize> {
    let ptr = RelPtr::from_bytes(bytes.get(field_pos..field_pos.checked_add(4)?)?)?;
    let target = field_pos.checked_add(ptr.raw() as usize)?;
    let end = target.checked_add(4)?;
    if end > bytes.len() {
        return None;
    }
    Some(target)
}

/// Checks the entire fixed-size representation, including trailing padding,
/// before a validator walks fields or constructs a typed reference.
pub fn check_skeleton<T>(bytes: &[u8], base: usize) -> Result<(), String> {
    if cfg!(target_endian = "big") {
        return Err("zero-copy archive access requires a little-endian target".into());
    }
    let end = base
        .checked_add(core::mem::size_of::<T>())
        .ok_or("archive skeleton size overflow")?;
    if end > bytes.len() {
        return Err("archive skeleton out of bounds".into());
    }
    let alignment = core::mem::align_of::<T>();
    if base % alignment != 0 || bytes.as_ptr() as usize % alignment != 0 {
        return Err("archive skeleton is misaligned".into());
    }
    Ok(())
}

fn checked_vec_elements_offset(body_base: usize, align: usize) -> Result<usize, String> {
    if !align.is_power_of_two() {
        return Err("invalid vec element alignment".into());
    }
    let after_count = body_base.checked_add(4).ok_or("vec header overflow")?;
    after_count
        .checked_add((align - after_count % align) % align)
        .ok_or_else(|| "vec alignment overflow".into())
}

/// Byte offset of the element array inside a `Vec<T>` body, given the body's
/// base address (the position of the `u32` count). The writer inserts the
/// same padding, so reader and writer always agree.
pub(crate) fn vec_elements_offset(body_base: usize, align: usize) -> usize {
    let after_count = body_base + 4;
    let pad = (align - (after_count % align)) % align;
    after_count + pad
}

/// The alignment helper for a concrete element type, mirroring the private
/// `vec_elements_offset` used by the writer and validators (crate-private, so
/// not linkable from public docs).
pub fn vec_elements_offset_of<T>(body_base: usize) -> usize {
    vec_elements_offset(body_base, core::mem::align_of::<T>())
}

/// Checks a `String` field: reads `u32 len` at the target and verifies the
/// UTF-8 bytes fit.
pub fn check_string_field(bytes: &[u8], field_pos: usize) -> Result<(), String> {
    let target = checked_field(bytes, field_pos).ok_or("string offset out of bounds")?;
    let len = u32::from_le_bytes(
        bytes
            .get(target..target + 4)
            .ok_or("string length out of bounds")?
            .try_into()
            .map_err(|_| "string length read failed")?,
    ) as usize;
    let body = target + 4;
    let end = body.checked_add(len).ok_or("string body length overflow")?;
    if end > bytes.len() {
        return Err("string body out of bounds".into());
    }
    core::str::from_utf8(&bytes[body..end])
        .map(|_| ())
        .map_err(|_| "invalid UTF-8 in archived string".into())
}

/// Checks a `Vec<T>` field of fixed-size elements: reads `u32 count` at the
/// target, skips the alignment padding, and verifies the element slice fits.
pub fn check_vec_field(
    bytes: &[u8],
    field_pos: usize,
    element_size: usize,
    element_align: usize,
) -> Result<(), String> {
    if cfg!(target_endian = "big")
        || !element_align.is_power_of_two()
        || bytes.as_ptr() as usize % element_align != 0
        || element_size % element_align != 0
    {
        return Err("invalid or misaligned vec element layout".into());
    }
    let target = checked_field(bytes, field_pos).ok_or("vec offset out of bounds")?;
    let count = u32::from_le_bytes(
        bytes
            .get(target..target + 4)
            .ok_or("vec count out of bounds")?
            .try_into()
            .map_err(|_| "vec count read failed")?,
    ) as usize;
    let size = count
        .checked_mul(element_size)
        .ok_or("vec body size overflow")?;
    let body = checked_vec_elements_offset(target, element_align)?;
    let end = body.checked_add(size).ok_or("vec body overflow")?;
    if end > bytes.len() {
        return Err("vec body out of bounds".into());
    }
    Ok(())
}

/// Checks a `Vec<T>` field of nested archived structs: verifies the element
/// slice fits (including alignment padding) and recursively validates each
/// element.
pub fn check_vec_nested<T: CheckBytes>(
    bytes: &[u8],
    field_pos: usize,
    element_size: usize,
    element_align: usize,
) -> Result<(), String> {
    let _validation = ValidationGuard::enter()?;
    if element_size != core::mem::size_of::<T>() || element_align != core::mem::align_of::<T>() {
        return Err("nested vec element layout does not match its type".into());
    }
    check_vec_field(bytes, field_pos, element_size, element_align)?;
    let target = checked_field(bytes, field_pos).ok_or("vec offset out of bounds")?;
    let count = u32::from_le_bytes(
        bytes
            .get(target..target + 4)
            .ok_or("vec count out of bounds")?
            .try_into()
            .map_err(|_| "vec count read failed")?,
    ) as usize;
    let size = count
        .checked_mul(element_size)
        .ok_or("vec body size overflow")?;
    let body = checked_vec_elements_offset(target, element_align)?;
    let end = body.checked_add(size).ok_or("vec body overflow")?;
    if end > bytes.len() {
        return Err("vec body out of bounds".into());
    }
    for i in 0..count {
        let element_base = body
            .checked_add(
                i.checked_mul(element_size)
                    .ok_or("vec element offset overflow")?,
            )
            .ok_or("vec element offset overflow")?;
        T::check_at(bytes, element_base)?;
    }
    Ok(())
}

/// Convenience: serializes a root value into a fresh payload.
pub fn to_archive<T: ArchiveWrite>(value: &T) -> Result<Vec<u8>, String> {
    let mut serializer = ArchiveSerializer::new();
    serializer.begin();
    let mut positions = VecDeque::new();
    value.write_skeleton(&mut serializer, &mut positions);
    value.write_bodies(&mut serializer, &mut positions)?;
    Ok(serializer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the `u32` at a validated body position via pure slice indexing.
    ///
    /// Every caller runs the matching `check_*_field` validator first, so the
    /// range is already known in-bounds; indexing here can never go out of
    /// bounds and needs no raw pointers.
    fn read_u32(bytes: &[u8], pos: usize) -> u32 {
        u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("validated u32 range"))
    }

    #[test]
    fn string_roundtrip() {
        let mut serializer = ArchiveSerializer::new();
        serializer.begin();
        let field = serializer.reserve_ptr();
        serializer.write_string_at(field, "hello archive").unwrap();
        let payload = serializer.finish();
        check_string_field(&payload, field).unwrap();

        let target = checked_field(&payload, field).expect("validated string offset");
        let len = read_u32(&payload, target) as usize;
        let body = &payload[target + 4..target + 4 + len];
        assert_eq!(
            core::str::from_utf8(body).expect("validated UTF-8"),
            "hello archive"
        );
    }

    #[test]
    fn vec_roundtrip() {
        let mut serializer = ArchiveSerializer::new();
        serializer.begin();
        let field = serializer.reserve_ptr();
        serializer
            .write_vec_at(field, &[1i32, 2, 3, 65_536])
            .unwrap();
        let payload = serializer.finish();
        check_vec_field(&payload, field, 4, 4).unwrap();
        let target = checked_field(&payload, field).expect("validated vec offset");
        assert_eq!(read_u32(&payload, target), 4);
        let elements = vec_elements_offset(target, 4);
        let expected = [1i32, 2, 3, 65_536];
        for (i, &value) in expected.iter().enumerate() {
            let start = elements + i * 4;
            let word: [u8; 4] = payload[start..start + 4]
                .try_into()
                .expect("validated element");
            assert_eq!(i32::from_le_bytes(word), value);
        }
    }

    #[test]
    fn vec_elements_are_aligned() {
        let mut serializer = ArchiveSerializer::new();
        serializer.begin();
        let string_field = serializer.reserve_ptr();
        serializer.write_string_at(string_field, "abc").unwrap();
        serializer.align_to(4);
        let vec_field = serializer.reserve_ptr();
        serializer.write_vec_at(vec_field, &[7i32, 8, 9]).unwrap();
        let payload = serializer.finish();
        check_vec_field(&payload, vec_field, 4, 4).unwrap();

        let target = checked_field(&payload, vec_field).expect("validated vec offset");
        assert_eq!(read_u32(&payload, target), 3);
        let elements = vec_elements_offset(target, 4);
        assert_eq!(elements % 4, 0, "element array must be 4-aligned");
        let expected = [7i32, 8, 9];
        for (i, &value) in expected.iter().enumerate() {
            let start = elements + i * 4;
            let word: [u8; 4] = payload[start..start + 4]
                .try_into()
                .expect("validated element");
            assert_eq!(i32::from_le_bytes(word), value);
        }
    }

    #[test]
    fn negative_offsets_are_rejected() {
        let mut serializer = ArchiveSerializer::new();
        serializer.begin();
        let field = serializer.reserve_ptr();
        serializer.bytes[field..field + 4].copy_from_slice(&(-8i32).to_le_bytes());
        let payload = serializer.finish();
        assert!(check_string_field(&payload, field).is_err());
    }

    #[test]
    fn corrupted_length_is_rejected() {
        let mut serializer = ArchiveSerializer::new();
        serializer.begin();
        let field = serializer.reserve_ptr();
        serializer.write_string_at(field, "x").unwrap();
        let mut payload = serializer.finish();

        let target = RelPtr::from_bytes(&payload[field..field + 4])
            .unwrap()
            .raw() as usize;
        payload[target..target + 4].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(check_string_field(&payload, field).is_err());
    }

    #[test]
    fn nested_vec_elements_are_checked() {
        let mut serializer = ArchiveSerializer::new();
        serializer.begin();
        let field = serializer.reserve_ptr();
        serializer.write_u32(2); // count
        serializer.write_u64(10);
        serializer.write_u32(100);
        serializer.write_u64(20);
        serializer.write_u32(200);
        serializer.patch_ptr(field, 0).unwrap();
        let payload = serializer.finish();

        check_vec_field(&payload, field, 12, 1).unwrap();
    }
}
