use core::marker::PhantomData;

/// Compile-time worst-case encoded size for statically bounded types.
///
/// Dynamic collections intentionally do not implement this trait.
pub trait StaticSize {
    /// Worst-case bytes across supported integer representations.
    const MAX_SIZE: usize;
    /// Worst-case meaningful bits in the bit-packed representation.
    const PACKED_MAX_BITS: usize;
    /// Worst-case bytes when a bit-packed representation is selected.
    const PACKED_MAX_SIZE: usize;
}

#[doc(hidden)]
pub const fn saturating_add(left: usize, right: usize) -> usize {
    left.saturating_add(right)
}

#[doc(hidden)]
pub const fn saturating_mul(left: usize, right: usize) -> usize {
    left.saturating_mul(right)
}

#[doc(hidden)]
pub const fn max(left: usize, right: usize) -> usize {
    if left > right {
        left
    } else {
        right
    }
}

#[doc(hidden)]
pub const fn bytes_for_bits(bits: usize) -> usize {
    bits.saturating_add(7) / 8
}

macro_rules! fixed {
    ($($ty:ty => ($size:expr, $bits:expr)),+ $(,)?) => {$(
        impl StaticSize for $ty {
            const MAX_SIZE: usize = $size;
            const PACKED_MAX_BITS: usize = $bits;
            const PACKED_MAX_SIZE: usize = bytes_for_bits($bits);
        }
    )+};
}

// `MAX_SIZE` is the worst case across supported profiles. In the unified
// nextjson data model every integer crosses the wire at `u64` / `i64` width, so
// the fixed-width profile dominates small integers (tag + 8 bytes) while the
// marker-varint profile dominates 64-bit values (tag + 9 bytes). The
// bit-packed bounds are independent of the wire format.
fixed! {
    () => (1, 0), bool => (1, 1), char => (13, 32),
    i8 => (9, 8), u8 => (9, 8),
    i16 => (9, 16), u16 => (9, 16),
    i32 => (9, 32), u32 => (9, 32),
    i64 => (10, 64), u64 => (10, 64),
    i128 => (18, 128), u128 => (18, 128),
    f32 => (5, 32), f64 => (9, 64)
}

impl<T: StaticSize> StaticSize for Option<T> {
    // None is a single null tag; Some is the tagged value.
    const MAX_SIZE: usize = max(1, T::MAX_SIZE);
    const PACKED_MAX_BITS: usize = saturating_add(1, T::PACKED_MAX_BITS);
    const PACKED_MAX_SIZE: usize = bytes_for_bits(Self::PACKED_MAX_BITS);
}

impl<T: StaticSize, const N: usize> StaticSize for [T; N] {
    // Array tag + elements + terminator.
    const MAX_SIZE: usize = saturating_add(saturating_mul(T::MAX_SIZE, N), 2);
    const PACKED_MAX_BITS: usize = saturating_mul(T::PACKED_MAX_BITS, N);
    const PACKED_MAX_SIZE: usize = bytes_for_bits(Self::PACKED_MAX_BITS);
}

impl<T> StaticSize for PhantomData<T> {
    const MAX_SIZE: usize = 0;
    const PACKED_MAX_BITS: usize = 0;
    const PACKED_MAX_SIZE: usize = 0;
}

macro_rules! tuple_size {
    ($($name:ident),+) => {
        impl<$($name: StaticSize),+> StaticSize for ($($name,)+) {
            // Array tag + elements + terminator.
            const MAX_SIZE: usize = 2usize $(.saturating_add($name::MAX_SIZE))+;
            const PACKED_MAX_BITS: usize = 0usize $(.saturating_add($name::PACKED_MAX_BITS))+;
            const PACKED_MAX_SIZE: usize = bytes_for_bits(Self::PACKED_MAX_BITS);
        }
    };
}

tuple_size!(A);
tuple_size!(A, B);
tuple_size!(A, B, C);
tuple_size!(A, B, C, D);
tuple_size!(A, B, C, D, E);
tuple_size!(A, B, C, D, E, F);
tuple_size!(A, B, C, D, E, F, G);
tuple_size!(A, B, C, D, E, F, G, H);
