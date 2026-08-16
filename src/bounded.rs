//! Resource-bounded decoding with a schema-derived cost algebra.
//!
//! # Problem model
//!
//! `StaticSize` bounds the *encoded bytes* of a value. This module advances
//! that idea to **provable resource semantics**: for every type `T` the derive
//! generates a cost algebra
//!
//! ```text
//! B(T)  maximum input bytes one decode of T can consume
//! A(T)  maximum heap bytes one decode of T can allocate
//! D(T)  maximum parser nesting depth (0 = no container)
//! W(T)  worst-case work in abstract units (bytes read + per-field overhead)
//! ```
//!
//! and [`decode_bounded`] runs the decode under a [`Budget`] that is enforced
//! at runtime, returning a [`Decoded<T>`] whose [`ResourceUse`] carries the
//! exact bytes read plus provable upper bounds for allocation, depth, and
//! work. The algebra is *isomorphic to the parser*: the derive mirrors the
//! exact container structure (object/array tags, terminators, per-field keys)
//! that `ser`/`decoder` walk, so the constants are the parser's own worst case
//! rather than a separate estimate.
//!
//! # What is proven vs. what is enforced
//!
//! - **Statically bounded types** (no dynamic collections or strings anywhere
//!   in `T`): all four constants are finite and **exact**. A decode of such a
//!   `T` reads at most `B(T)` input bytes, allocates at most `A(T)` bytes
//!   (usually 0), nests at most `D(T)` containers, and performs at most
//!   `W(T)` work units — by construction of the wire format.
//! - **Dynamic types** (`Vec`, `String`, `&str`, ...): `B`, `A` and `W` are
//!   content-dependent, so the derive reports `usize::MAX` and the *runtime*
//!   budget enforces the caller's limits. The depth constant `D` stays exact
//!   (a `Vec<T>` adds exactly one container level).
//!
//! # The allocation ceiling (what is proven)
//!
//! A decode allocates for two disjoint classes of bytes:
//!
//! - **Data**: the bytes materialized from input (string and byte-buffer
//!   bodies). Every such byte is read from the wire, so `data ≤ read`.
//! - **Structure**: collection backing buffers and boxes beyond their wire
//!   data. The derive computes [`DecodeBounded::MAX_STRUCTURAL_ELEMENT`] — the
//!   worst per-element structural allocation across every collection in the
//!   type (for `Vec<T>` that is `size_of::<T>()`, for `Box<T>` it is
//!   `size_of::<T>()`, for `String` it is `0`). A decode of `T` has at most
//!   `D(T)` nested collection levels, each capped at the collection limit, so
//!   total elements `≤ D(T) · collection_limit` and
//!
//!   ```text
//!   allocation ≤ read + MAX_STRUCTURAL_ELEMENT · D(T) · collection_limit
//!   ```
//!
//!   `decode_bounded` sets the collection limit so that this ceiling is at
//!   most `max_input + max_alloc`, and returns it as
//!   [`ResourceUse::alloc_bound`]. For types whose derive cannot know the
//!   structural cost (manual [`DecodeBounded`] implementations that leave
//!   `MAX_STRUCTURAL_ELEMENT` at its `usize::MAX` default), the budget's
//!   `element_structure_bytes` knob is used instead; its default of
//!   [`ELEMENT_STRUCTURE_BYTES`] (64) covers the standard collection shapes
//!   (String headers, Vec backing entries, std BTreeMap nodes). Wide-tuple or
//!   large-inline-element layouts should raise the knob or the `max_alloc`.
//!
//! # DoS contract
//!
//! `decode_bounded` rejects input *before* allocating when the budget is
//! violated, and every failure reports which dimension was exceeded
//! ([`BudgetExceeded`]). This is the entry point for DoS-sensitive consumers
//! (blockchain nodes, enclaves, gateways): the caller picks a `Budget` from
//! its policy — or from [`Budget::from_type::<T>()`], which derives tight
//! defaults from the algebra — and receives evidence of what the decode
//! actually consumed.

use core::fmt;
use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::config::{Config, DEFAULT_COLLECTION_LIMIT, DEFAULT_SIZE_LIMIT};
use crate::decoder;
use crate::tags::MAX_DEPTH;

/// Default per-element structural allocation ceiling, in bytes.
///
/// Used as the fallback structural bound when a type's
/// [`DecodeBounded::MAX_STRUCTURAL_ELEMENT`] is unknown (manual trait
/// implementations), and as the default of [`Budget::element_structure_bytes`].
/// 64 conservatively covers the standard collection shapes this codec drives:
/// `String` headers (24 bytes), `Vec` backing entries (`size_of::<T>()`, 8 for
/// pointers), and std `BTreeMap` nodes (~50 bytes per element for small
/// keys). Data materialized from input bytes (string and byte-buffer bodies)
/// is *not* structural; it is bounded by `max_input`. Types whose per-element
/// structural footprint exceeds this (wide tuples of small collections,
/// large inline element structs) must raise the budget knob or `max_alloc`.
pub const ELEMENT_STRUCTURE_BYTES: u64 = 64;

/// Compile-time cost algebra for one type, mirroring the parser structure.
///
/// Implementations are generated by `#[derive(DecodeBounded)]`; see the module
/// documentation for the exact semantics of each constant and the distinction
/// between statically bounded and dynamic types.
pub trait DecodeBounded {
    /// `B(T)`: worst-case input bytes consumed by one decode of `T`.
    ///
    /// `usize::MAX` when the encoded size depends on content (strings,
    /// collections, borrowed text).
    const MAX_INPUT: usize;
    /// `A(T)`: worst-case heap bytes allocated by one decode of `T`.
    ///
    /// `usize::MAX` when allocation depends on content. A finite value (usually
    /// `0`) marks the type as *statically bounded*.
    const MAX_ALLOC: usize;
    /// `D(T)`: worst-case parser nesting depth (0 = no container).
    ///
    /// Always finite: even dynamic collections add exactly one container level.
    const MAX_DEPTH: usize;
    /// `W(T)`: worst-case work in abstract units.
    ///
    /// `usize::MAX` when content-dependent.
    const MAX_WORK: usize;
    /// Worst per-collection-element structural allocation ceiling, in bytes.
    ///
    /// The maximum, across every collection in `T`, of the heap a single
    /// element's backing structure can occupy *beyond* the wire bytes it is
    /// decoded from. The derive fills it from the element types (`Vec<T>` and
    /// `Box<T>` report `size_of::<T>()`, `String` reports `0` because its heap
    /// is data-bound). `usize::MAX` when unknown; `decode_bounded` then falls
    /// back to the budget's `element_structure_bytes` knob.
    const MAX_STRUCTURAL_ELEMENT: usize = usize::MAX;

    /// Whether the type's resource use is content-independent.
    ///
    /// `true` when no field is dynamic (`MAX_ALLOC` is finite).
    const STATICALLY_BOUNDED: bool = Self::MAX_ALLOC != usize::MAX;
}

/// Runtime budget for one bounded decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    max_input: u64,
    max_alloc: u64,
    max_depth: usize,
    max_work: u64,
    element_structure_bytes: u64,
}

impl Budget {
    /// Creates a budget with explicit limits.
    ///
    /// The per-element structural knob defaults to [`ELEMENT_STRUCTURE_BYTES`].
    pub const fn new(max_input: u64, max_alloc: u64, max_depth: usize, max_work: u64) -> Self {
        Self {
            max_input,
            max_alloc,
            max_depth,
            max_work,
            element_structure_bytes: ELEMENT_STRUCTURE_BYTES,
        }
    }

    /// Derives a budget from `T`'s cost algebra.
    ///
    /// Finite constants become tight limits; `usize::MAX` constants fall back
    /// to the crate-wide defaults ([`DEFAULT_SIZE_LIMIT`] for input/allocation/
    /// work, `MAX_DEPTH` for depth). For statically bounded types the result
    /// is exact.
    pub const fn from_type<T: DecodeBounded>() -> Self {
        Self {
            max_input: const_or_default(T::MAX_INPUT, DEFAULT_SIZE_LIMIT),
            max_alloc: const_or_default(T::MAX_ALLOC, DEFAULT_SIZE_LIMIT),
            max_depth: if T::MAX_DEPTH == usize::MAX {
                MAX_DEPTH
            } else {
                T::MAX_DEPTH
            },
            max_work: const_or_default(T::MAX_WORK, DEFAULT_SIZE_LIMIT),
            element_structure_bytes: ELEMENT_STRUCTURE_BYTES,
        }
    }

    /// Derives a budget from an existing [`Config`]'s resource policy.
    pub const fn from_config(config: Config) -> Self {
        let max_input = match config.limit() {
            Some(limit) => limit,
            None => DEFAULT_SIZE_LIMIT,
        };
        let max_alloc = match config.collection_limit() {
            Some(limit) => limit.saturating_mul(ELEMENT_STRUCTURE_BYTES),
            None => DEFAULT_COLLECTION_LIMIT.saturating_mul(ELEMENT_STRUCTURE_BYTES),
        };
        Self {
            max_input,
            max_alloc,
            max_depth: config.depth_limit(),
            max_work: max_input,
            element_structure_bytes: ELEMENT_STRUCTURE_BYTES,
        }
    }

    /// Sets the maximum input bytes a decode may consume.
    pub const fn with_max_input(mut self, limit: u64) -> Self {
        self.max_input = limit;
        self
    }

    /// Sets the structural allocation budget (see the module documentation
    /// for the exact ceiling it implies).
    pub const fn with_max_alloc(mut self, limit: u64) -> Self {
        self.max_alloc = limit;
        self
    }

    /// Sets the maximum parser nesting depth.
    ///
    /// Clamped to the crate-wide `MAX_DEPTH` at decode time.
    pub const fn with_max_depth(mut self, limit: usize) -> Self {
        self.max_depth = limit;
        self
    }

    /// Sets the maximum work in abstract units.
    pub const fn with_max_work(mut self, limit: u64) -> Self {
        self.max_work = limit;
        self
    }

    /// Sets the per-collection-element structural allocation ceiling in bytes.
    ///
    /// Used only when the decoded type does not declare its own
    /// [`DecodeBounded::MAX_STRUCTURAL_ELEMENT`] (manual trait
    /// implementations). See the module documentation for the exact contract;
    /// the default is [`ELEMENT_STRUCTURE_BYTES`] (64).
    pub const fn with_element_structure_bytes(mut self, bytes: u64) -> Self {
        self.element_structure_bytes = bytes;
        self
    }

    /// Returns the maximum input bytes.
    pub const fn max_input(self) -> u64 {
        self.max_input
    }

    /// Returns the structural allocation budget.
    pub const fn max_alloc(self) -> u64 {
        self.max_alloc
    }

    /// Returns the maximum nesting depth.
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    /// Returns the maximum work.
    pub const fn max_work(self) -> u64 {
        self.max_work
    }

    /// Returns the per-element structural allocation ceiling.
    pub const fn element_structure_bytes(self) -> u64 {
        self.element_structure_bytes
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_input: DEFAULT_SIZE_LIMIT,
            max_alloc: DEFAULT_COLLECTION_LIMIT.saturating_mul(ELEMENT_STRUCTURE_BYTES),
            max_depth: MAX_DEPTH,
            max_work: DEFAULT_SIZE_LIMIT,
            element_structure_bytes: ELEMENT_STRUCTURE_BYTES,
        }
    }
}

/// Measured resource use of one bounded decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceUse {
    /// Exact input bytes consumed by the decode.
    pub read: u64,
    /// Provable upper bound on heap allocation for this decode.
    ///
    /// Exact for statically bounded types (`A(T)`); the conservative ceiling
    /// `read + ELEMENT_STRUCTURE_BYTES · collection_limit` for dynamic types.
    pub alloc_bound: u64,
    /// Enforced nesting-depth ceiling for this decode.
    pub depth_bound: usize,
    /// Provable work bound for this decode.
    ///
    /// Exact `W(T)` for statically bounded types; the consumed byte count for
    /// dynamic types (work is dominated by the linear input scan).
    pub work_bound: u64,
}

/// A value decoded under a budget, together with its resource-use evidence.
#[derive(Debug)]
pub struct Decoded<T> {
    /// The decoded value.
    pub value: T,
    /// Resource-use evidence for this decode.
    pub use_: ResourceUse,
}

impl<T> Decoded<T> {
    /// Maps the decoded value.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Decoded<U> {
        Decoded {
            value: f(self.value),
            use_: self.use_,
        }
    }
}

/// Which budget dimension was exceeded.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum BudgetExceeded {
    /// The input exceeded the byte budget before (or during) decoding.
    Input {
        /// The configured limit.
        limit: u64,
    },
    /// The structural allocation budget would be exceeded (collections are
    /// capped by the derived collection limit).
    Alloc {
        /// The configured allocation budget.
        limit: u64,
    },
    /// The type's nesting depth exceeds the configured depth budget.
    Depth {
        /// The configured limit.
        limit: usize,
    },
    /// The work budget was exceeded.
    Work {
        /// The configured limit.
        limit: u64,
    },
}

/// Errors from [`decode_bounded`].
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// The budget was exceeded; see [`BudgetExceeded`] for the dimension.
    Budget(BudgetExceeded),
    /// The underlying codec rejected the input (malformed, size/collection
    /// limit, trailing bytes, ...).
    Codec(crate::Error),
}

impl fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input { limit } => write!(f, "bounded decode: input exceeds {limit} bytes"),
            Self::Alloc { limit } => {
                write!(
                    f,
                    "bounded decode: allocation budget {limit} would be exceeded"
                )
            }
            Self::Depth { limit } => write!(f, "bounded decode: depth exceeds {limit}"),
            Self::Work { limit } => write!(f, "bounded decode: work exceeds {limit} units"),
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Budget(budget) => budget.fmt(f),
            Self::Codec(error) => write!(f, "bounded decode failed: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

impl From<crate::Error> for DecodeError {
    fn from(error: crate::Error) -> Self {
        Self::Codec(error)
    }
}

/// Selects `value` when finite, otherwise `default`.
#[doc(hidden)]
pub const fn const_or_default(value: usize, default: u64) -> u64 {
    if value == usize::MAX {
        default
    } else {
        value as u64
    }
}

/// Enforced limits derived from a [`Budget`] and a type's static-boundedness.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnforcedLimits {
    /// Input byte limit (the tighter of `max_input` and `max_work`).
    pub byte_limit: u64,
    /// Per-collection element cap.
    pub collection_limit: u64,
    /// Nesting-depth cap (clamped to `MAX_DEPTH`).
    pub depth_limit: usize,
}

/// Pure derivation of the enforced limits from a budget.
///
/// The byte limit is the tighter of input and work (every read costs at least
/// one work unit). For dynamic types the collection limit caps the *per-
/// collection* element count so that, together with the per-element structural
/// ceiling and the type's nesting depth, the documented allocation ceiling
/// `byte_limit + per_element_ceiling · collection_limit` holds. Statically
/// bounded types have no dynamic collections, so their element count is
/// bounded directly by the byte limit (every element costs at least one input
/// byte).
#[doc(hidden)]
pub const fn derive_enforced_limits(
    budget: Budget,
    statically_bounded: bool,
    per_element_ceiling: u64,
) -> EnforcedLimits {
    let byte_limit = if budget.max_input < budget.max_work {
        budget.max_input
    } else {
        budget.max_work
    };
    let collection_limit = if statically_bounded {
        byte_limit
    } else {
        // `checked_div` yields `None` for a zero ceiling, meaning the type has
        // no structural allocation and needs no per-element cap.
        match budget.max_alloc.checked_div(per_element_ceiling) {
            Some(raw) if raw < byte_limit => raw,
            _ => byte_limit,
        }
    };
    let depth_limit = if budget.max_depth < MAX_DEPTH {
        budget.max_depth
    } else {
        MAX_DEPTH
    };
    EnforcedLimits {
        byte_limit,
        collection_limit,
        depth_limit,
    }
}

/// Decodes `T` from `input` under `budget`, returning resource-use evidence.
///
/// # Guarantees
///
/// On success, the returned [`ResourceUse`] satisfies:
///
/// - `read ≤ min(max_input, max_work)` (measured exactly).
/// - `alloc_bound ≤ max_input + max_alloc` and the real allocation is at most
///   `alloc_bound` (see the module documentation for the exact ceiling).
/// - `depth_bound ≤ min(max_depth, MAX_DEPTH)` and the parser never nested
///   deeper (enforced by the decoder).
/// - `work_bound` equals `W(T)` for statically bounded types and `read`
///   otherwise.
///
/// Trailing bytes are rejected (strict decode).
pub fn decode_bounded<'de, T>(input: &'de [u8], budget: Budget) -> Result<Decoded<T>, DecodeError>
where
    T: DecodeBounded + for<'a> nextjson::NsonDeserialize<'a>,
{
    let input_len = u64::try_from(input.len()).map_err(|_| {
        DecodeError::Budget(BudgetExceeded::Input {
            limit: budget.max_input,
        })
    })?;
    if input_len > budget.max_input {
        return Err(DecodeError::Budget(BudgetExceeded::Input {
            limit: budget.max_input,
        }));
    }
    // Static types have exact compile-time bounds; reject budgets that cannot
    // accommodate them before doing any work.
    if T::MAX_DEPTH != usize::MAX && T::MAX_DEPTH > budget.max_depth {
        return Err(DecodeError::Budget(BudgetExceeded::Depth {
            limit: budget.max_depth,
        }));
    }
    if T::MAX_WORK != usize::MAX && T::MAX_WORK as u64 > budget.max_work {
        return Err(DecodeError::Budget(BudgetExceeded::Work {
            limit: budget.max_work,
        }));
    }
    // Per-element structural ceiling: the derive knows it exactly (the worst
    // `size_of::<element>()` across the type's collections), otherwise fall
    // back to the budget knob. Multiplying by the nesting depth bounds the
    // total number of collection elements (`D(T)` levels, each capped at the
    // collection limit).
    let structural = if T::MAX_STRUCTURAL_ELEMENT == usize::MAX {
        budget.element_structure_bytes()
    } else {
        T::MAX_STRUCTURAL_ELEMENT as u64
    };
    let depth_eff = if T::MAX_DEPTH == usize::MAX {
        budget.max_depth as u64
    } else {
        T::MAX_DEPTH as u64
    };
    let depth_eff = if depth_eff == 0 { 1 } else { depth_eff };
    let per_element_ceiling = structural.saturating_mul(depth_eff);
    let limits = derive_enforced_limits(budget, T::STATICALLY_BOUNDED, per_element_ceiling);
    let config = Config::standard()
        .with_limit(limits.byte_limit)
        .with_collection_limit(limits.collection_limit)
        .with_depth_limit(limits.depth_limit);
    let (value, consumed) =
        decoder::from_slice_with_consumed(input, config).map_err(DecodeError::Codec)?;
    if consumed != input.len() {
        return Err(DecodeError::Codec(crate::Error::TrailingBytes {
            remaining: input.len() - consumed,
        }));
    }
    let read = consumed as u64;
    // The reported depth bound is the type's exact derived depth, capped by
    // the actually enforced decoder ceiling (`min(budget.max_depth, MAX_DEPTH)`)
    // for paths where a very deep type is clamped by the crate-wide cap.
    let depth_bound = T::MAX_DEPTH.min(limits.depth_limit);
    let (alloc_bound, work_bound) = if T::STATICALLY_BOUNDED {
        (T::MAX_ALLOC as u64, T::MAX_WORK as u64)
    } else {
        (
            limits
                .byte_limit
                .saturating_add(limits.collection_limit.saturating_mul(per_element_ceiling)),
            read,
        )
    };
    Ok(Decoded {
        value,
        use_: ResourceUse {
            read,
            alloc_bound,
            depth_bound,
            work_bound,
        },
    })
}

macro_rules! primitive {
    ($($ty:ty => $input:expr),+ $(,)?) => {$(
        impl DecodeBounded for $ty {
            const MAX_INPUT: usize = $input;
            const MAX_ALLOC: usize = 0;
            const MAX_DEPTH: usize = 0;
            // Work is the encoded bytes plus one field-transition unit, so
            // MAX_WORK >= MAX_INPUT always holds for statically bounded types.
            const MAX_WORK: usize = $input + 1;
            const MAX_STRUCTURAL_ELEMENT: usize = 0;
        }
    )+};
}

// Encoded widths mirror `StaticSize`: tag + full-width payload under the
// variable profile, or tag + marker-varint for 64/128-bit integers.
primitive! {
    () => 1, bool => 1, char => 13,
    i8 => 9, u8 => 9,
    i16 => 9, u16 => 9,
    i32 => 9, u32 => 9,
    i64 => 10, u64 => 10,
    i128 => 18, u128 => 18,
    f32 => 5, f64 => 9
}

impl<T: DecodeBounded> DecodeBounded for Option<T> {
    const MAX_INPUT: usize = max(1, T::MAX_INPUT);
    const MAX_ALLOC: usize = T::MAX_ALLOC;
    const MAX_DEPTH: usize = T::MAX_DEPTH;
    const MAX_WORK: usize = saturating_add(1, T::MAX_WORK);
    const MAX_STRUCTURAL_ELEMENT: usize = T::MAX_STRUCTURAL_ELEMENT;
}

impl<T: DecodeBounded, const N: usize> DecodeBounded for [T; N] {
    // Array tag + elements + terminator.
    const MAX_INPUT: usize = saturating_add(saturating_mul(T::MAX_INPUT, N), 2);
    const MAX_ALLOC: usize = saturating_mul(T::MAX_ALLOC, N);
    const MAX_DEPTH: usize = depth_plus_one(T::MAX_DEPTH);
    const MAX_WORK: usize = saturating_add(saturating_mul(T::MAX_WORK, N), 2);
    const MAX_STRUCTURAL_ELEMENT: usize = T::MAX_STRUCTURAL_ELEMENT;
}

impl<T> DecodeBounded for PhantomData<T> {
    const MAX_INPUT: usize = 0;
    const MAX_ALLOC: usize = 0;
    const MAX_DEPTH: usize = 0;
    const MAX_WORK: usize = 0;
    const MAX_STRUCTURAL_ELEMENT: usize = 0;
}

/// Compile-time helper: maximum over a list of `usize` constants.
macro_rules! max_depth {
    ($a:expr) => {
        $a
    };
    ($a:expr, $($rest:expr),+) => {
        crate::bounded::max($a, max_depth!($($rest),+))
    };
}

macro_rules! tuple_bounded {
    ($($name:ident),+) => {
        impl<$($name: DecodeBounded),+> DecodeBounded for ($($name,)+) {
            const MAX_INPUT: usize = 2usize $(.saturating_add($name::MAX_INPUT))+;
            const MAX_ALLOC: usize = 0usize $(.saturating_add($name::MAX_ALLOC))+;
            const MAX_DEPTH: usize = depth_plus_one(max_depth!($($name::MAX_DEPTH),+));
            const MAX_WORK: usize = 2usize $(.saturating_add($name::MAX_WORK))+;
            const MAX_STRUCTURAL_ELEMENT: usize = max_depth!($($name::MAX_STRUCTURAL_ELEMENT),+);
        }
    };
}

tuple_bounded!(A);
tuple_bounded!(A, B);
tuple_bounded!(A, B, C);
tuple_bounded!(A, B, C, D);
tuple_bounded!(A, B, C, D, E);
tuple_bounded!(A, B, C, D, E, F);
tuple_bounded!(A, B, C, D, E, F, G);
tuple_bounded!(A, B, C, D, E, F, G, H);

#[cfg(feature = "alloc")]
impl DecodeBounded for String {
    const MAX_INPUT: usize = usize::MAX;
    const MAX_ALLOC: usize = usize::MAX;
    const MAX_DEPTH: usize = 1;
    const MAX_WORK: usize = usize::MAX;
    // The String heap is data-bound (every byte is read from the wire).
    const MAX_STRUCTURAL_ELEMENT: usize = 0;
}

#[cfg(feature = "alloc")]
impl<T: DecodeBounded> DecodeBounded for Vec<T> {
    const MAX_INPUT: usize = usize::MAX;
    const MAX_ALLOC: usize = usize::MAX;
    const MAX_DEPTH: usize = depth_plus_one(T::MAX_DEPTH);
    const MAX_WORK: usize = usize::MAX;
    // The backing buffer costs size_of::<T>() per element beyond the wire
    // data; nested collections inside T contribute their own ceilings.
    const MAX_STRUCTURAL_ELEMENT: usize = max(core::mem::size_of::<T>(), T::MAX_STRUCTURAL_ELEMENT);
}

#[cfg(feature = "alloc")]
impl<T: DecodeBounded> DecodeBounded for Box<T> {
    const MAX_INPUT: usize = T::MAX_INPUT;
    const MAX_ALLOC: usize = saturating_add(T::MAX_ALLOC, core::mem::size_of::<T>());
    const MAX_DEPTH: usize = T::MAX_DEPTH;
    const MAX_WORK: usize = T::MAX_WORK;
    // The box allocation costs at most size_of::<T>() beyond the wire data.
    const MAX_STRUCTURAL_ELEMENT: usize = max(core::mem::size_of::<T>(), T::MAX_STRUCTURAL_ELEMENT);
}

/// Borrowed UTF-8 text decodes into the input frame and allocates nothing.
impl DecodeBounded for &str {
    const MAX_INPUT: usize = usize::MAX;
    const MAX_ALLOC: usize = 0;
    const MAX_DEPTH: usize = 0;
    const MAX_WORK: usize = usize::MAX;
    const MAX_STRUCTURAL_ELEMENT: usize = 0;
}

/// Borrowed byte slices decode into the input frame and allocate nothing.
impl<T> DecodeBounded for &[T] {
    const MAX_INPUT: usize = usize::MAX;
    const MAX_ALLOC: usize = 0;
    const MAX_DEPTH: usize = 1;
    const MAX_WORK: usize = usize::MAX;
    const MAX_STRUCTURAL_ELEMENT: usize = 0;
}

/// Compile-time helper: saturating addition.
#[doc(hidden)]
pub const fn saturating_add(left: usize, right: usize) -> usize {
    left.saturating_add(right)
}

/// Compile-time helper: saturating multiplication.
#[doc(hidden)]
pub const fn saturating_mul(left: usize, right: usize) -> usize {
    left.saturating_mul(right)
}

/// Compile-time helper: maximum of two `usize` values.
#[doc(hidden)]
pub const fn max(left: usize, right: usize) -> usize {
    if left > right {
        left
    } else {
        right
    }
}

/// Compile-time helper: one container level, preserving `usize::MAX`.
#[doc(hidden)]
pub const fn depth_plus_one(depth: usize) -> usize {
    if depth == usize::MAX {
        usize::MAX
    } else {
        depth + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[derive(
        Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize, crate::DecodeBounded,
    )]
    struct StaticRecord {
        id: u64,
        enabled: bool,
        coordinates: [i32; 2],
    }

    #[derive(
        Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize, crate::DecodeBounded,
    )]
    struct DynamicRecord {
        id: u64,
        name: String,
        tags: Vec<u8>,
    }

    fn static_value() -> StaticRecord {
        StaticRecord {
            id: 7,
            enabled: true,
            coordinates: [1, -2],
        }
    }

    #[test]
    fn static_type_decode_reports_exact_bounds() {
        let value = static_value();
        let bytes = crate::options().serialize(&value).unwrap();
        let budget = Budget::from_type::<StaticRecord>();
        // The derived algebra is an exact upper bound on the wire size.
        assert_eq!(budget.max_input(), StaticRecord::MAX_INPUT as u64);
        assert!(budget.max_input() >= bytes.len() as u64);
        assert_eq!(budget.max_alloc(), 0);
        // Object level + the array field level.
        assert_eq!(budget.max_depth(), 2);
        let decoded = decode_bounded::<StaticRecord>(&bytes, budget).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.use_.read as usize, bytes.len());
        assert_eq!(decoded.use_.alloc_bound, 0);
        assert_eq!(decoded.use_.depth_bound, 2);
        assert_eq!(decoded.use_.work_bound, StaticRecord::MAX_WORK as u64);
        // The type reports itself as statically bounded.
        const {
            assert!(StaticRecord::STATICALLY_BOUNDED);
        };
        const {
            assert!(!DynamicRecord::STATICALLY_BOUNDED);
        };
    }

    #[test]
    fn static_type_input_budget_is_enforced() {
        let value = static_value();
        let bytes = crate::options().serialize(&value).unwrap();
        // A budget too small for the type is rejected before decoding.
        let budget = Budget::from_type::<StaticRecord>().with_max_input(3);
        assert!(matches!(
            decode_bounded::<StaticRecord>(&bytes, budget),
            Err(DecodeError::Budget(BudgetExceeded::Input { limit: 3 }))
        ));
        // A budget whose depth cannot accommodate the type is rejected.
        let budget = Budget::from_type::<StaticRecord>().with_max_depth(0);
        assert!(matches!(
            decode_bounded::<StaticRecord>(&bytes, budget),
            Err(DecodeError::Budget(BudgetExceeded::Depth { limit: 0 }))
        ));
    }

    #[test]
    fn dynamic_type_decode_is_budget_checked() {
        let value = DynamicRecord {
            id: 1,
            name: "hello".to_owned(),
            tags: vec![1, 2, 3],
        };
        let bytes = crate::options().serialize(&value).unwrap();
        let budget = Budget::default();
        let decoded = decode_bounded::<DynamicRecord>(&bytes, budget).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.use_.read as usize, bytes.len());
        // Dynamic ceiling: read + structural cap.
        assert!(decoded.use_.alloc_bound >= bytes.len() as u64);
        assert!(decoded.use_.work_bound >= bytes.len() as u64);
        // A tight input budget rejects the input up front.
        let tight = budget.with_max_input((bytes.len() - 2) as u64);
        assert!(matches!(
            decode_bounded::<DynamicRecord>(&bytes, tight),
            Err(DecodeError::Budget(BudgetExceeded::Input { .. }))
        ));
    }

    #[test]
    fn dynamic_collections_respect_alloc_budget() {
        let value = DynamicRecord {
            id: 1,
            name: String::new(),
            tags: vec![0u8; 100],
        };
        let bytes = crate::options().serialize(&value).unwrap();
        // max_alloc small -> collection_limit 0 -> collections are rejected.
        let budget = Budget::default().with_max_alloc(0);
        assert!(matches!(
            decode_bounded::<DynamicRecord>(&bytes, budget),
            Err(DecodeError::Codec(Error::CollectionLimit { limit: 0 }))
        ));
    }

    #[test]
    fn depth_budget_caps_nesting_for_dynamic_types() {
        // A nested Vec<Vec<u8>> has derived depth D = 2; a budget with that
        // ceiling must accept it, and one level shallower must reject it.
        let value: Vec<Vec<u8>> = vec![vec![1, 2], vec![3]];
        let bytes = crate::options().serialize(&value).unwrap();
        assert_eq!(<Vec<Vec<u8>> as DecodeBounded>::MAX_DEPTH, 2);
        let ok = Budget::default().with_max_depth(2);
        let decoded = decode_bounded::<Vec<Vec<u8>>>(&bytes, ok).unwrap();
        assert_eq!(decoded.use_.depth_bound, 2);
        let too_shallow = Budget::default().with_max_depth(1);
        assert!(matches!(
            decode_bounded::<Vec<Vec<u8>>>(&bytes, too_shallow),
            Err(DecodeError::Budget(BudgetExceeded::Depth { limit: 1 }))
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let value = 42u8;
        let mut bytes = crate::options().serialize(&value).unwrap();
        bytes.push(0);
        assert!(matches!(
            decode_bounded::<u8>(&bytes, Budget::default()),
            Err(DecodeError::Codec(Error::TrailingBytes { remaining: 1 }))
        ));
    }

    #[test]
    fn budget_from_config_matches_config_limits() {
        let config = crate::options()
            .with_limit(4096)
            .with_collection_limit(128)
            .with_depth_limit(8);
        let budget = Budget::from_config(config);
        assert_eq!(budget.max_input(), 4096);
        assert_eq!(budget.max_alloc(), 128 * ELEMENT_STRUCTURE_BYTES);
        assert_eq!(budget.max_depth(), 8);
        assert_eq!(budget.max_work(), 4096);
    }

    #[test]
    fn algebra_matches_wire_shapes() {
        // A unit value is a single null tag.
        assert_eq!(<() as DecodeBounded>::MAX_INPUT, 1);
        assert_eq!(<() as DecodeBounded>::MAX_DEPTH, 0);
        // Option<u8> is the null tag or the tagged value.
        assert_eq!(<Option<u8> as DecodeBounded>::MAX_INPUT, 9);
        assert_eq!(<Option<u8> as DecodeBounded>::MAX_DEPTH, 0);
        // [u16; 4] is tag + 4 values + terminator.
        assert_eq!(<[u16; 4] as DecodeBounded>::MAX_INPUT, 2 + 4 * 9);
        assert_eq!(<[u16; 4] as DecodeBounded>::MAX_DEPTH, 1);
        // Tuples are arrays with a depth level.
        assert_eq!(<(u8, bool) as DecodeBounded>::MAX_INPUT, 2 + 9 + 1);
        assert_eq!(<(u8, bool) as DecodeBounded>::MAX_DEPTH, 1);
        // Dynamic collections add exactly one depth level and report MAX.
        assert_eq!(<Vec<u8> as DecodeBounded>::MAX_DEPTH, 1);
        assert_eq!(<Vec<Vec<u8>> as DecodeBounded>::MAX_DEPTH, 2);
        assert_eq!(<String as DecodeBounded>::MAX_INPUT, usize::MAX);
        assert_eq!(<String as DecodeBounded>::MAX_ALLOC, usize::MAX);
        // Borrowed strings allocate nothing but are content-dependent.
        assert_eq!(<&str as DecodeBounded>::MAX_ALLOC, 0);
        assert_eq!(<&str as DecodeBounded>::MAX_INPUT, usize::MAX);
        // Box adds the type's heap footprint and no container level.
        assert_eq!(
            <Box<u64> as DecodeBounded>::MAX_ALLOC,
            core::mem::size_of::<u64>()
        );
        assert_eq!(<Box<u64> as DecodeBounded>::MAX_DEPTH, 0);
        assert_eq!(<Option<Box<u64>> as DecodeBounded>::MAX_DEPTH, 0);
    }

    #[test]
    fn structural_element_bounds_match_collection_shapes() {
        // String's heap is data-bound: zero structural allocation.
        assert_eq!(<String as DecodeBounded>::MAX_STRUCTURAL_ELEMENT, 0);
        // Vec<u8> backing buffer is 1 byte per element.
        assert_eq!(
            <Vec<u8> as DecodeBounded>::MAX_STRUCTURAL_ELEMENT,
            core::mem::size_of::<u8>()
        );
        // Vec<String> backing buffer is the String header (24 bytes) per
        // element; its heap data is bounded by the read budget.
        assert_eq!(
            <Vec<String> as DecodeBounded>::MAX_STRUCTURAL_ELEMENT,
            core::mem::size_of::<String>()
        );
        // A plain struct field contributes its own collections' ceilings:
        // DynamicRecord { id: u64, name: String, tags: Vec<u8> } -> Vec<u8>.
        assert_eq!(
            <DynamicRecord as DecodeBounded>::MAX_STRUCTURAL_ELEMENT,
            core::mem::size_of::<u8>()
        );
        // Box<T> reports the boxed type's size as structural ceiling.
        assert_eq!(
            <Box<u64> as DecodeBounded>::MAX_STRUCTURAL_ELEMENT,
            core::mem::size_of::<u64>()
        );
        // Static types report zero structural allocation.
        assert_eq!(<StaticRecord as DecodeBounded>::MAX_STRUCTURAL_ELEMENT, 0);
    }

    #[test]
    fn string_collection_allocation_is_covered_by_the_bound() {
        // The documented ceiling must hold for Vec<String>: the per-element
        // structural allocation (the String header in the backing buffer) is
        // 24 bytes, which the type-derived bound accounts for exactly.
        let value: Vec<String> = (0..200).map(|i| format!("s{i}")).collect();
        let bytes = crate::options().serialize(&value).unwrap();
        let budget = Budget::default();
        let decoded = decode_bounded::<Vec<String>>(&bytes, budget).unwrap();
        assert_eq!(decoded.use_.read as usize, bytes.len());
        // 200 String headers (24 each) + the string data (~600 bytes) is the
        // true allocation; the reported bound must cover it.
        let true_alloc = 200 * core::mem::size_of::<String>() + 600;
        assert!(
            decoded.use_.alloc_bound as usize >= true_alloc,
            "alloc_bound {} must cover the real allocation {}",
            decoded.use_.alloc_bound,
            true_alloc
        );
        // The budget knob is used only when the type does not declare its own
        // structural bound; the declared bound is tighter for String.
        assert!(
            budget.element_structure_bytes()
                >= <Vec<String> as DecodeBounded>::MAX_STRUCTURAL_ELEMENT as u64
        );
    }

    // -----------------------------------------------------------------------
    // Additional algebra coverage: every primitive, composite shape, enum
    // variant kind, and derived struct, plus budget-dimension boundaries.
    // -----------------------------------------------------------------------

    fn assert_primitive<T: DecodeBounded>(b: usize) {
        assert_eq!(T::MAX_INPUT, b, "B");
        assert_eq!(T::MAX_DEPTH, 0, "D");
        assert_eq!(T::MAX_ALLOC, 0, "A");
        assert_eq!(T::MAX_STRUCTURAL_ELEMENT, 0, "S");
        // Work is the encoded bytes plus one field-transition unit.
        assert_eq!(T::MAX_WORK, b + 1, "W");
        assert!(T::STATICALLY_BOUNDED);
    }

    #[test]
    fn primitive_algebra_is_exact() {
        assert_primitive::<()>(1);
        assert_primitive::<bool>(1);
        assert_primitive::<char>(13);
        assert_primitive::<i8>(9);
        assert_primitive::<u8>(9);
        assert_primitive::<i16>(9);
        assert_primitive::<u16>(9);
        assert_primitive::<i32>(9);
        assert_primitive::<u32>(9);
        assert_primitive::<i64>(10);
        assert_primitive::<u64>(10);
        assert_primitive::<i128>(18);
        assert_primitive::<u128>(18);
        assert_primitive::<f32>(5);
        assert_primitive::<f64>(9);
    }

    #[test]
    fn option_array_tuple_algebra_is_exact() {
        // Option adds the null-tag branch (max with 1) and no depth level.
        assert_eq!(<Option<u8> as DecodeBounded>::MAX_INPUT, 9);
        assert_eq!(<Option<u8> as DecodeBounded>::MAX_DEPTH, 0);
        assert_eq!(<Option<Vec<u8>> as DecodeBounded>::MAX_DEPTH, 1);
        assert_eq!(
            <Option<Vec<u8>> as DecodeBounded>::MAX_STRUCTURAL_ELEMENT,
            1
        );
        assert_eq!(<Option<String> as DecodeBounded>::MAX_ALLOC, usize::MAX);
        assert_eq!(<Option<String> as DecodeBounded>::MAX_STRUCTURAL_ELEMENT, 0);
        // Arrays: tag + N elements + terminator, exactly one container level.
        assert_eq!(<[u8; 0] as DecodeBounded>::MAX_INPUT, 2);
        assert_eq!(<[u8; 0] as DecodeBounded>::MAX_DEPTH, 1);
        assert_eq!(<[u8; 3] as DecodeBounded>::MAX_INPUT, 2 + 3 * 9);
        assert_eq!(<[u8; 3] as DecodeBounded>::MAX_WORK, 2 + 3 * 10);
        assert_eq!(<[[u8; 2]; 3] as DecodeBounded>::MAX_DEPTH, 2);
        // Tuples use array semantics with per-field sums.
        assert_eq!(<(u8, bool) as DecodeBounded>::MAX_INPUT, 2 + 9 + 1);
        assert_eq!(<(u8, bool) as DecodeBounded>::MAX_DEPTH, 1);
        assert_eq!(
            <(u8, u16, u32, u64, u128, i8, i16, i32) as DecodeBounded>::MAX_INPUT,
            2 + 9 + 9 + 9 + 10 + 18 + 9 + 9 + 9
        );
        // PhantomData costs nothing on any dimension.
        assert_eq!(<PhantomData<u64> as DecodeBounded>::MAX_INPUT, 0);
        assert_eq!(<PhantomData<u64> as DecodeBounded>::MAX_DEPTH, 0);
        assert_eq!(<PhantomData<u64> as DecodeBounded>::MAX_ALLOC, 0);
        assert_eq!(<PhantomData<u64> as DecodeBounded>::MAX_WORK, 0);
    }

    #[derive(
        Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize, crate::DecodeBounded,
    )]
    struct NestedRecord {
        header: StaticRecord,
        items: [u8; 3],
        maybe: Option<i64>,
    }

    #[derive(
        Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize, crate::DecodeBounded,
    )]
    enum StaticEnum {
        A,
        B(u8),
        C { x: i32, y: i32 },
    }

    #[derive(
        Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize, crate::DecodeBounded,
    )]
    enum ShapeEnum {
        Unit,
        Newtype(u64),
        Tuple(u8, bool),
        Named { code: u16, label: String },
    }

    #[test]
    fn derive_algebra_nested_struct_matches_hand_computation() {
        // header: B=80 W=84 D=2; items [u8;3]: B=29 W=32 D=1; maybe: B=10
        // W=12 D=0. Keys add 9 + name length. The object wrapper adds 2.
        assert_eq!(
            NestedRecord::MAX_INPUT,
            2 + (80 + 15) + (29 + 14) + (10 + 14)
        );
        assert_eq!(
            NestedRecord::MAX_WORK,
            2 + (84 + 15) + (32 + 14) + (12 + 14)
        );
        assert_eq!(NestedRecord::MAX_DEPTH, 3);
        assert_eq!(NestedRecord::MAX_ALLOC, 0);
        assert_eq!(NestedRecord::MAX_STRUCTURAL_ELEMENT, 0);
        const {
            assert!(NestedRecord::STATICALLY_BOUNDED);
        };
    }

    #[test]
    fn derive_algebra_enums_match_hand_computation() {
        // StaticEnum: variants A(unit), B(u8), C{x,y}. B = 1 + max(10+1,
        // 10+9, 10+(2+19+19)) + 1 = 52; W = 1 + max(10+1, 10+10, 10+42) + 1
        // = 54; D = 1 + max(0,0,1) = 2.
        assert_eq!(StaticEnum::MAX_INPUT, 52);
        assert_eq!(StaticEnum::MAX_WORK, 54);
        assert_eq!(StaticEnum::MAX_DEPTH, 2);
        assert_eq!(StaticEnum::MAX_ALLOC, 0);
        assert_eq!(StaticEnum::MAX_STRUCTURAL_ELEMENT, 0);
        const {
            assert!(StaticEnum::STATICALLY_BOUNDED);
        };
        // ShapeEnum: the Named variant carries a String, so B/A/W are dynamic
        // (usize::MAX). Depth stays finite: the Named variant adds the String
        // level (D=1) inside its own object level, and the enum adds another
        // -> 3. Structural stays zero (String is data-bound).
        assert_eq!(ShapeEnum::MAX_INPUT, usize::MAX);
        assert_eq!(ShapeEnum::MAX_ALLOC, usize::MAX);
        assert_eq!(ShapeEnum::MAX_WORK, usize::MAX);
        assert_eq!(ShapeEnum::MAX_DEPTH, 3);
        assert_eq!(ShapeEnum::MAX_STRUCTURAL_ELEMENT, 0);
        const {
            assert!(!ShapeEnum::STATICALLY_BOUNDED);
        };
    }

    #[test]
    fn decode_bounded_respects_derived_static_algebra() {
        let value = NestedRecord {
            header: static_value(),
            items: [1, 2, 3],
            maybe: Some(-5),
        };
        let bytes = crate::options().serialize(&value).unwrap();
        let budget = Budget::from_type::<NestedRecord>();
        assert_eq!(budget.max_input(), NestedRecord::MAX_INPUT as u64);
        assert_eq!(budget.max_alloc(), 0);
        assert_eq!(budget.max_depth(), 3);
        let decoded = decode_bounded::<NestedRecord>(&bytes, budget).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.use_.read as usize, bytes.len());
        assert!(decoded.use_.read <= NestedRecord::MAX_INPUT as u64);
        assert_eq!(decoded.use_.alloc_bound, 0);
        assert_eq!(decoded.use_.depth_bound, 3);
        assert!(decoded.use_.work_bound <= NestedRecord::MAX_WORK as u64);
    }

    #[test]
    fn decode_bounded_respects_derived_enum_algebra() {
        for value in [
            StaticEnum::A,
            StaticEnum::B(7),
            StaticEnum::C { x: -1, y: 2 },
        ] {
            let bytes = crate::options().serialize(&value).unwrap();
            let decoded =
                decode_bounded::<StaticEnum>(&bytes, Budget::from_type::<StaticEnum>()).unwrap();
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.use_.alloc_bound, 0);
            assert_eq!(decoded.use_.depth_bound, 2);
            assert!(decoded.use_.read <= StaticEnum::MAX_INPUT as u64);
        }
        // The dynamic enum decodes under a default budget.
        for value in [
            ShapeEnum::Unit,
            ShapeEnum::Newtype(u64::MAX),
            ShapeEnum::Tuple(0, true),
            ShapeEnum::Named {
                code: 9,
                label: "x".into(),
            },
        ] {
            let bytes = crate::options().serialize(&value).unwrap();
            let decoded = decode_bounded::<ShapeEnum>(&bytes, Budget::default()).unwrap();
            assert_eq!(decoded.value, value);
            assert_eq!(decoded.use_.depth_bound, 3);
        }
    }

    #[test]
    fn input_budget_boundary_is_exact() {
        let value: Vec<u8> = vec![1, 2, 3];
        let bytes = crate::options().serialize(&value).unwrap();
        // A budget of exactly the frame size decodes; one byte less rejects
        // before any allocation.
        let exact = Budget::default().with_max_input(bytes.len() as u64);
        assert!(decode_bounded::<Vec<u8>>(&bytes, exact).is_ok());
        let tight = Budget::default().with_max_input(bytes.len() as u64 - 1);
        assert!(matches!(
            decode_bounded::<Vec<u8>>(&bytes, tight),
            Err(DecodeError::Budget(BudgetExceeded::Input { .. }))
        ));
    }

    #[test]
    fn work_budget_boundary_is_exact() {
        // Static types reject a work budget below W(T) up front.
        let value = static_value();
        let bytes = crate::options().serialize(&value).unwrap();
        let exact =
            Budget::from_type::<StaticRecord>().with_max_work(StaticRecord::MAX_WORK as u64);
        assert!(decode_bounded::<StaticRecord>(&bytes, exact).is_ok());
        let tight =
            Budget::from_type::<StaticRecord>().with_max_work(StaticRecord::MAX_WORK as u64 - 1);
        assert!(matches!(
            decode_bounded::<StaticRecord>(&bytes, tight),
            Err(DecodeError::Budget(BudgetExceeded::Work { .. }))
        ));
        // Dynamic types enforce work through the byte limit (read <= work):
        // a budget of exactly the frame size decodes, one byte short cannot
        // read the whole frame and must fail (which error variant depends on
        // where the limit binds).
        let dyn_value: Vec<u64> = (0..16).collect();
        let dyn_bytes = crate::options().serialize(&dyn_value).unwrap();
        let len = dyn_bytes.len() as u64;
        let exact = Budget::default().with_max_work(len);
        let decoded = decode_bounded::<Vec<u64>>(&dyn_bytes, exact).unwrap();
        assert_eq!(decoded.use_.read, len);
        assert!(decoded.use_.work_bound >= len);
        let tight = Budget::default().with_max_work(len - 1);
        let result = decode_bounded::<Vec<u64>>(&dyn_bytes, tight);
        assert!(
            result.is_err(),
            "a work budget below the frame size ({len}) must fail; got {:?}",
            result.map(|d| d.use_)
        );
    }

    #[test]
    fn alloc_budget_boundary_is_exact() {
        // A Vec<u8> of 100 elements needs a collection limit >= 100. The
        // per-element structural ceiling for Vec<u8> is size_of::<u8>() = 1
        // and the depth is 1, so collection_limit = max_alloc / 1.
        let value: Vec<u8> = vec![0u8; 100];
        let bytes = crate::options().serialize(&value).unwrap();
        let tight = Budget::default()
            .with_max_alloc(99)
            .with_max_input(bytes.len() as u64);
        assert!(matches!(
            decode_bounded::<Vec<u8>>(&bytes, tight),
            Err(DecodeError::Codec(Error::CollectionLimit { limit: 99 }))
        ));
        let exact = Budget::default()
            .with_max_alloc(100)
            .with_max_input(bytes.len() as u64);
        assert!(decode_bounded::<Vec<u8>>(&bytes, exact).is_ok());
    }

    #[test]
    fn element_structure_knob_falls_back_when_structural_unknown() {
        // A manual DecodeBounded implementation leaves MAX_STRUCTURAL_ELEMENT
        // at its usize::MAX default; decode_bounded then uses the budget knob
        // as the per-element structural ceiling.
        let budget = Budget::default()
            .with_max_alloc(256)
            .with_element_structure_bytes(1);
        let limits = derive_enforced_limits(budget, false, budget.element_structure_bytes());
        assert_eq!(limits.collection_limit, 256);
        let budget = budget.with_element_structure_bytes(64);
        let limits = derive_enforced_limits(budget, false, budget.element_structure_bytes());
        assert_eq!(limits.collection_limit, 4);
        // A zero knob means no structural allocation: no per-element cap.
        let budget = budget.with_element_structure_bytes(0);
        let limits = derive_enforced_limits(budget, false, budget.element_structure_bytes());
        assert_eq!(limits.collection_limit, limits.byte_limit);
    }

    #[test]
    fn nested_collection_alloc_bounds_are_sound() {
        // Vec<Vec<u8>>: structural = max(size_of::<Vec<u8>>(), 1) = 24,
        // depth 2 -> per-element ceiling 48. The reported alloc_bound must
        // cover the real allocation (outer buffer 24*2 + inner data).
        let value: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4, 5]];
        let bytes = crate::options().serialize(&value).unwrap();
        let decoded = decode_bounded::<Vec<Vec<u8>>>(&bytes, Budget::default()).unwrap();
        let true_alloc = 2 * core::mem::size_of::<Vec<u8>>() + 5;
        assert!(decoded.use_.alloc_bound as usize >= true_alloc);
        assert_eq!(decoded.use_.depth_bound, 2);

        // Vec<Box<u64>>: structural = max(size_of::<Box<u64>>(), size_of::<u64>()) = 8.
        let boxed: Vec<Box<u64>> = vec![Box::new(1), Box::new(2)];
        let bytes = crate::options().serialize(&boxed).unwrap();
        let decoded = decode_bounded::<Vec<Box<u64>>>(&bytes, Budget::default()).unwrap();
        let true_alloc = 2 * core::mem::size_of::<Box<u64>>() + 2 * core::mem::size_of::<u64>();
        assert!(decoded.use_.alloc_bound as usize >= true_alloc);
    }

    #[test]
    fn decode_bounded_matches_plain_deserialize() {
        let values: Vec<DynamicRecord> = (0..20)
            .map(|i| DynamicRecord {
                id: i,
                name: format!("name{i}"),
                tags: (0..i % 5).map(|j| j as u8).collect(),
            })
            .collect();
        let bytes = crate::options().serialize(&values).unwrap();
        let budget = Budget::default()
            .with_max_input(bytes.len() as u64)
            .with_max_alloc(1 << 20);
        let decoded = decode_bounded::<Vec<DynamicRecord>>(&bytes, budget).unwrap();
        assert_eq!(decoded.value, values);
        assert_eq!(decoded.use_.read as usize, bytes.len());
        // The plain codec agrees on the same bytes.
        let plain: Vec<DynamicRecord> = crate::options().deserialize(&bytes).unwrap();
        assert_eq!(plain, values);
    }

    #[test]
    fn budget_builder_setters_and_accessors_roundtrip() {
        let budget = Budget::new(1, 2, 3, 4)
            .with_max_input(10)
            .with_max_alloc(20)
            .with_max_depth(30)
            .with_max_work(40)
            .with_element_structure_bytes(7);
        assert_eq!(budget.max_input(), 10);
        assert_eq!(budget.max_alloc(), 20);
        assert_eq!(budget.max_depth(), 30);
        assert_eq!(budget.max_work(), 40);
        assert_eq!(budget.element_structure_bytes(), 7);
        // Defaults.
        let default = Budget::default();
        assert_eq!(default.max_input(), DEFAULT_SIZE_LIMIT);
        assert_eq!(default.max_work(), DEFAULT_SIZE_LIMIT);
        assert_eq!(default.max_depth(), MAX_DEPTH);
        assert_eq!(default.element_structure_bytes(), ELEMENT_STRUCTURE_BYTES);
        assert_eq!(
            default.max_alloc(),
            DEFAULT_COLLECTION_LIMIT * ELEMENT_STRUCTURE_BYTES
        );
    }

    #[test]
    fn deeply_nested_depth_algebra_is_exact() {
        // Depth is always finite and grows by one container per Vec level.
        assert_eq!(<Vec<u8> as DecodeBounded>::MAX_DEPTH, 1);
        assert_eq!(<Vec<Vec<u8>> as DecodeBounded>::MAX_DEPTH, 2);
        assert_eq!(<Vec<Vec<Vec<u8>>> as DecodeBounded>::MAX_DEPTH, 3);
        assert_eq!(
            <Vec<Vec<Vec<Vec<Vec<Vec<u8>>>>>> as DecodeBounded>::MAX_DEPTH,
            6
        );
        // Depth in a struct is the max over fields plus the object level.
        assert_eq!(NestedRecord::MAX_DEPTH, 3);
        assert_eq!(<Option<StaticRecord> as DecodeBounded>::MAX_DEPTH, 2);
    }

    #[test]
    fn static_boundedness_flags_are_correct() {
        const {
            assert!(StaticRecord::STATICALLY_BOUNDED);
        };
        const {
            assert!(NestedRecord::STATICALLY_BOUNDED);
        };
        const {
            assert!(StaticEnum::STATICALLY_BOUNDED);
        };
        const {
            assert!(!DynamicRecord::STATICALLY_BOUNDED);
        };
        const {
            assert!(!ShapeEnum::STATICALLY_BOUNDED);
        };
        const {
            assert!(!<Vec<u8>>::STATICALLY_BOUNDED);
        };
        const {
            assert!(<Option<u8>>::STATICALLY_BOUNDED);
        };
        const {
            assert!(<[u8; 4]>::STATICALLY_BOUNDED);
        };
    }
}
