# rustbinary-derive

`rustbinary-derive` is the procedural-macro package for
[`rustbinary`](https://crates.io/crates/rustbinary). It generates checked,
allocation-free schema metadata and bit-level codecs from ordinary Rust
structs and enums.

[中文文档](README.zh-CN.md)

This crate is intentionally small at runtime: it contains procedural macros,
not a second serialization engine. The generated implementation calls traits
owned by `rustbinary`, so wire behavior, resource limits, error types, and
configuration remain in one runtime crate.

The macro crate itself runs on the host with `std`, as procedural macros do.
Its generated code is `no_std`: it uses core syntax and RustBinary runtime
traits without emitting `std`, `Vec`, or `String` references. Runtime features
and the `derive` feature are additive and independent.

## What It Provides

| Derive | Generated contract | Typical use |
| --- | --- | --- |
| `Fingerprint` | `rustbinary::Fingerprint` | Detect type and codec-profile drift |
| `StaticSize` | `rustbinary::StaticSize` | Compile-time worst-case bounds |
| `Reflect` | `rustbinary::Reflect` | Inspect static field and variant metadata |
| `BitPacked` | `rustbinary::BitPack` | Pack bounded fields at bit granularity |
| `CompactBinary` | `rustbinary::compact::{CompactEncode, CompactDecode}` | Schema-guided compact wire profile (no tags, no field names) |

The macros do not implement `nextjson::NsonSerialize` or
`nextjson::NsonDeserialize`. Combine them with nextjson derives when the
ordinary binary, CBOR, compression, encryption, or schema-evolution APIs are
needed.

## Installation

Most applications should depend on the runtime crate and use its re-exported
macros:

```toml
[dependencies]
nextjson = { version = "0.1", features = ["derive"] }
rustbinary = { version = "0.1.4", features = [
    "derive",
    "fingerprint",
    "reflection",
    "static-size",
    "bit-packing",
] }
```

The feature names are independent. `derive` enables macro re-exports, while
`fingerprint`, `reflection`, `static-size`, `bit-packing`, and `compact`
enable their runtime contracts. Application code normally writes
`rustbinary::Fingerprint`, `rustbinary::StaticSize`, `rustbinary::Reflect`,
`rustbinary::BitPacked`, and `rustbinary::CompactBinary`.

Direct use of this package is also supported for macro ownership or build
tooling, but the runtime crate must still be present because generated paths
refer to `::rustbinary`:

```toml
[dependencies]
rustbinary = { version = "0.1.4", features = [
    "fingerprint",
    "reflection",
    "static-size",
    "bit-packing",
] }
rustbinary-derive = "0.1.4"
```

The `path` plus `version` dependency in the workspace is intentional. Local
workspace builds use the path; a published package resolves the same version
from crates.io. Publish `rustbinary-derive` before `rustbinary`.

## Complete Example

The following type uses every derive provided by this package. It is a normal
nextjson value, has a compatibility fingerprint, exposes static metadata, and
has a separate bit-packed representation for bounded flags.

```rust
use nextjson::{NsonDeserialize, NsonSerialize};
use rustbinary::{Fingerprint, Reflect, StaticSize, TypeShape};

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize, Fingerprint, Reflect, StaticSize)]
struct Header {
    enabled: bool,
    partition: u16,
    coordinates: [i32; 2],
}

#[derive(Debug, PartialEq, rustbinary::BitPacked, StaticSize)]
struct Flags {
    enabled: bool,
    #[bits = 3]
    priority: u8,
    #[bits = 12]
    sequence: u16,
}

fn main() -> rustbinary::Result<()> {
    let value = Header {
        enabled: true,
        partition: 17,
        coordinates: [-4, 9],
    };
    let config = rustbinary::options().with_limit(4096);

    let frame = config.serialize(&value)?;
    let decoded: Header = config.deserialize(&frame)?;
    assert_eq!(decoded, value);
    assert!(frame.len() <= Header::MAX_SIZE);

    if let TypeShape::Struct(fields) = Header::SHAPE {
        assert_eq!(fields[1].name, "partition");
        assert_eq!(fields[1].type_name, "u16");
    }

    let flags = Flags {
        enabled: true,
        priority: 5,
        sequence: 2047,
    };
    let packed = rustbinary::options().with_bit_packing().serialize(&flags)?;
    assert_eq!(packed.len(), 2);
    assert_eq!(
        rustbinary::options()
            .with_bit_packing()
            .deserialize::<Flags>(&packed)?,
        flags
    );
    Ok(())
}
```

## `Fingerprint`

`Fingerprint` generates an implementation of:

```rust
pub trait Fingerprint {
    const TYPE_FINGERPRINT: u64;
    fn fingerprint(config: rustbinary::Config) -> u64;
}
```

The generated type fingerprint is a compile-time FNV-1a compatibility
identifier. It incorporates:

- the module path and declared type name;
- struct, tuple, or enum shape;
- field names or tuple indexes;
- the `Fingerprint::TYPE_FINGERPRINT` of every field type;
- declaration order;
- enum variant names, indexes, and payload fields.

The configuration fingerprint additionally includes effective endianness,
integer encoding, trailing-byte policy, resource limits, and the active format
wrapper. `Endian::Native` therefore produces different identities on little-
and big-endian targets.

Use it to reject accidental schema or configuration drift:

```rust
let config = rustbinary::options().with_fingerprint();
let frame = config.serialize(&value)?;
let value: Header = config.deserialize(&frame)?;
```

Changing a field name, type, order, enum variant, module path, or relevant
configuration intentionally changes the identity. This is useful for cache
keys and compatibility gates, but it is not cryptographic authentication.
Do not use it as a signature, password hash, authorization decision, or
tamper-detection mechanism. Use the encryption or signature layer for those
properties.

### Generic fingerprints

Every type parameter receives a `rustbinary::Fingerprint` bound. The bound is
required because the generated constant incorporates the parameter's type
identity:

```rust
use nextjson::{NsonDeserialize, NsonSerialize};

#[derive(NsonSerialize, NsonDeserialize, Fingerprint)]
struct Envelope<T> {
    sequence: u64,
    payload: T,
}

let a = <Envelope<u32> as Fingerprint>::TYPE_FINGERPRINT;
let b = <Envelope<u64> as Fingerprint>::TYPE_FINGERPRINT;
assert_ne!(a, b);
```

If a generic parameter is intentionally opaque, use a concrete wrapper that
implements `Fingerprint` explicitly rather than weakening the generated
contract.

## `StaticSize`

`StaticSize` generates three compile-time constants:

```rust
pub trait StaticSize {
    const MAX_SIZE: usize;
    const PACKED_MAX_BITS: usize;
    const PACKED_MAX_SIZE: usize;
}
```

`MAX_SIZE` is a conservative upper bound for the ordinary binary profile.
`PACKED_MAX_BITS` is the maximum meaningful bit count for a `BitPack` layout,
and `PACKED_MAX_SIZE` is its byte ceiling. The generated arithmetic saturates
instead of wrapping on overflow.

The derive works for structs, tuple structs, unit structs, and enums. Every
field type must implement `StaticSize`; dynamic containers such as `String`
and `Vec<T>` intentionally do not implement it because they have no finite
type-only upper bound. Use an application limit for those values instead:

```rust
#[derive(nextjson::NsonSerialize, nextjson::NsonDeserialize)]
struct DynamicMessage {
    body: String,
}

let config = rustbinary::options()
    .with_limit(64 * 1024)
    .with_collection_limit(4096);
```

An enum bound includes the largest variant and its normal representation tag.
The bound is not a promise that every value occupies that many bytes.

## `Reflect`

`Reflect` emits immutable constants with no global registry and no runtime
allocation:

```rust
pub trait Reflect {
    const TYPE_NAME: &'static str;
    const SHAPE: rustbinary::TypeShape;
}
```

`TypeShape::Struct` contains `FieldInfo` values. `TypeShape::Enum` contains
`VariantInfo` values, each with its fields. A field descriptor includes its
declared name (or tuple index), token-form type name, declaration index, and a
`symbols` alphabet size consumed by the entropy coder.

The `symbols` value is derived deterministically: an explicit
`#[entropy(symbols = N)]` (1..=32768) wins, then a `#[bits = N]` range when
`N <= 15`, then a known primitive alphabet (`bool` to 2, `u8`/`i8` to 256);
anything else reports `0`, meaning the field is coded byte-by-byte. The
`Reflect` derive accepts both the `entropy` and `bits` field attributes.

```rust
#[derive(Reflect)]
struct Telemetry {
    #[entropy(symbols = 10)]
    priority: u8,
    level: bool,
    payload: u8,   // symbols = 256
}
```

```rust
match Header::SHAPE {
    TypeShape::Struct(fields) => {
        for field in fields {
            println!("{}: {}", field.name, field.type_name);
        }
    }
    TypeShape::Enum(variants) => {
        for variant in variants {
            println!("variant {} = {}", variant.index, variant.name);
        }
    }
}
```

This is structural metadata, not Rust ABI reflection. It does not expose
memory offsets, padding, private runtime state, nextjson rename rules, or a
dynamic type registry. Type aliases and generic parameters are represented by
their declared token spelling.

## `BitPacked`

`BitPacked` generates `rustbinary::BitPack` for structs, tuple structs, unit
structs, and enums. Bits are written least-significant-bit first into a caller-
owned byte slice.

There are two field modes:

1. A field with `#[bits = N]` uses `BitValue`. The value is range-checked for
   the declared width on encode and decode.
2. A field without the attribute recursively uses `BitPack` and its
   `MAX_BITS` constant.

Supported built-in `BitValue` types are `bool`, all signed integers, and all
unsigned integers. `bool` requires exactly one bit. Signed values use
two's-complement sign extension for the declared width. A width of zero or a
width greater than 128 is rejected during macro expansion.

```rust
#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct ControlWord {
    ready: bool,
    #[bits = 2]
    mode: u8,
    #[bits = 10]
    retry_count: u16,
}

let value = ControlWord {
    ready: true,
    mode: 2,
    retry_count: 17,
};
let config = rustbinary::options().with_bit_packing();
let bytes = config.serialize(&value)?;
let decoded: ControlWord = config.deserialize(&bytes)?;
assert_eq!(decoded, value);
```

The encoder clears the caller-owned output before writing. The decoder rejects
non-zero padding bits and, when configured, trailing bytes. Unknown enum tags
are rejected. Enum tags use the minimum number of bits required for the number
of declared variants; adding or reordering variants is therefore a wire
format change.

Nested packed values compose naturally:

```rust
#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct Inner {
    #[bits = 4]
    value: u8,
}

#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct Outer {
    inner: Inner,
    #[bits = 1]
    enabled: bool,
}
```

Custom field types can implement `BitPack` or `BitValue` in the runtime crate.
The derive only selects the appropriate trait path; it does not guess a
custom type's representation.

## Accepted Rust Shapes

All four derives support structs and enums unless stated otherwise. Unions are
rejected with a span-aware compile error because their active field cannot be
represented safely from type syntax alone.

| Shape | `Fingerprint` | `StaticSize` | `Reflect` | `BitPacked` |
| --- | --- | --- | --- | --- |
| Named struct | yes | yes | yes | yes |
| Tuple struct | yes | yes | yes | yes |
| Unit struct | yes | yes | yes | yes |
| Enum | yes | yes | yes | yes |
| Union | rejected | rejected | rejected | rejected |

Generic parameters must satisfy the trait required by the selected derive.
Where clauses are preserved. nextjson attributes (`#[njson(...)]`) remain
nextjson's concern and are not interpreted by these macros.

## Diagnostics and Failure Cases

The macros fail at compile time with a `syn` diagnostic for:

- unions;
- empty enums passed to `BitPacked`;
- malformed `#[bits]` syntax;
- widths outside `1..=128`;
- a field whose selected trait bound is missing.

Runtime errors still apply to values and buffers. A valid `#[bits = 3] u8`
field containing `8` is a runtime `BitPacking` error, not a silent truncation.
An undersized caller buffer returns `BufferTooSmall`; malformed input,
non-zero padding, unknown tags, and rejected trailing bytes return typed
`rustbinary::Error` values.

## Production Patterns

### Separate compatibility and storage layouts

Use `Fingerprint` on the nextjson model that crosses a compatibility boundary
and `BitPacked` on a compact flags type used inside a frame. Do not assume
that a bit-packed layout is compatible with the ordinary nextjson layout.

### Bound untrusted input

`StaticSize` is a compile-time bound for finite types, not a replacement for
runtime limits. At network or storage boundaries, always configure both byte
and collection limits before deserializing.

### Keep fingerprints out of cryptographic policy

Fingerprints detect accidental schema drift. Encryption authenticates a frame;
signatures authenticate an application-level statement. Keep those decisions
separate so a compatibility identifier is never treated as proof of origin.

### Use reflection for tooling, not decoding

`Reflect::SHAPE` is suitable for diagnostics, schema dashboards, generated
documentation, and protocol inspection. It does not dynamically decode an
unknown Rust type; decoding still requires a statically selected type.

## Testing and Documentation

From the repository root:

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
cargo package -p rustbinary-derive --allow-dirty --no-verify --list
```

The package is designed for docs.rs. Its generated paths intentionally use
`::rustbinary`; consumers should enable the corresponding runtime features.
The root repository contains executable examples in `examples/metadata.rs`
and `examples/complete.rs` that exercise the macros against the real runtime.

## Versioning and Compatibility

Changing a field name, type, order, enum variant order, module path, or packed
width changes the generated contract. Treat those changes as schema changes,
record the package version and feature set, and retain golden vectors for
long-lived data. The macros do not provide automatic schema migration; use
the runtime `schema-evolution` feature for stable field IDs and migrations.

## License

Licensed under the [Apache License, Version 2.0](../LICENSE). The complete
license text is at the repository root. Redistributions must preserve the
license and attribution notices. 
