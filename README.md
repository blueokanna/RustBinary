# RustBinary

RustBinary is a bounded binary codec built on [nextjson](https://crates.io/crates/nextjson).
It implements nextjson's `NsonSerialize` / `NsonDeserialize` and `FormatEncoder` /
`FormatDecoder` contracts, so your types are described with the normal nextjson
derives. The binary wire format is type-tagged and self-describing: every value
starts with a one-byte type tag and containers are terminated with `0xff`, so
`Option`, `Value`, untagged enums, and borrowed strings round-trip
unambiguously.

The public API is split into three layers plus an optional archive surface:

| Layer        | Module                | Default | Scope                                                          |
| ------------ | --------------------- | ------- | -------------------------------------------------------------- |
| **Core**     | `rustbinary::core`    | yes     | Compact V1 encode/decode, limits, trailing policy, caller buffers, `no_std` |
| **Protocol** | `rustbinary::protocol`| no      | schema evolution, fingerprints, reflection, static bounds, bit packing |
| **Pipeline** | `rustbinary::pipeline`| no      | CBOR, compression, encryption, ordered parallel batches        |
| **Archive**  | `rustbinary::archive` | no      | validated read-only memory-mapped object stores                |

[中文文档](README.zh-CN.md)

## Features

| Capability                      | Status                    | Notes                                                    |
| ------------------------------- | ------------------------- | -------------------------------------------------------- |
| nextjson binary codec           | Implemented               | strict marker-varint profile and a fixed-width legacy profile |
| Adaptive integers/strings       | Implemented               | per-value width selection, ZigZag signed values, ASCII7 packing |
| Adaptive `i64` collections      | Implemented               | raw / delta / run-length frames                          |
| SIMD                            | Hot scans only            | runtime AVX2/SSE2/NEON with scalar fallback; AVX-512/SVE/SME are detected but unused |
| Zero-allocation codec paths     | Implemented               | exact-size output and caller-owned buffers               |
| Borrowed zero-copy decoding     | Implemented               | nested `&str` fields point into the input frame          |
| Bit packing                     | Implemented               | `BitPacked` derive, checked widths, canonical zero padding |
| Schema fingerprinting           | Implemented               | structural hash including codec configuration            |
| Compile-time bounds             | Implemented               | `StaticSize::{MAX_SIZE, PACKED_MAX_BITS, PACKED_MAX_SIZE}` |
| RFC 8949 CBOR                   | Implemented               | nextjson CBOR relay; optional canonical map ordering     |
| Schema evolution                | Implemented               | stable field IDs, versions, defaults, unknown-field skipping |
| Compression                     | Implemented               | adaptive Zstandard; raw data is kept when it is smaller  |
| Encryption                      | Implemented               | XChaCha20-Poly1305, random 192-bit nonce, authenticated header |
| Parallel serialization          | Implemented               | ordered batch frames, scheduling-independent output      |
| Runtime reflection              | Implemented               | allocation-free compile-time metadata (`Reflect`)        |
| `std::io` streams               | Implemented               | reader/writer adapters keep the configured limits        |
| `no_std`                        | Implemented               | Compact V1 slice codec and caller buffers need no default features |
| `no_std + alloc`                | Implemented               | owned values, fingerprints, evolution, adaptive codecs   |

## Installation

Add the crate and the nextjson framework to your `Cargo.toml`:

```toml
[dependencies]
rustbinary = "0.1"
nextjson = { version = "0.1", features = ["derive"] }
```

Optional systems are enabled with Cargo features. Enable only what you use:

```toml
rustbinary = { version = "0.1", features = ["protocol"] }   # whole Protocol layer
rustbinary = { version = "0.1", features = ["fingerprint", "derive"] }
rustbinary = { version = "0.1", features = ["archive"] }    # mmap archives only
```

The minimum supported Rust version is 1.87 (declared as `rust-version` in
`Cargo.toml`). The optional Zstandard dependency needs a C toolchain on the
build platform.

### Feature matrix

| Feature            | Default | Purpose                                                            |
| ------------------ | ------- | ------------------------------------------------------------------ |
| `std`              | yes     | owned Core and I/O APIs; required by Pipeline and SIMD             |
| `alloc`            | via std | compatibility marker; owned APIs always available (nextjson's `FormatDecoder` needs `alloc`) |
| `protocol`         | no      | convenience bundle: adaptive, bit-packing, derive, fingerprint, reflection, schema-evolution, static-size |
| `pipeline`         | no      | convenience bundle: cbor, compression, encryption, parallel       |
| `archive`          | no      | validated read-only mmap archives; requires `std`, rkyv, memmap2   |
| `derive`           | no      | re-exports the procedural macros with their runtime feature        |
| `fingerprint`      | no      | structural fingerprint runtime and frames                          |
| `reflection`       | no      | allocation-free reflection runtime                                 |
| `static-size`      | no      | compile-time bounds runtime                                        |
| `simd`             | no      | runtime detection and hot-scan dispatch; never changes the wire bytes |
| `bit-packing`      | no      | bit-level traits and caller-buffer codec                           |
| `adaptive`         | no      | caller-buffer adaptive strings/collections; implies `bit-packing`  |
| `cbor`             | no      | RFC 8949 CBOR through nextjson's relay                             |
| `compression`      | no      | adaptive Zstandard frame                                           |
| `encryption`       | no      | XChaCha20-Poly1305, OS randomness, zeroized keys                   |
| `parallel`         | no      | scoped-thread ordered batch frames                                 |
| `schema-evolution` | no      | stable-field-ID versioned frames                                   |

## Quick start

```rust
use nextjson::{NsonDeserialize, NsonSerialize};

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
struct Packet {
    sequence: u64,
    payload: Vec<u8>,
}

let config = rustbinary::options()
    .with_varint_encoding()
    .with_little_endian()
    .with_limit(8 * 1024 * 1024)
    .with_collection_limit(100_000)
    .reject_trailing_bytes();

let packet = Packet { sequence: 42, payload: vec![1, 2, 3] };
let bytes = config.serialize(&packet)?;
assert_eq!(config.deserialize::<Packet>(&bytes)?, packet);
# Ok::<(), rustbinary::Error>(())
```

The top-level `serialize` / `deserialize` functions and `options()` use the
strict compact profile: little endian, canonical marker varints, ZigZag signed
integers, a 64 MiB byte limit, a 1,000,000-element collection limit, and
rejected trailing bytes. `legacy_options()` explicitly selects the old
unbounded fixed-width profile with allowed trailing bytes; it is meant for
trusted, in-memory data only.

### Configuration chain

Configuration values are small and copyable. Format-changing methods return a
different wrapper, so the transform order is visible in the type:

```text
Config -> CborConfig -> CompressedConfig -> EncryptedConfig
```

`Config` chooses endianness, integer encoding, byte/collection limits, and the
trailing-byte policy. The wrappers add one capability each. For example, with
all features enabled:

```rust
let secure = rustbinary::options()
    .with_limit(16 * 1024 * 1024)
    .with_cbor_format()
    .with_deterministic_encoding()
    .with_zstd_compression(3)
    .with_compression_threshold(256)
    .with_encryption(rustbinary::EncryptionKey::new([0xA5; 32]));
# let value = vec![1u32, 2, 3];
let frame = secure.serialize(&value)?;
assert_eq!(secure.deserialize::<Vec<u32>>(&frame)?, value);
# Ok::<(), rustbinary::Error>(())
```

Keys must come from a real key-management system; hard-coded keys are only
suitable for tests.

## Wire format

The format encodes values, never Rust object memory: no padding, native
pointers, vtables, or `repr(Rust)` layout. Every value starts with a one-byte
type tag; arrays and objects are terminated with `0xff`.

| nextjson value         | Wire representation                                   |
| ---------------------- | ----------------------------------------------------- |
| `null` / unit / `None` | tag `0x00`                                            |
| `false` / `true`       | tags `0x01` / `0x02`                                  |
| `u64` / `u128`         | tags `0x03` / `0x04` + unsigned payload               |
| `i64` / `i128`         | tags `0x05` / `0x06` + ZigZag payload                 |
| `f64` / `f32`          | tags `0x07` / `0x08` + IEEE 754 bits in configured endian |
| string / char          | tag `0x09` + encoded byte length + UTF-8              |
| array                  | tag `0x0a` + elements + `0xff`                        |
| object                 | tag `0x0b` + (`string key` + value) pairs + `0xff`    |

Integer and length payloads use marker varints (or fixed `u64` width in the
legacy profile, because nextjson's unified data model crosses all integers at
`u64`/`i64` width). Marker varints are canonical:

| Marker    | Payload   | Minimum accepted value     |
| --------- | --------- | -------------------------- |
| `0..=250` | none      | 0                          |
| `251`     | 2 bytes   | 251                        |
| `252`     | 4 bytes   | 65,536                     |
| `253`     | 8 bytes   | 4,294,967,296              |
| `254`     | 16 bytes  | 18,446,744,073,709,551,616 |
| `255`     | reserved  | never accepted             |

The decoder rejects non-minimal forms, narrowing overflow, malformed UTF-8,
invalid tags, truncation, limit violations, and disallowed trailing bytes.

## Zero allocation and zero copy

`serialized_size` uses a counting writer. `serialize_into_slice` serializes once
into caller-owned memory and returns the exact initialized length; when the
slice is too small, `Error::BufferTooSmall` carries the exact required size.

Slice deserialization borrows nested `&str` and byte-slice fields directly from
the input:

```rust
use nextjson::{NsonDeserialize, NsonSerialize};

#[derive(NsonSerialize, NsonDeserialize)]
struct View<'a> {
    name: &'a str,
    #[njson(borrow)]
    payload: &'a str,
}

let source = View { name: "edge", payload: "frame" };
let config = rustbinary::options().with_limit(4096);
let mut storage = vec![0; config.serialized_size(&source)? as usize];
let written = config.serialize_into_slice(&mut storage, &source)?;
let view: View<'_> = config.deserialize(&storage[..written])?;
assert_eq!(view.payload, "frame");
# Ok::<(), rustbinary::Error>(())
```

The codec does not allocate on this path; a user-defined nextjson
implementation may still allocate internally. Allocation-free codec paths
include `serialized_size`, `serialize_into_slice`, the adaptive
`encode_*_into_slice` / `decode_*_into_slice` APIs, and bit-packed caller
buffers. Reader-based decoding requires owned targets (`DeserializeOwned`);
returning a reference into a temporary reader buffer would be unsound.

Packed ASCII7 strings must expand into owned text; raw adaptive UTF-8 can be
returned as `Cow::Borrowed`. See [zero_copy.rs](examples/zero_copy.rs) for
pointer-range assertions.

## Adaptive encoding

`with_adaptive_encoding()` keeps the compact nextjson profile and adds explicit
data-aware APIs. Frames carry a stable strategy tag, and the decoder validates
canonical varints, padding, lengths, delta overflow, and RLE runs.

```rust
let adaptive = rustbinary::options()
    .with_limit(1 << 20)
    .with_adaptive_encoding();

let values = [1000, 1001, 1002, 1003];
let required = adaptive.encoded_i64_slice_size(&values)?;
let mut output = vec![0; required];
adaptive.encode_i64_slice_into_slice(&mut output, &values)?;
assert_eq!(adaptive.decode_i64_vec(&output)?, values);

let encoded = adaptive.encode_string("telemetry/primary")?;
assert_eq!(adaptive.decode_string(&encoded)?, "telemetry/primary");
# Ok::<(), rustbinary::Error>(())
```

String frames contain a strategy byte, a canonical decoded-length varint, and
the payload. Strategy 0 is raw UTF-8; strategy 1 is ASCII7 packed
least-significant-bit first. ASCII7 is only selected when every byte is ASCII
and the packed form is strictly smaller; ties resolve to raw UTF-8.

`i64` collections compare three complete encodings: independent ZigZag values
(`Raw`), first value plus checked `i128` deltas (`Delta`), and value/run pairs
(`RunLength`). Delta wins only when strictly smaller than raw and no larger
than RLE; RLE wins only when strictly smaller than raw; otherwise raw is used.
See [adaptive_zero_alloc.rs](examples/adaptive_zero_alloc.rs).

## Bit packing

`BitPacked` derives a bit-level codec for bounded fields. Fields annotated with
`#[bits = N]` use `BitValue` range validation; other fields recursively use
`BitPack`. Enum tags use the minimum bit width and unknown decoded tags are
rejected.

```rust
#[derive(Debug, PartialEq, rustbinary::BitPacked)]
struct Header {
    #[bits = 3]
    mode: u8,
    enabled: bool,
    #[bits = 7]
    delta: i16,
}

let config = rustbinary::options().with_bit_packing();
let header = Header { mode: 2, enabled: true, delta: -1 };
let packed = config.serialize(&header)?;
assert_eq!(config.deserialize::<Header>(&packed)?, header);
# Ok::<(), rustbinary::Error>(())
```

`BitWriter` clears the output so terminal padding is canonical zero, and
`BitReader` rejects non-zero padding and (when configured) trailing bytes.

## SIMD

With `simd`, `simd_backend()` picks AVX2, SSE2, NEON, or a scalar path at
runtime, caching the result. Adaptive ASCII classification and one-byte varint
scans use these kernels. All unaligned loads are bounds-checked by the safe
dispatcher; unsafe code is confined to target-specific modules and
`unsafe_op_in_unsafe_fn` is denied crate-wide.

AVX-512, SVE, and SME are detected and reported separately via
`hardware_capabilities()`, but no codec kernel uses them. Wider vectors are not
automatically faster for small codec records, and they have no hardware CI
coverage here.

## Fingerprint, reflection, and static bounds

```rust
use rustbinary::StaticSize as _;

#[derive(
    NsonSerialize,
    NsonDeserialize,
    rustbinary::Fingerprint,
    rustbinary::Reflect,
    rustbinary::StaticSize,
)]
struct Header {
    enabled: bool,
    count: u16,
    coordinates: [i32; 2],
}

let config = rustbinary::options().with_fingerprint();
let value = Header { enabled: true, count: 7, coordinates: [2, 3] };
let frame = config.serialize(&value)?;
let _: Header = config.deserialize(&frame)?;
assert!(Header::MAX_SIZE >= frame.len() - 16);
# Ok::<(), rustbinary::Error>(())
```

- `Fingerprint` hashes field and variant names, declared types, declaration
  order, integer encoding, effective endianness, trailing policy, resource
  limits, and CBOR deterministic mode. It is a compatibility identifier based
  on FNV-1a — **not** a cryptographic hash, and it must not replace AEAD,
  signatures, or authorization.
- `StaticSize` provides worst-case normal and bit-packed size bounds for
  statically sized types. Dynamically sized collections intentionally do not
  implement it.
- `Reflect` generates allocation-free metadata (type name, fields, variants)
  at compile time, with no runtime registry. See
  [metadata.rs](examples/metadata.rs).

The derive package has its own [English](rustbinary-derive/README.md) and
[Chinese](rustbinary-derive/README.zh-CN.md) guides covering the generated
contracts, accepted data shapes, generic bounds, `#[bits = N]` validation,
compile-fail cases, and production patterns.

## Schema evolution

The `schema-evolution` feature frames values with a stable schema ID, a schema
version, canonical field-ID ordering, length-delimited fields, and
unknown-field skipping. Field IDs and schema IDs are explicit protocol
decisions, not hashes that can change during refactoring.

The frame starts with the magic `RBE1`, a format version, flags, the schema ID,
the schema version, the field count, and `(field_id, payload)` entries. The
encoder sorts IDs and rejects duplicates; the decoder requires strictly
increasing IDs and validates all length arithmetic before slicing.

Application rules:

1. Assign one permanent schema ID to a compatible type family.
2. Never reuse a field ID for a different meaning or incompatible type.
3. Keep the ID when renaming a Rust field.
4. Add optional or defaulted fields for backward compatibility.
5. Use the encoded version for deliberate semantic migrations.
6. Inspect unknown fields when forwarding or preservation is required.

See [schema_evolution.rs](examples/schema_evolution.rs) for a complete V1/V2
upgrade and downgrade example with a rename, a default, and a borrowed field.

## CBOR, compression, and encryption

The pipeline is explicit and ordered: serialize, optionally compress, then
encrypt. Deterministic CBOR recursively sorts canonical map keys. Compression
runs only above a size threshold and stores the Zstandard output only when it
is strictly smaller. Encryption authenticates the full frame header (algorithm,
nonce, lengths) as AEAD associated data and uses a fresh 192-bit nonce every
time, so encrypted bytes are intentionally nondeterministic.

- CBOR (feature `cbor`) delegates to nextjson's RFC 8949 relay. The CBOR relay
  materializes a value tree before typed decoding, so per-container element
  counts are enforced against the collection limit to keep memory amplification
  bounded. Trailing bytes are always rejected (the relay requires exactly one
  root value).
- Compression (feature `compression`) uses the magic `RBZ1`, a 24-byte header
  recording raw and stored lengths, and decoders reject unknown flags,
  inconsistent lengths, decompression-length mismatches, truncation, and limit
  violations.
- Encryption (feature `encryption`) uses the magic `RBX1`. `EncryptionKey`
  owns 32 bytes, redacts `Debug`, and zeroizes on drop. Key derivation,
  rotation, storage, and access control remain application/KMS
  responsibilities. See [secure_pipeline.rs](examples/secure_pipeline.rs).

## Parallel batches

`with_parallel_serialization()` encodes independent batch elements on scoped
worker threads and emits an ordered `u64` length table followed by the payload
section, so the output bytes are independent of worker scheduling. It is meant
for large independent records; small values may be slower due to worker and
merge overhead. See [parallel_batch.rs](examples/parallel_batch.rs).

## Memory-mapped archives

The optional `archive` feature is a separate storage format based on rkyv's
validated relative-pointer layout. `build` produces a 64-byte RustBinary
envelope followed by a little-endian archive with 32-bit relative pointers. The
envelope records a format version, format flags, a non-zero application schema
ID, and checked payload/file lengths. rkyv is pinned because an incompatible
archive-layout dependency update requires a RustBinary format version review.

`MappedArchive::open` enforces the file-size limit (1 GiB by default),
validates the envelope, schema, alignment, and the complete relative-pointer
graph once; `root()` afterwards performs no allocation or deserialization.
Opening is `unsafe`: every process must keep the mapped file immutable and
untruncated for the mapping lifetime. Publish a new file and atomically switch
application references; never update a mapped file in place. The schema ID is
application-owned and must change after an incompatible root layout change; it
is an identity check, not cryptographic authentication. See
[mmap_archive.rs](examples/mmap_archive.rs).

## Streams

`serialize_into` writes directly to `std::io::Write`; `deserialize_from` reads
owned values from `std::io::Read`. Slice decoding is the only API that can
return borrowed values. Compression and encryption stream readers consume one
declared frame when passed `&mut R`, leaving later frames unread, and validate
header length relationships and configured raw/plaintext limits before
allocating the body.

## Security

- Every value starts with a one-byte type tag; `0xff` terminates containers.
- Floats preserve their IEEE 754 bit pattern; endianness is explicit.
- Variable integers reject marker 255 and non-minimal encodings.
- Struct fields are encoded as named object keys.
- Ordinary maps preserve nextjson iteration order and are not deterministic;
  deterministic map serialization requires deterministic CBOR or an ordered map.
- Compression and encryption frames validate versions, flags, lengths, and limits.
- Decryption authenticates before deserialization.
- Fingerprints are compatibility checks, not cryptographic authentication.
- User-defined nextjson implementations may allocate or reject borrowed visitors.

At every untrusted boundary: set realistic byte and collection limits, reject
trailing bytes unless an outer protocol owns them, authenticate adversarial
data, and treat decompression/deserialization errors as input failures.

Two bounds are worth calling out. Decompression is always bounded even without
a configured byte limit: the decompressed size is validated against the frame
header and capped at the crate-wide default when `with_no_limit` / the legacy
profile is used, so a hostile frame cannot drive unbounded expansion. The
collection limit applies to sequence and map element counts; strings are
bounded by the byte limit.

## Error model

All operations return `rustbinary::Result<T>`. `Error` preserves I/O errors and
has structured variants for limits, capacity, frames, schemas, compression,
encryption, bit packing, adaptive data, worker failure, and malformed primitive
values. It is `#[non_exhaustive]`; downstream exhaustive matches need a
fallback arm. Frame offsets, length sums, delta reconstruction, and integer
narrowing use checked arithmetic rather than panic recovery.

`Error::category()` maps errors to a stable operational category:
`UserInput`, `Protocol`, `Configuration`, or `InternalBug`.

## Verification

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features
cargo test --workspace --all-features --release
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
cargo bench --bench codec_comparison
```

### Examples

| Example                                                     | Covers                                     | Command                                                              |
| ----------------------------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------- |
| [complete.rs](examples/complete.rs)                         | end-to-end, all features                   | `cargo run --example complete --all-features`                        |
| [core_codec.rs](examples/core_codec.rs)                     | bounded core, buffers, borrowing, errors   | `cargo run --example core_codec`                                     |
| [zero_copy.rs](examples/zero_copy.rs)                       | nested borrowing and pointer proof         | `cargo run --example zero_copy`                                      |
| [mmap_archive.rs](examples/mmap_archive.rs)                 | validated mmap object graph                | `cargo run --example mmap_archive --features archive`                |
| [adaptive_zero_alloc.rs](examples/adaptive_zero_alloc.rs)   | adaptive decisions and caller buffers      | `cargo run --example adaptive_zero_alloc --features adaptive`        |
| [secure_pipeline.rs](examples/secure_pipeline.rs)           | deterministic CBOR, compression, AEAD      | `cargo run --example secure_pipeline --features cbor,compression,encryption` |
| [schema_evolution.rs](examples/schema_evolution.rs)         | bidirectional schema V1/V2                 | `cargo run --example schema_evolution --features schema-evolution`   |
| [parallel_batch.rs](examples/parallel_batch.rs)             | ordered multi-worker batches               | `cargo run --example parallel_batch --features parallel`             |
| [metadata.rs](examples/metadata.rs)                         | fingerprint, reflection, bounds, packing   | `cargo run --example metadata --features bit-packing,derive,fingerprint,reflection,static-size` |

## docs.rs and compatibility

The package metadata builds docs.rs with all features, and feature-gated APIs
receive automatic docs.rs labels. To validate docs locally on PowerShell:

```powershell
$env:RUSTDOCFLAGS='-D warnings'
cargo doc --workspace --all-features --no-deps
```

Versioned wrappers reject unknown versions and reserved flags instead of
guessing. Before 1.0, wire changes may occur between minor releases and must be
called out in release notes. Long-lived deployments should pin the version,
record the complete configuration, keep golden vectors, and use explicit schema
IDs.

## Non-goals

- Casting arbitrary Rust structs directly from serialized memory
- Mutable shared-memory object graphs or in-place updates to mapped files
- Wrapping blocking I/O in a misleading async facade
- Automatically sorting randomized maps in the core profile
- Claiming AVX-512/SVE acceleration without tested kernels
- Replacing application key management, authorization, or schema governance

## License

RustBinary is licensed under the [Apache License, Version 2.0](LICENSE). You
may use, reproduce, modify, and redistribute the project under the terms of
that license. Redistributions must preserve the copyright notice, license text,
and required attribution notices. Changes to the source should be identified
clearly, and the Apache License patent terms and disclaimer apply.

The complete legal text is in [`LICENSE`](LICENSE). This project is provided
without warranties or conditions of any kind.
