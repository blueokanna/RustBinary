# RustBinary

RustBinary is a bounded binary codec built on [nextjson](https://crates.io/crates/nextjson).
Your types are described with the normal nextjson derives; this crate turns
those into bytes and back. It exists for a narrow job: moving structured data
across a wire or into a file, where the other side might be hostile, where
memory is scarce, and where you want to know exactly what a decoder will
consume before it runs.

- **MSRV**: Rust 1.78 (hard-pinned in both crates and verified by CI on the
  exact toolchain; the dependency graph is locked to versions that still
  build on 1.78).
- **`no_std` first**: the crate is unconditionally `#![no_std]` + `alloc`;
  `std` is an opt-in feature that only adds the I/O adapters and the std-only
  transform layers. The self-describing core and every self-implemented
  feature (adaptive, entropy, reconcile, evolution, projection, bounded,
  probe) build without `std`.

Every feature in here answers a concrete question — "can I afford to reject
this frame?", "can a light client read one field without scanning the whole
record?", "what is the worst case this type can do to my heap?" — and the
sections below state the answers together with what each one costs. Nothing in
this crate is decoration, and the README says plainly when a feature is a
trade-off rather than a win.

## Format identity

The stream wire format is a **type-tagged, self-describing byte stream**:
every value starts with a one-byte type tag, and arrays and objects end with
`0xff`. That is the whole identity of the *dynamic* stream. It is not a
bincode-style compact layout and it is not a CBOR-style length-prefixed
layout, and it will not quietly become either of those.

For statically typed values the crate additionally ships a **schema-guided
compact profile** (`Config::with_compact_format()` + the `CompactBinary`
derive). It is a *second, additive* wire format, not a mode of the tagged
stream: no per-value tags, no field names, length-prefixed containers, and
memcpy / bulk-endian fast paths for byte strings and float arrays. `Value`,
untagged enums, and `FormatEncoder`-driven types stay on the self-describing
stream; static hot paths can take the compact profile. The two never change
each other's bytes.

Being self-describing buys three things the rest of the design leans on:

- `Option`, untagged enums, and `nextjson::Value` round-trip without any side
  metadata.
- A borrowed `&str` field points straight into the input frame; no copying.
- A decoder can always tell where a value ends and whether a frame is whole.

The price is a one-byte tag per value and one tag per element in a numeric
array. That tax is real, and it is measured rather than waved away — the
benchmark lab in this repository reports it against bincode 1, bincode 2,
bincode-next, postcard, rkyv, and minicbor on the same data, and the numbers
are honest about where this format loses. If your workload is a giant array of
`f64` and nothing else, a schemaless codec will beat the *tagged stream* on
size and speed; the compact profile closes most of that gap while keeping the
same bounded, resource-policed decoder. If your workload is heterogeneous
records that must round-trip unambiguously and be readable without an
out-of-band schema, the tag tax buys you that.

The `archive` feature is **not a second stream format**. It is a separate
storage format — an in-tree, root-first relative-pointer codec inside a
RustBinary envelope — for read-only memory-mapped object stores, and it is
versioned on its own (`RBARC004`). The stream codec never casts memory, never
emits relative pointers, and never changes its behavior based on which Cargo
features are on.

## Dependency policy

This crate is deliberately **self-contained**. The stream path depends on
nextjson and, optionally, the derive crate; every primitive that other codecs
would pull in as a third-party dependency is implemented in-tree:

| Primitive            | In-tree module        | Replaces        |
| -------------------- | --------------------- | --------------- |
| BLAKE3 (Merkle + projection proofs) | `crate::hash`   | `blake3`        |
| XChaCha20-Poly1305 AEAD (RFC 8439)  | `crate::aead`   | `chacha20poly1305` |
| OS CSPRNG + zeroize  | `crate::entropy`      | `getrandom`, `zeroize` |
| LZ77 lossless compression | `crate::lz`    | `zstd`          |
| Read-only mmap       | `crate::mmap`         | `memmap2`       |
| Zero-copy archive codec | `crate::archive_codec` | `rkyv`        |

- **MSRV**: the crate is pinned to Rust 1.78 (`rust-version = "1.78"` in both
  `rustbinary` and `rustbinary-derive`), and the CI matrix verifies every
  feature combination on that exact toolchain. nextjson is pinned to `=0.1.4`,
  whose serialize/deserialize path **rejects non-finite floats** (`NaN`/`±Inf`
  are errors, not round-trippable values); RustBinary inherits and tests that
  contract.
- **Supply chain**: the runtime dependency graph is exactly `nextjson` (+ its
  derive) and the in-tree `rustbinary-derive`. No other crate is linked at
  runtime; the dev-dependencies (proptest for property tests) are pinned to
  versions that still build on 1.78.
- **Crypto implementation**: every primitive is implemented in-tree and
  validated against official vectors — BLAKE3 against the RFC test suite,
  ChaCha20-Poly1305 against the RFC 8439 vectors, and the AEAD framing
  byte-for-byte against the previous `chacha20poly1305`-based pipeline (a
  golden-vector test holds the old bytes). The Merkle tree also uses the
  in-tree BLAKE3, so the whole integrity path is dependency-free.

## Layers

| Layer       | Module                 | Default | Scope                                                                        |
| ----------- | ---------------------- | ------- | ---------------------------------------------------------------------------- |
| **Core**    | `rustbinary::core`     | yes     | compact encode/decode, limits, trailing policy, caller buffers; `no_std` always |
| **Protocol**| `rustbinary::protocol` | no      | schema evolution, fingerprints, reflection, static bounds, bit packing       |
| **Pipeline**| `rustbinary::pipeline` | no      | CBOR, compression, encryption, ordered parallel batches (`std`)              |
| **Sync**    | `sync`                 | no      | rANS entropy coding, differential frames, IBLT reconciliation, trust calculus|
| **Archive** | `rustbinary::archive`  | no      | Merkle-verified read-only memory-mapped object stores                        |
| **Projection**| `rustbinary::projection`| no    | self-authenticating projectable records with projection soundness            |

[中文文档](README.zh-CN.md)

## Features

| Capability                  | Status         | Notes                                                                                       |
| --------------------------- | -------------- | ------------------------------------------------------------------------------------------- |
| nextjson binary codec       | Implemented    | strict marker-varint profile and a fixed-width legacy profile                               |
| Compact profile             | Implemented    | schema-guided `CompactBinary` derive: no tags/field names, length-prefixed containers, byte/float fast paths |
| Adaptive integers/strings   | Implemented    | per-value width selection, ZigZag signed values, ASCII7 packing                             |
| Adaptive `i64` collections  | Implemented    | raw / delta / run-length frames                                                             |
| rANS entropy coding         | Implemented    | from-scratch static-model coder; hash-free replay verification                              |
| SIMD                        | Hot scans only | runtime AVX2/SSE2/NEON with scalar fallback; AVX-512/SVE/SME detected but unused            |
| Zero-allocation codec paths | Implemented    | exact-size output and caller-owned buffers                                                  |
| Borrowed zero-copy decoding | Implemented    | nested `&str` fields point into the input frame                                             |
| Bit packing                 | Implemented    | `BitPacked` derive, checked widths, canonical zero padding                                  |
| Schema fingerprinting       | Implemented    | structural hash including codec configuration (FNV-1a, **not** cryptographic)               |
| Compile-time bounds         | Implemented    | `StaticSize::{MAX_SIZE, PACKED_MAX_BITS, PACKED_MAX_SIZE}`                                  |
| RFC 8949 CBOR               | Implemented    | crate-owned streaming CBOR codec (no value tree); optional canonical map ordering           |
| Schema evolution            | Implemented    | stable field IDs, versions, defaults, unknown-field skipping                                |
| Compression                 | Implemented    | in-tree LZ77 (hash-chained matches); raw data is kept when it is smaller  |
| Encryption                  | Implemented    | XChaCha20-Poly1305, random 192-bit nonce, authenticated header                              |
| Parallel serialization      | Implemented    | ordered batch frames, scheduling-independent output                                         |
| Runtime reflection          | Implemented    | allocation-free compile-time metadata (`Reflect`), per-field symbol alphabets               |
| Differential frames         | Implemented    | baseline-relative integer deltas + deterministic HPACK-style dynamic tables                 |
| IBLT set reconciliation     | Implemented    | from-scratch invertible Bloom lookup tables (Goodrich and Mitzenmacher)                     |
| Trust calculus              | Implemented    | type-level authentication state machine; unauthenticated receive is unrepresentable         |
| Merkle archives             | Implemented    | in-tree BLAKE3 tree, O(log n) proofs, header-only open                                      |
| Projectable self-auth. records | Implemented | projection soundness, O(log n) proofs, schema-version binding, unknown-field skipping      |
| Resource-bounded decoding   | Implemented    | schema-derived B/A/D/W cost algebra, budget-enforced `decode_bounded` with evidence          |
| Exact frame probing         | Implemented    | allocation-free `Config::probe`: exact bytes/containers/elements/depth of one value, honors every limit |
| Configurable depth limit    | Implemented    | `Config::with_depth_limit` caps nesting on encode and decode                              |
| Formal verification         | Kani harnesses | varint/ZigZag core + projection tree geometry + budget-limit algebra                        |
| `no_std` first               | Implemented    | the crate is unconditionally `no_std` + `alloc`; `std` is an opt-in feature                  |
| `no_std` layers             | Implemented    | compact, adaptive, entropy, reconcile, evolution, projection, bounded, probe, CBOR, trust calculus all build without `std` |

## Installation

```toml
[dependencies]
rustbinary = "0.1"
# nextjson is pinned to the exact codec target: 0.1.4 rejects non-finite
# floats on both encode and decode, and RustBinary inherits that contract.
nextjson = { version = "=0.1.4", features = ["derive"] }
```

Enable only the systems you use:

```toml
rustbinary = { version = "0.1", features = ["protocol"] }   # whole Protocol layer
rustbinary = { version = "0.1", features = ["sync"] }       # entropy + reconcile + trust
rustbinary = { version = "0.1", features = ["archive"] }    # Merkle mmap archives
```

For `no_std` targets, opt out of `std` and pull in the layers you need — the
core, the protocol, and every self-implemented feature build without `std`:

```toml
rustbinary = { version = "0.1", default-features = false, features = ["compact"] }
```

Everything is pure Rust with no C build step, and the runtime dependency
graph is exactly nextjson plus the in-tree derive (see the dependency
policy).

### Feature matrix

| Feature            | Default | Purpose                                                                                                  |
| ------------------ | ------- | -------------------------------------------------------------------------------------------------------- |
| `std`              | yes     | I/O adapters and the std-only transform layers (archive, compression, encryption, parallel, SIMD, trust sessions); the self-describing core is always `no_std` |
| `protocol`         | no      | bundle: adaptive, bit-packing, derive, fingerprint, reflection, schema-evolution, static-size            |
| `pipeline`         | no      | bundle: cbor, compression, encryption, parallel                                                          |
| `sync`             | no      | bundle: entropy, reconcile, trust                                                                        |
| `archive`          | no      | Merkle-verified mmap archives; in-tree codec, mmap, and BLAKE3; requires `std` and `derive` |
| `compact`          | yes     | schema-guided compact profile runtime; implies `derive` (the profile is consumed through the `CompactBinary` derive) |
| `derive`           | no      | re-exports the procedural macros with their runtime feature; implied by `compact` and `archive` |
| `fingerprint`      | no      | structural fingerprint runtime and frames                                                                |
| `reflection`       | no      | allocation-free reflection runtime                                                                      |
| `static-size`      | no      | compile-time bounds runtime                                                                             |
| `simd`             | no      | runtime detection and hot-scan dispatch; never changes the wire bytes                                   |
| `bit-packing`      | no      | bit-level traits and caller-buffer codec                                                                 |
| `adaptive`         | no      | caller-buffer adaptive strings/collections; implies `bit-packing`                                       |
| `entropy`          | no      | static-model rANS entropy coding; implies `reflection`                                                  |
| `reconcile`        | no      | differential frames (`delta`) and IBLT (`ibl`)                                                          |
| `trust`            | no      | type-level trust calculus and session state machine                                                      |
| `cbor`             | no      | crate-owned streaming RFC 8949 CBOR codec; optional canonical ordering                             |
| `compression`      | no      | in-tree LZ77 frame                                                                        |
| `encryption`       | no      | XChaCha20-Poly1305, OS randomness, zeroized keys                                                         |
| `parallel`         | no      | scoped-thread ordered batch frames                                                                       |
| `schema-evolution` | no      | stable-field-ID versioned frames                                                                         |
| `bounded`          | no      | `DecodeBounded` cost algebra (B/A/D/W), `Budget`, `decode_bounded`; `no_std`, requires `derive` |
| `projection`       | no      | self-authenticating projectable records and projection proofs; `no_std`, in-tree BLAKE3 |

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

`options()` and the top-level functions use the strict compact profile: little
endian, canonical marker varints, ZigZag signed integers, a 64 MiB byte limit,
a 1,000,000-element collection limit, and rejected trailing bytes.
`legacy_options()` is the old unbounded fixed-width profile; it is for trusted
in-memory data only and is named so you notice it.

### Configuration chain

Format-changing methods return a different wrapper type, so the transform
order is visible in the type:

```text
Config -> CborConfig -> CompressedConfig -> EncryptedConfig
```

```rust
let secure = rustbinary::options()
    .with_limit(16 * 1024 * 1024)
    .with_cbor_format()
    .with_deterministic_encoding()
    .with_compression(3)
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
pointers, vtables, or `repr(Rust)` layout.

| nextjson value         | Wire representation                                       |
| ---------------------- | --------------------------------------------------------- |
| `null` / unit / `None` | tag `0x00`                                                |
| `false` / `true`       | tags `0x01` / `0x02`                                      |
| `u64` / `u128`         | tags `0x03` / `0x04` + unsigned payload                   |
| `i64` / `i128`         | tags `0x05` / `0x06` + ZigZag payload                     |
| `f64` / `f32`          | tags `0x07` / `0x08` + IEEE 754 bits in configured endian |
| string / char          | tag `0x09` + encoded byte length + UTF-8                  |
| array                  | tag `0x0a` + elements + `0xff`                            |
| object                 | tag `0x0b` + (`string key` + value) pairs + `0xff`        |

Integer and length payloads use canonical marker varints in the default
profile:

| Marker    | Payload  | Minimum accepted value     |
| --------- | -------- | -------------------------- |
| `0..=250` | none     | 0                          |
| `251`     | 2 bytes  | 251                        |
| `252`     | 4 bytes  | 65,536                     |
| `253`     | 8 bytes  | 4,294,967,296              |
| `254`     | 16 bytes | 18,446,744,073,709,551,616 |
| `255`     | reserved | never accepted             |

The decoder rejects non-minimal forms, narrowing overflow, malformed UTF-8,
invalid tags, truncation, limit violations, and disallowed trailing bytes.
The varint and ZigZag machinery lives in one place, `canonical`, shared by
both directions, and Kani proves its roundtrip, boundedness, and canonical
uniqueness (see Verification).

## Zero allocation and zero copy

`serialized_size` counts with a writing pass that allocates nothing.
`serialize_into_slice` serializes once into caller-owned memory and returns
the exact initialized length; when the slice is too small,
`Error::BufferTooSmall` carries the exact required size.

Slice deserialization borrows nested `&str` fields directly from the input:

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
implementation may still allocate internally. Reader-based decoding requires
owned targets; returning a reference into a temporary reader buffer would be
unsound. Packed ASCII7 strings expand into owned text; raw adaptive UTF-8 can
be returned as `Cow::Borrowed`.

## Adaptive encoding

`with_adaptive_encoding()` keeps the compact profile and adds explicit
data-aware APIs. Frames carry a stable strategy tag, and the decoder validates
canonical varints, padding, lengths, delta overflow, and RLE runs.

The encoder's analysis policy is controlled by
`with_adaptive_mode(rustbinary::AdaptiveMode::…)`:

- `Off` (default) — encode directly with the raw representation; **zero** scan
  passes, the low-latency choice for online paths.
- `Heuristic` — sample the first `HEURISTIC_SAMPLE` (64) elements to decide
  whether delta / run-length pays off, then take a single sizing pass.
- `Exact` — compare the complete raw / delta / run-length encodings and pick
  the smallest; best for offline compression.

The mode is **size-only**: every strategy is lossless, so all three modes
decode to the same values; they differ in scan passes and frame size.

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

// Off (default) writes raw frames with no analysis scans; Exact picks delta
// for ramp-like data.
let off = rustbinary::options()
    .with_adaptive_encoding()
    .with_adaptive_mode(rustbinary::AdaptiveMode::Off);
assert_eq!(
    off.collection_strategy(&off.encode_i64_slice(&values)?)?,
    rustbinary::CollectionStrategy::Raw
);
# Ok::<(), rustbinary::Error>(())
```

String frames hold a strategy byte, a canonical decoded-length varint, and the
payload. Strategy 0 is raw UTF-8; strategy 1 is ASCII7 packed
least-significant-bit first, chosen only when every byte is ASCII and the
packed form is strictly smaller. `i64` collections compare three complete
encodings — independent ZigZag values, first-value-plus-checked-deltas, and
value/run pairs — and pick the strictly smallest with the documented tie
order.

## rANS entropy coding

`with_entropy_encoding()` enables the `entropy` module: a from-scratch rANS
coder (range Asymmetric Numeral Systems; 16-bit renormalization; 64-bit
state) with **static models derived from `Reflect` schema**. It is not a
wrapper around zstd or anything else: no C, no dictionary transmission,
`no_std` + `alloc`.

The model is derived without transmitting anything:

- `#[derive(Reflect)]` records a per-field symbol alphabet: an enum's variant
  cardinality, a `#[bits = N]` range, an explicit `#[entropy(symbols = N)]`,
  or a known primitive (`bool` to 2, `u8`/`i8` to 256).
- `Model::from_uniform` builds a uniform prior over that exact alphabet;
  `Model::from_weights` builds a static prior from application weights.
- `SchemaModel::from_reflect` walks the shape and yields one model per field.
  Both sides compile the same type, so both derive the same table; the
  decoder needs nothing beyond the schema it already has.

### How corruption is detected, without a hash

A rANS stream is not self-authenticating. The final state check rejects
truncation and most substitution, but it has a nonzero miss rate for byte
changes that still decode. The first version of this module papered over that
with a SHA-256 digest in the frame; this version removes the hash entirely and
replaces it with something exact:

**Replay verification.** The decoder re-encodes the decoded symbols with the
same models and requires the result to match the frame's stored payload and
final state byte-for-byte. A frame is accepted only when it is the canonical
encoding of the payload it decodes to — i.e., `frame == encode(decode(frame))`.

That acceptance rule is the entire guarantee; the failure modes are:

- Truncation or a corrupt state/count fails the consumption and state checks.
- A byte change that still decodes yields a *different* payload, whose
  canonical encoding almost never equals the corrupted frame, so the replay
  differs and the frame is rejected.
- The residual gap: a corrupted frame can in principle be the canonical
  encoding of a *different* payload (`frame == encode(x)` with `x` different
  from the original). Replay then accepts it with the wrong content; no
  hash-free scheme can close that gap. Note that an unkeyed frame digest
  *would* catch every accidental flip of this kind — replay verification
  trades that small detection gap for zero hashing. Neither replay nor a
  digest resists an attacker who can rewrite the frame; authenticated
  integrity belongs to the AEAD/trust layer.
- Raw-fallback frames store the literal input and carry no redundancy, so
  they are only length-checked. `EntropyConfig::without_raw_fallback()`
  disables that fallback, keeping every frame coded and replay-verified.

Replay verification is on by default and costs one extra encode pass on
decode (visible in the benchmark table). `without_replay_verification()`
drops it for transports that authenticate bytes elsewhere.

```rust
use rustbinary::{Model, RansEncoder, RansDecoder};

// An exact 5-symbol alphabet costs log2(5) ~= 2.32 bits/symbol instead of 3.
let model = Model::from_uniform(5)?;
let mut encoder = RansEncoder::new();
for _ in 0..100 { encoder.put_symbol(&model, 3)?; }
let (final_state, payload) = encoder.finish();
let mut decoder = RansDecoder::new(final_state, &payload);
let mut kinds = Vec::new();
for _ in 0..100 { kinds.push(decoder.get_symbol(&model)?); }
decoder.finish()?;
kinds.reverse();
# assert!(kinds.iter().all(|&k| k == 3));
# Ok::<(), rustbinary::Error>(())
```

See [entropy.rs](examples/entropy.rs) for the schema-driven flow and the
standalone byte codec with a skewed prior (2x+ on repetitive telemetry,
measured in the benchmark crate).

## Bit packing

`BitPacked` derives a bit-level codec for bounded fields. `#[bits = N]`
fields use `BitValue` range validation; other fields recurse through
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

`BitWriter` clears the output so terminal padding is canonical zero;
`BitReader` rejects non-zero padding and, when configured, trailing bytes.

## SIMD

`simd_backend()` picks AVX2, SSE2, NEON, or a scalar path at runtime and
caches the result. Adaptive ASCII classification and one-byte varint scans use
these kernels. All unaligned loads are bounds-checked by the safe dispatcher;
unsafe code is confined to target-specific modules, and
`unsafe_op_in_unsafe_fn` is denied crate-wide.

AVX-512, SVE, and SME are detected and reported by
`hardware_capabilities()`, but no kernel uses them; wider vectors are not
automatically faster for small codec records and there is no hardware CI
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
- `StaticSize` gives worst-case normal and bit-packed size bounds for
  statically sized types; dynamic collections intentionally do not implement
  it.
- `Reflect` generates allocation-free metadata (type name, fields, variants)
  at compile time with no runtime registry. Each `FieldInfo` also carries the
  field's symbol alphabet (`symbols`), which the rANS schema model consumes.

## Schema evolution

The `schema-evolution` feature frames values with a stable schema ID, a
schema version, canonical field-ID ordering, length-delimited fields, and
unknown-field skipping. Field IDs and schema IDs are explicit protocol
decisions, not hashes that can change during refactoring.

The frame starts with the magic `RBE1`, a format version, flags, the schema
ID, the schema version, the field count, and `(field_id, payload)` entries.
The encoder sorts IDs and rejects duplicates; the decoder requires strictly
increasing IDs and validates all length arithmetic before slicing.

Application rules: one permanent schema ID per compatible type family; never
reuse a field ID for a different meaning or incompatible type; keep the ID
when renaming a Rust field; add optional or defaulted fields for backward
compatibility; use the encoded version for deliberate semantic migrations;
inspect unknown fields when forwarding or preservation is required.

## Projectable self-authenticating records (projection soundness)

The `projection` feature is a **protocol format, not a compact codec**: a
canonical, self-authenticating record whose fields can be verified and
decoded *individually* against a trusted root, without scanning or decoding
the rest of the record. The guarantee is **projection soundness**:

```text
Verify(P, π, q) = v   ⟹   v = Project_q(Decode(P))
```

`P` is the record, `q` a projection query (a set of field ids), `π` the
proof, and `Decode(P)` the unique canonical decoding (uniqueness follows from
the format's canonicality: strictly increasing field ids, fixed-width
headers, no duplicates). Fields outside `q` are never read, yet their
authenticity is still guaranteed: every field is bound into the Merkle root,
so a tampered or substituted unread field changes the root and fails
verification.

- **Construction**: fields are `(field_id, payload_len, payload)` triples;
  the root is `BLAKE3(schema_version ‖ merkle_root)`, so a proof cannot be
  replayed against a different schema version. `RecordBuilder` enforces
  canonical order; `prove` extracts a batch proof (minimal sibling set);
  `verify` never touches the record and requires a **trusted anchor** (the
  record root as committed by an authenticated source — a block header, a
  keyed commitment, a signed index). The module binds integrity; keyed
  authentication is the caller's trust anchor. `verify_untrusted` checks
  internal consistency only and detects corruption, not substitution.
- **Honest complexity**: `prove` is O(n); proof size is O(|q| · log(n/|q|))
  worst case and O(log n) for a single field or a contiguous range; `verify`
  does O(|q| + log n) hash operations. The Merkle overhead means the format
  targets records with moderate field counts; for payload-heavy records the
  per-field hash cost is negligible.
- **Verified**: the Kani harness `small_tree_proof_agrees_with_root` proves
  the aggregation/recomputation protocol is algebraically consistent for any
  hash and any query; `leaf_count_is_complete_and_bounded` proves the tree is
  complete and never more than doubles.

```rust
let mut builder = rustbinary::RecordBuilder::new(7); // schema version 7
builder.insert_str(1, "alpha").unwrap();
builder.insert_varint(2, 42).unwrap();
builder.insert_bytes(3, b"\x00\x01").unwrap();
let record = builder.finish().unwrap();

// The trusted anchor comes from an authenticated source (e.g. a block header).
let parsed = rustbinary::ProjectedRecord::parse(&record, &rustbinary::ProjectionLimits::new())?;
let anchor = *parsed.root();

let query = rustbinary::Projection::new([2]);
let proof = rustbinary::prove(&record, &query, &rustbinary::ProjectionLimits::new())?;
let verified = rustbinary::verify(&proof, &anchor, 7)?; // schema version bound
assert_eq!(verified[0].field_id, 2);
assert_eq!(verified[0].as_varint()?, 42);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Resource-bounded decoding (cost algebra)

The `bounded` feature advances `StaticSize` from "worst-case output bytes" to
**provable resource semantics**. For each type the `#[derive(DecodeBounded)]`
macro generates a cost algebra that mirrors the parser exactly:

```text
B(T)  maximum input bytes one decode of T can consume
A(T)  maximum heap bytes one decode of T can allocate
D(T)  maximum parser nesting depth
W(T)  worst-case work (bytes read + per-field overhead)
```

`decode_bounded` runs the decode under a [`Budget`] and returns a `Decoded<T>`
carrying **evidence** (`ResourceUse`: exact bytes read plus provable bounds
for allocation, depth, and work). The algebra is isomorphic to the parser —
the derive mirrors the exact container/key structure the encoder and decoder
walk — so for statically bounded types the constants are exact: such a decode
reads at most `B(T)` bytes, allocates at most `A(T)` (usually 0), nests at
most `D(T)` levels, and does at most `W(T)` work, by construction.

Dynamic types (`Vec`, `String`, `&str`) report `usize::MAX` for
content-dependent resources, and the *runtime* budget enforces the caller's
limits. The allocation ceiling is conservative and exact for the types the
derive covers:

- **Data**: every byte materialized on the heap from the input (string and
  byte-buffer bodies) is bounded by the byte limit, so `data ≤ read`.
- **Structure**: collection backing buffers and boxes beyond their wire data.
  The derive computes `MAX_STRUCTURAL_ELEMENT` — the worst per-element
  structural allocation across the type's collections (`size_of::<T>()` for
  `Vec<T>`/`Box<T>`, `0` for `String`). A decode has at most `D(T)` nested
  collection levels, each capped at the collection limit, so
  `allocation ≤ read + MAX_STRUCTURAL_ELEMENT · D(T) · collection_limit ≤
  max_input + max_alloc`. The reported `alloc_bound` is that ceiling.
  Manual `DecodeBounded` implementations that do not declare
  `MAX_STRUCTURAL_ELEMENT` fall back to the budget's
  `element_structure_bytes` knob (default [`ELEMENT_STRUCTURE_BYTES`] = 64,
  which covers the standard collection shapes; raise it for wide-tuple or
  large-inline-element layouts).

Every failure reports which dimension was exceeded (`BudgetExceeded`). This
is the entry point for DoS-sensitive consumers: blockchain nodes, enclaves,
and gateways pick a `Budget` — from policy or from `Budget::from_type::<T>()`,
which derives tight defaults from the algebra — and receive evidence of what
the decode consumed.

```rust
#[derive(nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::DecodeBounded)]
struct Packet {
    sequence: u64,
    payload: Vec<u8>,
}

let bytes = rustbinary::options().serialize(&Packet { sequence: 1, payload: vec![0; 64] })?;
let budget = rustbinary::Budget::from_type::<Packet>()
    .with_max_alloc(1 << 16);
let decoded = rustbinary::decode_bounded::<Packet>(&bytes, budget)?;
assert_eq!(decoded.value.sequence, 1);
assert!(decoded.use_.read as usize <= bytes.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The `bounded` module's budget derivation and the projection tree geometry are
Kani-proven (see Verification). `Config::with_depth_limit` (always available)
caps container nesting on encode and decode below the crate-wide 128 ceiling
and is clamped so a hostile limit cannot cause out-of-bounds indexing.

## Frame probing (exact preflight)

A normal decode materializes the value; a skip discards it. `Config::probe`
occupies the space in between: it walks the wire format and reports the
**exact** structural footprint of the next value — byte length, container
count, element count, and maximum nesting depth — with zero allocation and
without ever building a value.

The probe is a byte-exact mirror of the decoder: it reads with the same
boundary semantics, honors the same byte/collection/depth limits, and rejects
the same malformed input (invalid tags, non-canonical varints, truncation,
trailing bytes). A value accepted by `probe` decodes with the same byte count;
a value rejected by `probe` is rejected by `deserialize` for the same reason.
The drift-guard tests pin this against the encoder.

```rust
let frame = rustbinary::options().serialize(&vec![1u32, 2, 3])?;
let probe = rustbinary::options().probe(&frame)?;
assert_eq!(probe.bytes(), frame.len());       // exact frame length
assert_eq!(probe.containers(), 1);            // one array
assert_eq!(probe.elements(), 3);              // three entries
assert_eq!(probe.depth(), 1);                 // one nesting level

// Preflight against a budget before decoding: reject by shape, not by decode.
#[cfg(feature = "bounded")]
{
    let budget = rustbinary::Budget::default().with_max_input(8);
    assert!(!probe.fits_budget(budget));
}
# Ok::<(), rustbinary::Error>(())
```

Use cases: a gateway decides "should I decode this frame?" from its exact
shape before spending memory on it; an inspector routes by shape without
parsing values; a stream hand-off already knows the exact frame length.

## CBOR, compression, and encryption

The pipeline is explicit and ordered: serialize, optionally compress, then
encrypt. Deterministic CBOR recursively sorts canonical map keys. Compression
runs only above a size threshold and stores the in-tree LZ77 output only when
it is strictly smaller. Encryption authenticates the full frame header
(algorithm, nonce, lengths) as AEAD associated data and uses a fresh 192-bit
nonce each time, so ciphertext is intentionally nondeterministic.

- CBOR is the crate's own streaming RFC 8949 codec (`src/cbor_codec.rs`):
  values encode and decode directly between `T` and the bytes with no
  intermediate value tree and no JSON text round-trip, so the memory peak of
  a decoded value is the decoded value itself. Definite- and
  indefinite-length containers, bignum tags 2/3, half-precision floats, and
  native byte strings are supported; byte and collection limits are enforced
  inline. Deterministic canonical map ordering is the one explicit exception
  and materializes a value tree to sort keys (opt-in).
- Compression uses the magic `RBZ1` and a 24-byte header recording raw and
  stored lengths; decoders reject unknown flags, inconsistent lengths,
  decompression-length mismatches, truncation, and limit violations.
  Decompression is always bounded, even with no configured limit.
- Encryption uses the magic `RBX1`. `EncryptionKey` owns 32 bytes, redacts
  `Debug`, and zeroizes on drop. Key derivation, rotation, storage, and
  access control stay with the application/KMS.

## Parallel batches

`with_parallel_serialization()` encodes independent batch elements on scoped
worker threads and emits an ordered `u64` length table followed by the payload
section, so the output bytes are independent of worker scheduling. It is for
large independent records; small values may be slower due to worker and merge
overhead.

## Memory-mapped archives with Merkle proofs

The `archive` feature is a storage format: the in-tree, root-first
relative-pointer codec (`crate::archive_codec`) inside a 128-byte RustBinary
envelope. `build` produces the envelope, the little-endian payload, and a
stored BLAKE3 Merkle tree over fixed-size payload blocks. Hashing uses the
in-tree BLAKE3 (`crate::hash`, validated against the official test vectors);
domain separation (`LEAF`/`NODE`/`PAD` tags plus big-endian index) and tree
geometry are this module's own. The envelope records the format version,
flags, a non-zero application schema ID, payload/file lengths, block size and
count, the Merkle root, and the hash-section location.

Archived types are ordinary structs with `#[derive(Archive, Serialize)]`
(`#[archive(check_bytes)]` is accepted for compatibility). The derive emits a
packed-free `#[repr(C)]` mirror type with 32-bit relative pointers (root at
payload offset 0), a one-pass structural validator (`CheckBytes`), and a
two-phase writer; every offset, length, and range is bounds-checked before
any zero-copy access. `bool` fields are rejected by the derive (not every
byte pattern is a valid `bool`), and the supported field surface is
documented in the derive crate.

Two access modes:

- `MappedArchive::open` validates the envelope, schema, alignment, the
  complete relative-pointer graph, **and** the Merkle root once; `root()` is
  then zero-copy.
- `MappedArchive::open_header_only` validates only the envelope (O(1)) and
  has **no `root()`** — typed zero-copy access requires full validation or a
  verified proof. `proof_for` builds a self-contained `MerkleProof` for any
  payload byte range in O(log n), reading sibling hashes from the stored hash
  section. `verify()` recomputes the root from the carried blocks and
  siblings; `extract()` returns the verified bytes. A proof is self-contained,
  so a light client holding only the root can verify a range without the rest
  of the file.

Proof construction and verification are both O(log n) for a fixed range
width, which turns archive validation from a one-time cost into a per-access
cost. The tree is a complete binary tree padded to a power of two with
domain-separated hashes, so the root is a pure function of
`(payload, block_size)`; the default leaf is 4 KiB.

Opening any archive is `unsafe`: every process must keep the mapped file
immutable and untruncated for the mapping lifetime. Publish a new file and
atomically switch application references; never update a mapped file in
place. The schema ID is application-owned and must change after an
incompatible root layout change; it is an identity check, not cryptographic
authentication.

## Differential frames and IBLT reconciliation

The `reconcile` feature targets gossip/consensus transport, where the
receiver often already holds a baseline:

- `DeltaConfig::encode_delta` encodes `value - base` as a canonical ZigZag
  varint. The base is negotiated out of band (e.g., the hash of the last
  committed state) and never repeated.
- `DeltaTable` is a deterministic HPACK-style FIFO table.
  `DeltaConfig::encode_updates` emits a table reference for values already
  seen and a literal otherwise; both sides replay the identical
  insert/evict rule, so table state is a pure function of the update stream
  and is never transmitted.
- `Iblt` (invertible Bloom lookup table) reconciles **unordered sets**: two
  peers encode their sets, one side subtracts, and peeling recovers exactly
  `mine \ theirs` and `theirs \ mine`. It is a from-scratch implementation
  with three splitmix64 hash functions, `no_std` + `alloc`, no dependencies.

Decoding an undersized IBLT fails cleanly with `Error::Iblt` rather than
returning wrong data.

## Trust calculus

The `trust` feature lifts the configuration chain into an authentication
state machine:

- `TrustedConfig<C, Untrusted>` can deserialize, but only through the
  explicitly named `deserialize_untrusted`. There is no `From`/`Into` path to
  the authenticated state — the only transition is `authenticate`, which
  demands a `Verifier`.
- `TrustedConfig<C, Authenticated>` is the only configuration with the plain
  `deserialize` name. `deserialize_verified` wraps the result in `Verified`,
  whose only constructor is the authenticated path.
- `Session<C, Handshake, _>` has **no `recv` method**. Receiving only appears
  after `authenticate` moves the session to the authenticated state, and
  `close` moves it to the terminal `Closed` state which exposes nothing.
  "Deserialize unauthenticated data" is therefore unrepresentable, not just
  discouraged. The session is generic over any `Codec`, so it composes with
  every configuration in the chain.

`EncryptedConfig` (XChaCha20-Poly1305) is the built-in authenticating `Codec`;
application verifiers (MACs, signatures, handshake proofs) implement
`Verifier`.

## Streams

`serialize_into` writes directly to `std::io::Write`; `deserialize_from` reads
owned values from `std::io::Read`. Slice decoding is the only API that can
return borrowed values. Compression and encryption stream readers consume one
declared frame when passed `&mut R`, leaving later frames unread, and validate
header length relationships and configured limits before allocating the body.

## Security and audit

The security posture is: bounded everywhere, authenticated where it matters,
and honest about what is not protected.

- Every value starts with a one-byte type tag; `0xff` terminates containers.
- Floats preserve their IEEE 754 bit pattern; endianness is explicit.
- Variable integers reject marker 255 and non-minimal encodings.
- Compression and encryption frames validate versions, flags, lengths, and
  limits; decryption authenticates before deserializing.
- Entropy frames are accepted only when canonical (hash-free replay);
  truncation and substitution are caught except for the "corrupted frame is
  itself a valid frame for a different payload" case, which no
  non-authenticated scheme can distinguish.
- Archives carry a Merkle root; proofs and full opens verify it.
- Fingerprints are compatibility checks, not cryptographic authentication.

This pass's audit found and fixed four issues:

| Finding | Severity | Fix |
| ------- | -------- | --- |
| `delta` varint decoder could shift a final group past bit 127 on hostile input (debug panic / release wrap) | High | reject groups that overflow `u128` before shifting |
| header-only archive open did not validate hash-section length against tree geometry; a malformed file could drive `read_section_hash` out of bounds | High | validate `hash_len == (leaf_count - 1) * 32` at envelope parse time |
| `build` and `validate_archive` each computed the Merkle tree twice | Low | compute levels once, derive root from the top |
| `Session` was hard-wired to `Config` while `TrustedConfig` is generic over `Codec` | Low (coupling) | `Session<C: Codec, S, R>` with an explicit frame-length bound |

At every untrusted boundary: set realistic byte and collection limits, reject
trailing bytes unless an outer protocol owns them, authenticate adversarial
data, and treat decompression/deserialization errors as input failures.

Two bounds are worth calling out. Decompression is always bounded even without
a configured byte limit: the decompressed size is validated against the frame
header and capped at the crate-wide default under `with_no_limit` / the legacy
profile. The collection limit applies to sequence and map element counts;
strings are bounded by the byte limit.

## Verification

### Machine proofs (Kani)

`src/canonical.rs` is the single implementation of canonical little-endian
varints and ZigZag, shared by the encoder and decoder. The Kani harnesses in
`src/kani_proofs.rs` prove symbolically over the full `u128`/`i128` domain:

- Roundtrip: `decode(encode(v)) == v` for every `u128`; ZigZag in both
  directions.
- Boundedness: the encoded form is at most 17 bytes and uses the canonical
  (minimal) width.
- Canonical uniqueness: the roundtrip plus determinism of `decode` imply no
  two distinct values share one encoding.

```text
cargo kani -p rustbinary --harness canonical::varint_roundtrip
cargo kani -p rustbinary --harness canonical::zigzag_roundtrip
cargo kani -p rustbinary --harness canonical::zigzag_injective
cargo kani -p rustbinary --harness canonical::varint_bounded_and_minimal
cargo kani -p rustbinary --features projection --harness projection::leaf_count_is_complete_and_bounded
cargo kani -p rustbinary --features projection --harness projection::small_tree_proof_agrees_with_root
cargo kani -p rustbinary --features bounded --harness bounded::enforced_limits_respect_budget
cargo kani -p rustbinary --features bounded --harness bounded::depth_algebra_preserves_max
```

The projection harnesses prove the Merkle aggregation/recomputation protocol
is algebraically consistent for *any* hash values and any query subset, and
that `leaf_count` yields a complete tree that never more than doubles. The
bounded harnesses prove the derived enforced limits never exceed the budget
and that the documented allocation ceiling holds.

The archive hashes with the in-tree BLAKE3 implementation (`crate::hash`),
which is validated byte-for-byte against the official BLAKE3 test vectors.
Correctness of the Merkle *geometry* (domain separation, sibling extraction,
root recomputation) is this crate's responsibility and is covered by the
archive tests and the projection Kani harness for tree aggregation.

### Property tests (proptest)

`tests/entropy_roundtrip.rs` and `tests/canonical_proptest.rs` randomize the
public API: byte and uniform-alphabet roundtrips, per-byte corruption
properties (error, or a *different* payload — never the original), truncation
rejection, non-canonical-form rejection, and integer roundtrips.

`tests/projection_proptest.rs` randomizes the projection format's *shape*
(arbitrary field counts, payloads, and queries): every proof returns exactly
the queried projection with authentic bytes, any single header/field byte
tamper is detected against the trusted anchor, arbitrary bytes never panic,
and the stored root always matches the recomputed root.
`tests/bounded_proptest.rs` randomizes values through `decode_bounded`: the
result agrees with the plain codec, the bytes read are exact, the reported
allocation bound is sound, static types never exceed their compile-time
algebra, and the input-budget boundary is exact.

### Fuzzing (cargo-fuzz)

The `fuzz/` crate (standalone, not a workspace member) feeds arbitrary bytes
to both the compact and legacy decoders (must not panic, must classify every
error) and roundtrips structured random records.

```text
cargo +nightly fuzz run decode_arbitrary_bytes
cargo +nightly fuzz run decode_structured_roundtrip
```

### Benchmarks

Two benchmark surfaces live in `rustbinary-bench/` (a standalone crate, not a
workspace member):

- `cargo run --release` — the median-of-9 table comparing rustbinary against
  bincode 1, bincode 2, postcard, cbor4ii, and minicbor on shared datasets
  (small header, telemetry frame, bulk numerics, bulk strings), plus the
  standalone rANS byte codec and exact-alphabet enum coding.
- `cargo bench --bench lab` — the **fair benchmark lab** (criterion) across
  five workload classes: `homogeneous` (1024 identical records),
  `heterogeneous` (mixed enum variants), `borrowed` (zero-copy `&str`),
  `adversarial` (100k-element vector), and `schema-evolution` (V1 bytes
  decoded by a V2 type). Opponents are bincode 1, bincode 2, **bincode-next**,
  postcard, rkyv, and minicbor — every codec built by the same invocation
  with identical `[profile.release]` flags, criterion median statistics with
  calibration and `black_box`, encoded byte counts printed beside every
  pair.

The lab is the comparison this crate is willing to be judged by. It is
re-run on a fresh GitHub Actions runner on every push to `main`, and the
full report lives in
[`github_action_benchmark.md`](github_action_benchmark.md) — regenerated by
`.github/workflows/benchmark.yml`, never a stale screenshot. The most recent
local run (Windows 11, Intel i7-11850H, Rust 1.97, release profile) is below,
cut to the rows that matter; the file has every row.

**homogeneous** (1024 identical records; per-op medians):

| codec | encode | decode | bytes |
|---|---|---:|---:|---:|
| rustbinary | 120.5 µs | 272.6 µs | 51716 |
| bincode 1 | 3.2 µs | 2.0 µs | 14344 |
| bincode 2 | 10.1 µs | 4.2 µs | 13829 |
| bincode-next | 7.9 µs | 8.6 µs | 13829 |
| postcard | 22.5 µs | 9.1 µs | 13686 |
| rkyv | 5.7 µs | 445.1 ns | 24584 |

**schema-evolution** (V1 bytes decoded by a V2 type with an appended
`#[serde(default)]` field):

| codec | encode-v1 | decode-v1-as-v2 | bytes |
|---|---|---:|---:|---:|
| rustbinary | 306.8 ns | 217.3 ns | 68 |
| bincode 1 | 50.7 ns | error | 26 |
| bincode 2 | 182.3 ns | error | 18 |
| bincode-next | 173.7 ns | 71.3 ns | 18 |
| postcard | 185.7 ns | error | 17 |

Read these with the format identity in mind. rustbinary is a type-tagged,
self-describing format: on a giant homogeneous array it pays one tag per
value, so it loses on bytes and speed — and the table says so plainly. What
the tax buys shows up in `schema-evolution`: bincode 1, bincode 2 and
postcard cannot decode V1 bytes as a V2 type with an appended field (their
sequential format carries no field metadata, so the missing value errors
out); bincode-next tracks the field count and succeeds; rustbinary succeeds
through stable field IDs. The same honest framing holds elsewhere —
`borrowed` omits bincode 2 and bincode-next because their
`decode_from_slice` needs `T: for<'de> Deserialize<'de>`, which a borrowed
serde type cannot satisfy, and on the `adversarial` 100k-`Vec<u64>` workload
rustbinary decodes in ~3.3 ms where bincode 1 takes 88.6 µs. Those are real
costs of self-description, reported rather than hidden; the full per-codec
tables for all five workloads are in `github_action_benchmark.md`.

Numbers vary by machine and build; the benchmark crate exists so the
comparison can be re-run, not asserted.

### Full verification commands

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets --all-features
cargo test --workspace --all-features --release
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
```

### Examples

| Example                                                   | Covers                                   | Command                                                                                         |
| --------------------------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------- |
| [complete.rs](examples/complete.rs)                       | end-to-end, all features                 | `cargo run --example complete --all-features`                                                   |
| [core_codec.rs](examples/core_codec.rs)                   | bounded core, buffers, borrowing, errors | `cargo run --example core_codec`                                                                |
| [zero_copy.rs](examples/zero_copy.rs)                     | nested borrowing and pointer proof       | `cargo run --example zero_copy`                                                                 |
| [entropy.rs](examples/entropy.rs)                         | schema-driven rANS coding                | `cargo run --example entropy --features entropy,derive`                                         |
| [merkle_archive.rs](examples/merkle_archive.rs)           | Merkle proofs, header-only access        | `cargo run --example merkle_archive --features archive`                                         |
| [mmap_archive.rs](examples/mmap_archive.rs)               | validated mmap object graph              | `cargo run --example mmap_archive --features archive`                                           |
| [delta_sync.rs](examples/delta_sync.rs)                   | delta frames + IBLT reconciliation       | `cargo run --example delta_sync --features reconcile`                                           |
| [trust_session.rs](examples/trust_session.rs)             | trust calculus + session state machine   | `cargo run --example trust_session --features trust`                                            |
| [adaptive_zero_alloc.rs](examples/adaptive_zero_alloc.rs) | adaptive decisions and caller buffers    | `cargo run --example adaptive_zero_alloc --features adaptive`                                   |
| [secure_pipeline.rs](examples/secure_pipeline.rs)         | deterministic CBOR, compression, AEAD    | `cargo run --example secure_pipeline --features cbor,compression,encryption`                    |
| [schema_evolution.rs](examples/schema_evolution.rs)       | bidirectional schema V1/V2               | `cargo run --example schema_evolution --features schema-evolution`                              |
| [parallel_batch.rs](examples/parallel_batch.rs)           | ordered multi-worker batches             | `cargo run --example parallel_batch --features parallel`                                        |
| [metadata.rs](examples/metadata.rs)                       | fingerprint, reflection, bounds, packing | `cargo run --example metadata --features bit-packing,derive,fingerprint,reflection,static-size` |

## docs.rs and compatibility

The package metadata builds docs.rs with all features. Versioned wrappers
reject unknown versions and reserved flags instead of guessing. Before 1.0,
wire changes may occur between minor releases and must be called out in
release notes. Long-lived deployments should pin the version, record the
complete configuration, keep golden vectors, and use explicit schema IDs. Two
format families exist and are versioned independently: the stream format
(`RBAN` entropy frames, `RBZ1`/`RBX1` pipeline frames) and the archive storage
format (`RBARC004`). A change to one never silently changes the other.

## Non-goals

- Casting arbitrary Rust structs directly from serialized memory in the
  **stream** codec (the archive feature is a separate, explicitly validated
  storage format with its own envelope and Merkle root).
- Mutable shared-memory object graphs or in-place updates to mapped files.
- Wrapping blocking I/O in a misleading async facade.
- Automatically sorting randomized maps in the core profile.
- Claiming AVX-512/SVE acceleration without tested kernels.
- Replacing application key management, authorization, or schema governance.
- Substituting the tagged stream format with a schemaless compact format:
  the format identity is fixed, and size-sensitive paths use the entropy,
  delta, or archive layers instead.
- Claiming cryptographic strength for FNV-1a fingerprints or for the
  un-keyed replay check; authenticated integrity belongs to the AEAD/trust
  layer.

## License

RustBinary is licensed under the [Apache License, Version 2.0](LICENSE). You
may use, reproduce, modify, and redistribute the project under the terms of
that license. Redistributions must preserve the copyright notice, license
text, and required attribution notices. Changes to the source should be
identified clearly, and the Apache License patent terms and disclaimer apply.

The complete legal text is in [`LICENSE`](LICENSE). This project is provided
without warranties or conditions of any kind.
