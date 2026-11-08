# RustBinary

RustBinary is a binary codec built on [nextjson](https://crates.io/crates/nextjson),
with self-describing and schema-guided profiles, parser limits, optional
compression, authenticated frames and Merkle proofs. It uses `no_std` + `alloc`;
the default `std` feature adds I/O and platform facilities. The declared MSRV
is Rust 1.78; the CI configuration includes an MSRV job.

Parser limits are not a process-memory sandbox. The precise guarantees and
migration notes are in [the security contract](docs/security-contract.md).

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

The runtime depends on nextjson 0.1.5; derive support adds proc-macro dependencies.
The workspace uses the local `rustbinary-derive` so tests exercise the code being
edited. nextjson 0.1.5 has no `std` feature and no direct `std::collections::HashMap`
implementation: use `BTreeMap` or an application newtype implementing nextjson's traits.

BLAKE3, XChaCha20-Poly1305, OS randomness, key erasure, LZ77 and mmap support
are maintained in this repository. Fewer dependencies transfer maintenance,
platform testing and security review to this project; they do not remove those duties.
The LZ77 codec is a proprietary RustBinary format, not Zstandard-compatible;
no equivalent compression ratio, speed, dictionaries or interoperability is claimed.

Crypto checks cover RFC 8439 ChaCha20/Poly1305 examples, the XChaCha20-Poly1305
Internet-Draft vector, and the upstream BLAKE3 unkeyed 256-bit vectors.
See [vector provenance and coverage](docs/security-contract.md#test-evidence).
The pipeline golden fixture checks decoding compatibility for that fixture;
its historical producer was not recorded, so it is not evidence of comprehensive
compatibility with an earlier third-party implementation. No independent
implementation-level security audit is claimed.

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
| rANS entropy coding         | Implemented    | from-scratch static-model coder; canonical replay checks                              |
| SIMD                        | Hot scans only | runtime AVX2/SSE2/NEON with scalar fallback; AVX-512/SVE/SME detected but unused            |
| Zero-allocation codec paths | Implemented    | exact-size output and caller-owned buffers                                                  |
| Borrowed zero-copy decoding | Implemented    | nested `&str` fields point into the input frame                                             |
| Bit packing                 | Implemented    | `BitPacked` derive, checked widths, canonical zero padding                                  |
| Schema fingerprinting       | Implemented    | structural hash including codec configuration (FNV-1a, **not** cryptographic)               |
| Compile-time bounds         | Implemented    | `StaticSize::{MAX_SIZE, PACKED_MAX_BITS, PACKED_MAX_SIZE}`                                  |
| RFC 8949 CBOR               | Implemented    | crate-owned streaming CBOR codec (no value tree); optional stable map ordering           |
| Schema evolution            | Implemented    | stable field IDs, versions, defaults, unknown-field skipping                                |
| Compression                 | Implemented    | in-tree LZ77 (hash-chained matches); raw data is kept when it is smaller  |
| Encryption                  | Implemented    | XChaCha20-Poly1305, random 192-bit nonce, authenticated header                              |
| Parallel serialization      | Implemented    | ordered batch frames, scheduling-independent output                                         |
| Runtime reflection          | Implemented    | allocation-free compile-time metadata (`Reflect`), per-field symbol alphabets               |
| Differential frames         | Implemented    | baseline-relative integer deltas + deterministic HPACK-style dynamic tables                 |
| IBLT set reconciliation     | Implemented    | from-scratch invertible Bloom lookup tables (Goodrich and Mitzenmacher)                     |
| Trust calculus              | Implemented    | type-level authentication state machine; unauthenticated receive is unrepresentable         |
| Merkle archives             | Implemented    | in-tree BLAKE3 tree, O(log n) proofs, header-only open                                      |
| Projectable self-auth. records | Implemented | trusted-anchor membership, exact query checks, schema-version binding      |
| Resource-bounded decoding   | Implemented    | parser counters and schema estimates; no hard heap ceiling          |
| Exact frame probing         | Implemented    | allocation-free `Config::probe`: exact bytes/containers/elements/depth of one value, checks parser limits |
| Configurable depth limit    | Implemented    | `Config::with_depth_limit` caps nesting on encode and decode                              |
| Formal verification         | Kani harnesses | varint/ZigZag core + projection tree geometry + budget-limit algebra                        |
| `no_std` first               | Implemented    | the crate is unconditionally `no_std` + `alloc`; `std` is an opt-in feature                  |
| `no_std` layers             | Implemented    | compact, adaptive, entropy, reconcile, evolution, projection, bounded, probe, CBOR, trust calculus all build without `std` |

## Installation

```toml
[dependencies]
rustbinary = "0.1"
# Match the nextjson API used by this release.
nextjson = { version = "0.1.5", features = ["derive"] }
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
both directions, and Kani harnesses check roundtrip, boundedness, and canonical
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

Replay checks whether decoding and re-encoding with the same model reproduces
the frame. This rejects noncanonical representations. Another valid codeword
can decode to different data and pass replay: there is no quantified accidental
corruption detection rate and no authentication guarantee. Raw fallback checks
framing and length only. Disabling raw fallback does not create an integrity boundary.
Use a trusted digest, MAC, AEAD or authenticated transport according to the threat model.

Replay is enabled by default and adds an encoding pass. The API name
`without_replay_verification()` refers to this canonicality check, not message freshness.

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

Projection proofs bind disclosed field bytes to an externally trusted Merkle root.
`verify(proof, anchor, schema_version)` verifies membership of the fields supplied
by the proof. `verify_query(proof, anchor, schema_version, query)` additionally
requires exactly the caller's requested IDs; missing and extra fields are rejected.
The format provides no absence proof. `verify_untrusted` checks internal consistency
only: a sender can replace both content and root.

The argument assumes collision resistance of BLAKE3, an authenticated anchor
and a canonical source record. Hashing is not mathematical injectivity. A valid
partial proof neither reads nor certifies the current contents of an omitted
field in a separate file. It also does not establish the semantic validity of
opaque field payloads or application schema rules.

For n fields and k disclosed fields, sibling count is O(k log(n/k) + k).
Verification hashes the disclosed payload bytes and the required tree nodes;
its BTreeMap bookkeeping adds logarithmic factors. Building a proof currently
scans the record and builds a tree in O(n) space, plus payload processing.

## Resource-bounded decoding (cost algebra)

`decode_bounded` enforces parser limits for consumed bytes, cumulative byte
reads, global token visits, per-container entries and nesting depth. Global
visits include object keys, skipped fields and speculative retries. Depth alone
cannot constrain breadth: a depth-two collection can contain arbitrarily many
sibling collections, up to the separate input and element policies.

`Budget::with_max_values` controls global visits. `max_work` counts parser byte
reads, including backtracking; it does not meter arbitrary trait code or CPU time.
`ResourceUse` reports `read`, `work_read`, `values` and the enforced `depth_bound`.

`max_alloc` caps the admission estimate: dynamic types charge input bytes plus
weighted token visits; static types use their schema estimate. A successful
decode reports `alloc_estimate <= max_alloc`. This is not an allocation bound. Collection capacity,
reallocation peaks, boxes, custom deserializers and allocator overhead invalidate
the old depth-times-collection-limit formula. `DecodeBounded` constants are
schema estimates supplied by trusted implementations, not proofs of allocations.
Even derived metadata must be considered alongside nextjson attributes and
custom field implementations. Applications needing a hard memory ceiling must
supply allocator or process isolation.

This changes the public metrics: migrate `alloc_bound` to `alloc_estimate`
and `work_bound` to `work_read`, and do not use the former as a security assertion.
The self-describing Config also exposes `with_value_limit` and
`with_decode_work_limit`; these two policies do not apply to compact, CBOR,
archive or compression internals.

## Frame probing (exact preflight)

A normal decode materializes the value; a skip discards it. `Config::probe`
occupies the space in between: it walks the wire format and reports the
**exact** structural footprint of the next value — byte length, container
count, element count, and maximum nesting depth — with zero allocation and
without ever building a value.

The probe shares the decoder's token reader: it reads with the same
boundary semantics, honors the same byte/collection/depth limits, and rejects
the same malformed input (invalid tags, non-canonical varints, truncation,
trailing bytes). A successful probe validates wire structure, not whether an
arbitrary target type accepts it. Typed decoding may also backtrack and consume
more work. Probe metrics are tested against encoded fixtures.

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
encrypt. The CBOR ordering option sorts map keys; it does not implement RFC 8949 section 4.2 deterministic encoding. Compression
runs only above a size threshold and stores the in-tree LZ77 output only when
it is strictly smaller. Encryption authenticates the full frame header
(algorithm, nonce, lengths) as AEAD associated data and uses a fresh 192-bit
nonce each time, so ciphertext is intentionally nondeterministic.

- CBOR is the crate's own streaming RFC 8949 codec (`src/cbor_codec.rs`):
  values encode and decode directly between `T` and the bytes with no
  intermediate value tree and no JSON text round-trip. Collection capacity,
  transient allocations and custom traits still affect peak memory. Definite- and
  indefinite-length containers, bignum tags 2/3, half-precision floats, and
  native byte strings are supported; byte and collection limits are enforced
  inline. Stable map ordering is the one explicit exception
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

Archived views are borrowed in place and do not implement `Copy` or `Clone`.
Manual `CheckBytes` implementations are unsafe contracts. See the
[security and migration notes](docs/security-contract.md#migration) for archive
validation limits, little-endian requirements and serializer API changes.

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

`src/kani_proofs.rs` contains harnesses for varint/ZigZag arithmetic, small
Merkle-tree aggregation and budget-limit arithmetic. Harness source is not a
record of a successful proof run. These harnesses do not verify BLAKE3 collision
resistance, real heap allocations, arbitrary schemas or the complete decoder.
Run Kani separately in a supported environment and retain its results.

### Test evidence

Unit and property tests exercise roundtrips, malformed inputs, exact parser
boundaries, projection membership and query matching. They do not prove absence
of bugs. The crypto corpus and its coverage are documented in
[the security contract](docs/security-contract.md#test-evidence); local format
golden vectors, independent known-answer vectors, fuzzing and formal harnesses
serve different purposes and are not interchangeable.

### Fuzzing (cargo-fuzz)

Five targets cover self-describing, compact and CBOR decoders, structured
roundtrips, and entropy/projection frames. Windows and Linux CI run ASan smoke
campaigns. The [runner and setup instructions](fuzz/README.md) explain native
Windows support, limits, logs and failure reproduction.

```powershell
./scripts/fuzz.ps1 -Seconds 120
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
