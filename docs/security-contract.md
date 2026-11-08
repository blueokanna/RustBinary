# Security contract and nextjson 0.1.5 migration

## Parser limits

The self-describing decoder and probe share their token reader and skip grammar.
They enforce byte, per-container entry, global token-visit and nesting limits.
The cumulative byte-read budget counts speculative rereads; global visits count
object keys, container starts and skipped values, but not terminators. Restoring
a checkpoint does not restore either global budget. Resource exhaustion remains
an error even if a custom deserializer catches it and tries to return success.

`Config::standard()` defaults to 64 MiB consumed bytes, 64 MiB cumulative reads,
one million visits, one million entries per container, and depth 128. These
dimensions are independent. `with_no_limit()` only removes the consumed-byte
limit; `with_no_collection_limit()` only removes the per-container limit.
`Config::legacy()` disables byte, collection, visit and read limits but retains
the depth ceiling. Use explicit policies for untrusted input.

The global visit/read policies are specific to the self-describing decoder and
probe. Compact, CBOR, archive, compression and application-level work have
separate implementations and do not inherit these counters. CBOR applies its
configured depth and collection limits to unknown fields as well as decoded
fields. rANS checks both frame bytes and decoded storage against the byte
limit, and checks symbol counts against the collection limit before allocation;
a sequence symbol occupies four decoded bytes, while a byte stream uses one.
Compact depth accounting covers length-prefixed collections; fixed schema
arrays, tuples and struct fields do not add wire-container levels.

## Allocation and custom implementations

The previous formula `depth * collection_limit` did not bound total elements.
For example, N sibling vectors of N elements already contain N squared inner
elements at depth two. A size-of-element calculation also omits vector spare
capacity, simultaneous old/new buffers during growth, boxes, allocator metadata
and unrelated work in custom traits.

`DecodeBounded` is trusted schema metadata. Its constants and `max_alloc` are
admission estimates, not allocator instrumentation. `ResourceUse::alloc_estimate`
must never be used as a certified heap ceiling. Successful bounded decoding
reports `alloc_estimate <= max_alloc`: dynamic estimates reserve input bytes
first, then charge weighted token visits; static estimates use `MAX_ALLOC`. The returned `read`, `work_read`
and `values` measure parser activity; `depth_bound` reports the configured cap.
`Decoded::map` retains the original decode's metrics, not the closure's costs.
Derived schemas are subject to the same boundary when fields or nextjson
attributes change decoding behavior. A process-wide hard ceiling needs a
bounded allocator or process isolation supplied by the application.

## Integrity and encoding

AEAD authenticates ciphertext and associated data under a secret key; it does
not supply authorization, key rotation, sender identity or replay prevention.
XChaCha20 uses a 192-bit nonce and a 256-bit HChaCha20 subkey. RFC 8439 specifies
ChaCha20-Poly1305 with a 96-bit nonce; the extension is specified separately in
the XChaCha Internet-Draft. Payload length is checked before allocation to
prevent reuse of a 32-bit ChaCha block counter.

Merkle proofs require an externally authenticated anchor and collision
resistance. `verify` authenticates supplied membership claims; `verify_query`
also matches the caller's complete query. There are no absence proofs. Opaque
payload semantics and omitted fields in external storage are not validated.
`verify_untrusted` establishes only internal consistency.

rANS replay tests canonical representation under a chosen model. A different
valid codeword can pass. It supplies neither authentication nor a quantified
corruption detection probability. Raw fallback and forced coded mode are both
unsuitable as an integrity boundary by themselves.

Canonical marker-varints do not make every Rust value uniquely encoded. Map
order, schema choices, target-type conversions and opaque payloads remain
relevant. CBOR's `with_deterministic_encoding` currently provides stable map
ordering, not RFC 8949 section 4.2 deterministic CBOR: indefinite containers and
non-minimal float widths remain. Its intermediate value tree is not heap-budgeted.
LZ77 frames are not Zstandard-compatible; removing a zstd dependency does not
establish equivalent compression capabilities.

## Test evidence

| Evidence | Source and scope |
| --- | --- |
| BLAKE3 known answers | [Upstream vector corpus](https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json), vendored in `tests/vectors/blake3.json`; all 35 input lengths, first 32 bytes of unkeyed hash output, one-shot and incremental feeds. Keyed mode, derive-key and XOF are not implemented or certified by this test. |
| ChaCha20 / Poly1305 | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html), sections 2.3.2, 2.4.2, 2.5.2 and 2.8.2; selected primitive and AEAD examples, not all appendix edge vectors. |
| XChaCha20-Poly1305 | [draft-irtf-cfrg-xchacha-03](https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt), Appendix A.3.1; complete encrypt/decrypt known answer through the implementation's public primitive. This document is an Internet-Draft, not an RFC. |
| Pipeline fixture | `tests/golden_vectors.rs::pipeline_encryption_decoder_vector_is_stable`; fixed-frame decoding compatibility. The historical generator is unknown. |
| Kani | Harness source for arithmetic and small-tree aggregation; not an end-to-end proof, allocator proof or record of execution. |

The vendored BLAKE3 corpus was retrieved on 2026-11-08. Its SHA-256 is
`dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624`.
Expected outputs are upstream data, not generated by the implementation under test.
Roundtrips and streaming equivalence supplement known answers; they cannot
independently validate a shared cryptographic mistake. No independent security
audit, side-channel assessment or universal absence of bugs is claimed.

## Migration

- Archive mirrors, `ArchivedString` and `ArchivedVec` no longer implement
  `Copy`/`Clone`: their relative pointers are valid only at their original
  address. Keep borrowed views, or copy out application-owned field values.
- Manual `CheckBytes` implementations now require `unsafe impl` and must prove
  complete layout, alignment, reachable data validity and immutable lifetime
  guarantees. Derives supply this implementation automatically.
- `ArchiveSerializer::write_string_at`, `write_vec_at` and `patch_ptr` now return
  `Result`; propagate failures instead of truncating lengths or relative offsets.
- Generated archive validation is capped at 128 active validation steps and
  one million visits per outermost call (nested-vector helpers also count as
  steps). These limits protect recursive and zero-sized schemas; they are not
  allocator instrumentation or limits on custom validator code.
- Zero-copy archive access requires a little-endian target and checks actual
  buffer alignment for vector elements as well as the root. Nested structs now
  include their C-layout trailing padding; archives affected by the old missing
  padding or mixed-up nested-vector pointers must be rebuilt from source values.
- nextjson is now 0.1.5. Remove `nextjson/std`; its crate has no such feature.
- Use `BTreeMap` or a local newtype for `std::collections::HashMap` values.
- The workspace uses a path plus version dependency for `rustbinary-derive`.
- Rename `ResourceUse::alloc_bound` to `alloc_estimate` and `work_bound` to
  `work_read`. Review security decisions using the old fields.
- Prefer `verify_query` when the verifier expects a particular set of fields.
  Verification now rejects unused and out-of-range sibling nodes.
- Dynamic allocation admission now includes input bytes in `max_alloc`.
  Budgets that previously covered only token weights may need adjustment.
- Entropy byte/sequence APIs now enforce decoded-size and symbol-count policies,
  including on encoding. Previously accepted oversized values are rejected.
- Tight parser budgets may reject inputs accepted previously, especially
  nested breadth, unknown fields and speculative decoding. Encoded bytes are
  unchanged by these parser fixes.

## Local validation (2026-11-08)

After the archive follow-up, Windows passed 312 all-target/all-feature tests.
Rust 1.78 and release runs passed 320 tests each, including doctests. Formatting,
Clippy and rustdoc with warnings denied passed. The archive regression suite
now includes ten tests for skeleton truncation/padding, nested position queues,
actual vector alignment, checked offsets/counts and bounded recursive validation.
Five compile-fail doctests reject copied/cloned relative-pointer views and safe
implementations of the unsafe validation contract. Earlier no-default-feature
runs also passed for compact, CBOR and entropy individually. The follow-up reran
and passed no-default-feature tests for core, archive, bounded and projection.

Native Windows libFuzzer execution now works through `cargo +nightly fuzz run`
with the MSVC ASan runtime on PATH. The earlier LNK1561 failure came from an
ordinary `cargo run` attempt. The latest successful campaigns used cargo-fuzz
0.13.2, rustc `1.102.0-nightly (f5cedb83a 2026-11-07)`, AddressSanitizer, seed
101, a maximum input length of 8192, and a 60-second time setting per target:

| Target | Executions | Reported seconds |
| --- | ---: | ---: |
| `decode_arbitrary_bytes` | 187,636 | 61 |
| `decode_compact_arbitrary` | 3,594,005 | 61 |
| `decode_structured_roundtrip` | 267,657 | 61 |
| `decode_cbor_arbitrary` | 492,251 | 61 |
| `decode_frames_arbitrary` | 302,297 | 61 |

These five completed runs total 4,843,846 executions. Logs and JSON reports
are in the local `target/fuzz-results/` directory. See the
[fuzz runner](../fuzz/README.md) for commands and reproducibility limits.
Windows and Linux CI campaigns are configured; Linux execution was not observed
in this local session.

Fuzzing found a compact float-vector panic and an rANS oversized allocation.
Both were fixed and rerun. Regression tests also cover the analogous signed-byte
vector panic, partial-array cleanup on errors and unwinding, CBOR head/bignum/
UTF-8/skip validation, bounded admission, probe collection limits and allocations
triggered by truncated collection headers. The frame harness itself was adjusted
to keep generated valid payloads within its declared collection policy.

Kani harnesses and an independent security audit were not run. These short
campaigns and regression checks do not establish universal absence of bugs,
constant-time behavior, or a hard process-memory ceiling.
