# Executable Examples

Every program is compiled by `cargo test --all-targets --all-features` and is
also intended to be run directly. Assertions are part of each example: a zero
exit status means its success and failure-path contracts both held.

| Program | Product layer | Required command |
| --- | --- | --- |
| `core_codec` | Core | `cargo run --example core_codec` |
| `zero_copy` | Core | `cargo run --example zero_copy` |
| `adaptive_zero_alloc` | Protocol | `cargo run --example adaptive_zero_alloc --features adaptive` |
| `metadata` | Protocol | `cargo run --example metadata --features bit-packing,derive,fingerprint,reflection,static-size` |
| `schema_evolution` | Protocol | `cargo run --example schema_evolution --features schema-evolution` |
| `secure_pipeline` | Pipeline | `cargo run --example secure_pipeline --features cbor,compression,encryption` |
| `parallel_batch` | Pipeline | `cargo run --example parallel_batch --features parallel` |
| `complete` | All layers | `cargo run --example complete --all-features` |

The encryption example uses fixed in-process test keys only so it can execute
without external infrastructure. Its comments explicitly require KMS/HSM or a
protected secret store for production key material. No example claims that a
test key, fingerprint, compatibility tag, or compression frame provides an
application security policy.
