# Fair benchmark lab protocol

This document defines how to run `rustbinary-bench`'s criterion lab
(`cargo bench --bench lab`) so that measurements are comparable and
reproducible. The lab compares rustbinary against bincode 1, bincode 2,
bincode-next, postcard, rkyv, and minicbor.

## Opponents and their status

| opponent       | crate / version          | serde-based | notes                                            |
| -------------- | ------------------------ | ----------- | ------------------------------------------------ |
| bincode 1      | `bincode` 1.3.3          | yes         | RustSec marks it **unmaintained** (RUSTSEC-2025-0141) |
| bincode 2      | `bincode` 2.0.1          | yes         | RustSec marks it **unmaintained** (RUSTSEC-2025-0141) |
| bincode-next   | `bincode-next` 3.1.1     | yes         | the maintained continuation of the bincode line  |
| postcard       | `postcard` 1.x           | yes         | compact, no-length-prefix format                 |
| rkyv           | `rkyv` 0.8               | no          | zero-copy archives (homogeneous/borrowed only)   |
| minicbor       | `minicbor` 2.x           | no          | CBOR, length-prefixed                            |

RustSec's "unmaintained" notices are informational, not vulnerabilities:
the bincode project's development moved to the `bincode-next` crate. We keep
both old versions in the lab because real deployments still ship them and the
comparison is exactly what those deployments are choosing between.

## Workload classes

| Group              | Input                          | What it measures                     |
| ------------------ | ------------------------------ | ------------------------------------ |
| `homogeneous`      | 1024 identical small records   | throughput-shaped bulk encode/decode |
| `heterogeneous`    | 1024 mixed enum variants       | tag-dispatch cost                    |
| `borrowed`         | one record, decode into `&str` | zero-copy decode cost                |
| `adversarial`      | 100 000-element `Vec<u64>`     | per-element worst case               |
| `schema-evolution` | V1 bytes decoded by a V2 type  | forward-compatibility cost           |

Every row reports encode ns/op, decode ns/op, and encoded bytes. The three
numbers are in tension; the report shows the trade-off, not a winner.

## Protocol

1. **Same machine, same toolchain, same flags.** Run all codecs in one
   `cargo bench` invocation. `[profile.release]` (`lto = "thin"`,
   `codegen-units = 1`, `opt-level = 3`) is identical for every dependency.
   Record the `rustc --version` and CPU model in the report.
2. **Median statistics with calibration.** Criterion subtracts a calibrated
   empty-loop baseline, filters outliers, and reports the median with a
   confidence interval. `black_box` is applied to every payload and result.
3. **Cache regime.** Criterion's measurement loop re-reads the same buffer,
   so decode numbers are _warm-cache_. The encoded byte count is printed
   beside every pair: on a cold cache, the smaller buffers win more. If a
   workload's cold-cache behavior matters, measure it separately (e.g. with
   `perf stat -e cache-misses` on a single pass).
4. **CPU pinning (Linux).** Pin the benchmark to one physical core so
   frequency scaling and migration noise are bounded:

   ```text
   taskset -c 2 cargo bench --bench lab
   ```

   For the pinned, counter-backed numbers:

   ```text
   taskset -c 2 perf stat -e cycles,instructions,cache-misses,cache-references \
     cargo bench --bench lab -- homogeneous/rustbinary/decode
   ```

5. **Perf counters.** `perf stat` gives the cycle and cache-miss numbers that
   wall time alone cannot separate (a codec that wins on ns/op but stalls on
   cache misses is a different product). Use the single-bench filters shown
   above; run each three times and report the median of the three runs.
6. **Variance check.** After the first full run, re-run one group
   (e.g. `homogeneous`) three times; if the medians move by more than ~5%,
   the machine is noisy — fix the environment (disable turbo, pin, close
   background load) before trusting any number.

## Known-honest gaps

- **bincode 2, bincode-next and `borrowed`**: both implement
  `decode_from_slice` with a `T: for<'de> Deserialize<'de>` bound, which a
  borrowed serde type cannot satisfy. They are intentionally absent from that
  group; the absence is commented in the source.
- **rkyv and `borrowed`**: rkyv's zero-copy borrow path needs archived
  reference types; it appears only in `homogeneous`, where it is the
  zero-copy baseline.
- **`schema-evolution` and the sequential serde codecs**: decoding V1 bytes
  as a V2 type with an appended `#[serde(default)]` field requires the
  decoder to know a field is missing. bincode 1, bincode 2 and postcard
  cannot do it (their sequential format carries no field metadata, so the
  missing value errors out); bincode-next tracks the field count and
  succeeds; rustbinary succeeds via stable field IDs. The lab probes each
  codec once and emits `BENCH_EVO_FAIL` for the ones that error, so the
  report shows `error (see notes)` instead of a fabricated timing.
- **rustbinary is a protocol format**: it is type-tagged and self-describing.
  On `homogeneous` and `adversarial` it will lose to schemaless codecs on
  bytes and speed; that is the measured, intended trade-off for
  self-description, borrowing, and bounded decoding. The `schema-evolution`
  and `heterogeneous` groups are where that tax buys something.

## Automated report

The GitHub Actions workflow `.github/workflows/benchmark.yml` runs this lab on
a fresh `ubuntu-latest` runner and produces `github_action_benchmark.md` from
the raw criterion output. The lab emits machine-readable `BENCH_BYTES` lines
(the encoded byte counts), and `scripts/bench_to_md.py` merges them with
criterion's median timings into the report tables.

