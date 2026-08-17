# Benchmark lab (criterion)

| field | value |
| --- | --- |
| OS | Linux 6.17.0-1022-azure |
| CPU | AMD EPYC 7763 64-Core Processor |
| Rust | rustc 1.97.1 (8bab26f4f 2026-07-14) |
| Run | https://github.com/blueokanna/RustBinary/actions/runs/32000179808 |
| Date (UTC) | 2026-08-17T14:04:33+08:00 |

## homogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 13.1 µs | 13829 |
| bincode-next | decode | 6.6 µs | 13829 |
| bincode1 | encode | 9.8 µs | 14344 |
| bincode1 | decode | 2.1 µs | 14344 |
| bincode2 | encode | 15.4 µs | 13829 |
| bincode2 | decode | 5.0 µs | 13829 |
| minicbor | encode | 15.0 µs | 14795 |
| minicbor | decode | 30.4 µs | 14795 |
| postcard | encode | 20.9 µs | 13686 |
| postcard | decode | 8.1 µs | 13686 |
| rkyv | encode | 11.9 µs | 24584 |
| rkyv | decode | 643.4 ns | 24584 |
| rustbinary | encode | 134.0 µs | 51716 |
| rustbinary | decode | 318.9 µs | 51716 |

## heterogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 7.3 µs | 7687 |
| bincode-next | decode | 17.5 µs | 7687 |
| bincode1 | encode | 9.0 µs | 14344 |
| bincode1 | decode | 15.7 µs | 14344 |
| bincode2 | encode | 7.5 µs | 7687 |
| bincode2 | decode | 16.6 µs | 7687 |
| minicbor | encode | 12.1 µs | 10103 |
| minicbor | decode | 34.7 µs | 10103 |
| postcard | encode | 8.9 µs | 7362 |
| postcard | decode | 17.3 µs | 7362 |
| rustbinary | encode | 57.3 µs | 23046 |
| rustbinary | decode | 148.8 µs | 23046 |

## borrowed

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode1 | encode | 24.3 ns | 66 |
| bincode1 | decode | 18.4 ns | 66 |
| minicbor | encode | 87.5 ns | 48 |
| minicbor | decode | 35.9 ns | 48 |
| postcard | encode | 95.7 ns | 45 |
| postcard | decode | 27.6 ns | 45 |
| rustbinary | encode | 205.4 ns | 66 |
| rustbinary | decode | 240.7 ns | 66 |

## adversarial

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 321.5 µs | 499997 |
| bincode-next | decode | 469.3 µs | 499997 |
| bincode1 | encode | 68.0 µs | 800008 |
| bincode1 | decode | 95.3 µs | 800008 |
| bincode2 | encode | 342.7 µs | 499997 |
| bincode2 | decode | 313.0 µs | 499997 |
| minicbor | encode | 278.0 µs | 499997 |
| minicbor | decode | 569.7 µs | 499997 |
| postcard | encode | 795.1 µs | 491367 |
| postcard | decode | 249.9 µs | 491367 |
| rustbinary | encode | 1.5 ms | 599994 |
| rustbinary | decode | 3.4 ms | 599994 |

## schema-evolution

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode-v1 | 63.2 ns | 18 |
| bincode-next | decode-v1-as-v2 | 56.7 ns | 18 |
| bincode1 | encode-v1 | 25.3 ns | 26 |
| bincode1 | decode-v1-as-v2 | error (see notes) | 26 |
| bincode2 | encode-v1 | 67.2 ns | 18 |
| bincode2 | decode-v1-as-v2 | error (see notes) | 18 |
| postcard | encode-v1 | 72.7 ns | 17 |
| postcard | decode-v1-as-v2 | error (see notes) | 17 |
| rustbinary | encode-v1 | 148.8 ns | 68 |
| rustbinary | decode-v1-as-v2 | 182.2 ns | 68 |

## Notes

- Measured by [criterion](https://github.com/bheisler/criterion.rs) (median of many samples, outlier-filtered, `black_box` on every payload); lower is better on time and bytes.

- **borrowed**: bincode 2 and bincode-next are absent because their `decode_from_slice` requires `T: for<'de> Deserialize<'de>`, which a borrowed serde type cannot satisfy (a real limitation of those opponents, reported rather than hidden).

- **schema-evolution**: the serde codecs are probed for the `V1 bytes -> V2 type with an appended #[serde(default)] field` case. bincode 1, bincode 2 and postcard fail it (their sequential format carries no field metadata, so the missing value errors); bincode-next tracks the field count and succeeds. rustbinary succeeds via stable field IDs. Rows marked `error (see notes)` are that failure, reported rather than hidden.

- Numbers vary by machine and load; the `BENCH_RUN_ID` header above identifies the exact run that produced this file.

