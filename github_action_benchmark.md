# Benchmark lab (criterion)

| field | value |
| --- | --- |
| OS | Linux 6.17.0-1022-azure |
| CPU | AMD EPYC 7763 64-Core Processor |
| Rust | rustc 1.98.0 (88d9e12ae 2026-08-18) |
| Run | https://github.com/blueokanna/RustBinary/actions/runs/33306828690 |
| Date (UTC) | 2026-08-30T18:34:50+08:00 |

## homogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 13.2 µs | 13829 |
| bincode-next | decode | 6.5 µs | 13829 |
| bincode1 | encode | 9.9 µs | 14344 |
| bincode1 | decode | 2.1 µs | 14344 |
| bincode2 | encode | 15.3 µs | 13829 |
| bincode2 | decode | 5.0 µs | 13829 |
| minicbor | encode | 15.4 µs | 14795 |
| minicbor | decode | 30.4 µs | 14795 |
| postcard | encode | 23.7 µs | 13686 |
| postcard | decode | 8.1 µs | 13686 |
| rkyv | encode | 12.4 µs | 24584 |
| rkyv | decode | 327.4 ns | 24584 |
| rustbinary | encode | 122.7 µs | 51716 |
| rustbinary | decode | 198.3 µs | 51716 |
| rustbinary compact | encode | 17.7 µs | 13829 |
| rustbinary compact | decode | 9.6 µs | 13829 |

## heterogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 7.4 µs | 7687 |
| bincode-next | decode | 17.4 µs | 7687 |
| bincode1 | encode | 8.5 µs | 14344 |
| bincode1 | decode | 15.6 µs | 14344 |
| bincode2 | encode | 7.5 µs | 7687 |
| bincode2 | decode | 16.2 µs | 7687 |
| minicbor | encode | 12.5 µs | 10103 |
| minicbor | decode | 35.0 µs | 10103 |
| postcard | encode | 9.4 µs | 7362 |
| postcard | decode | 16.7 µs | 7362 |
| rustbinary | encode | 50.0 µs | 23046 |
| rustbinary | decode | 91.5 µs | 23046 |
| rustbinary compact | encode | 9.2 µs | 7687 |
| rustbinary compact | decode | 20.2 µs | 7687 |

## borrowed

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode1 | encode | 24.3 ns | 66 |
| bincode1 | decode | 17.5 ns | 66 |
| minicbor | encode | 86.2 ns | 48 |
| minicbor | decode | 35.7 ns | 48 |
| postcard | encode | 96.2 ns | 45 |
| postcard | decode | 22.2 ns | 45 |
| rustbinary | encode | 180.8 ns | 66 |
| rustbinary | decode | 139.0 ns | 66 |
| rustbinary compact | encode | 95.1 ns | 45 |
| rustbinary compact | decode | 22.8 ns | 45 |

## adversarial

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 321.3 µs | 499997 |
| bincode-next | decode | 532.7 µs | 499997 |
| bincode1 | encode | 68.5 µs | 800008 |
| bincode1 | decode | 79.3 µs | 800008 |
| bincode2 | encode | 330.8 µs | 499997 |
| bincode2 | decode | 282.1 µs | 499997 |
| minicbor | encode | 277.5 µs | 499997 |
| minicbor | decode | 568.9 µs | 499997 |
| postcard | encode | 794.9 µs | 491367 |
| postcard | decode | 250.2 µs | 491367 |
| rustbinary | encode | 1.1 ms | 599994 |
| rustbinary | decode | 2.3 ms | 599994 |
| rustbinary compact | encode | 344.6 µs | 499997 |
| rustbinary compact | decode | 437.9 µs | 499997 |

## schema-evolution

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode-v1 | 64.3 ns | 18 |
| bincode-next | decode-v1-as-v2 | 50.3 ns | 18 |
| bincode1 | encode-v1 | 25.1 ns | 26 |
| bincode1 | decode-v1-as-v2 | error (see notes) | 26 |
| bincode2 | encode-v1 | 66.9 ns | 18 |
| bincode2 | decode-v1-as-v2 | error (see notes) | 18 |
| postcard | encode-v1 | 72.7 ns | 17 |
| postcard | decode-v1-as-v2 | error (see notes) | 17 |
| rustbinary | encode-v1 | 138.3 ns | 68 |
| rustbinary | decode-v1-as-v2 | 102.5 ns | 68 |

## Notes

- Measured by [criterion](https://github.com/bheisler/criterion.rs) (median of many samples, outlier-filtered, `black_box` on every payload); lower is better on time and bytes.

- **borrowed**: bincode 2 and bincode-next are absent because their `decode_from_slice` requires `T: for<'de> Deserialize<'de>`, which a borrowed serde type cannot satisfy (a real limitation of those opponents, reported rather than hidden).

- **schema-evolution**: the serde codecs are probed for the `V1 bytes -> V2 type with an appended #[serde(default)] field` case. bincode 1, bincode 2 and postcard fail it (their sequential format carries no field metadata, so the missing value errors); bincode-next tracks the field count and succeeds. rustbinary succeeds via stable field IDs. Rows marked `error (see notes)` are that failure, reported rather than hidden.

- Numbers vary by machine and load; the `BENCH_RUN_ID` header above identifies the exact run that produced this file.

