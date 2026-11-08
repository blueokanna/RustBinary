# Benchmark lab (criterion)

| field | value |
| --- | --- |
| OS | Linux 7.0.0-1019-azure |
| CPU | AMD EPYC 7763 64-Core Processor |
| Rust | rustc 1.99.1 (58cf8f9c3 2026-10-13) |
| Run | https://github.com/blueokanna/RustBinary/actions/runs/42490047636 |
| Date (UTC) | 2026-11-08T14:36:33Z |

## homogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 12.4 µs | 13829 |
| bincode-next | decode | 6.6 µs | 13829 |
| bincode1 | encode | 9.4 µs | 14344 |
| bincode1 | decode | 2.1 µs | 14344 |
| bincode2 | encode | 14.3 µs | 13829 |
| bincode2 | decode | 4.5 µs | 13829 |
| minicbor | encode | 15.7 µs | 14795 |
| minicbor | decode | 30.1 µs | 14795 |
| postcard | encode | 22.1 µs | 13686 |
| postcard | decode | 8.1 µs | 13686 |
| rkyv | encode | 12.5 µs | 24584 |
| rkyv | decode | 645.0 ns | 24584 |
| rustbinary | encode | 141.9 µs | 51716 |
| rustbinary | decode | 232.8 µs | 51716 |
| rustbinary compact | encode | 16.1 µs | 13829 |
| rustbinary compact | decode | 9.5 µs | 13829 |

## heterogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 7.8 µs | 7687 |
| bincode-next | decode | 15.5 µs | 7687 |
| bincode1 | encode | 9.6 µs | 14344 |
| bincode1 | decode | 13.4 µs | 14344 |
| bincode2 | encode | 7.9 µs | 7687 |
| bincode2 | decode | 15.4 µs | 7687 |
| minicbor | encode | 12.6 µs | 10103 |
| minicbor | decode | 33.0 µs | 10103 |
| postcard | encode | 9.2 µs | 7362 |
| postcard | decode | 15.0 µs | 7362 |
| rustbinary | encode | 59.3 µs | 23046 |
| rustbinary | decode | 106.0 µs | 23046 |
| rustbinary compact | encode | 9.2 µs | 7687 |
| rustbinary compact | decode | 18.8 µs | 7687 |

## borrowed

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode1 | encode | 23.4 ns | 66 |
| bincode1 | decode | 19.0 ns | 66 |
| minicbor | encode | 96.9 ns | 48 |
| minicbor | decode | 36.4 ns | 48 |
| postcard | encode | 109.9 ns | 45 |
| postcard | decode | 25.7 ns | 45 |
| rustbinary | encode | 252.5 ns | 66 |
| rustbinary | decode | 161.9 ns | 66 |
| rustbinary compact | encode | 105.2 ns | 45 |
| rustbinary compact | decode | 24.7 ns | 45 |

## adversarial

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 319.7 µs | 499997 |
| bincode-next | decode | 532.4 µs | 499997 |
| bincode1 | encode | 69.2 µs | 800008 |
| bincode1 | decode | 81.0 µs | 800008 |
| bincode2 | encode | 334.1 µs | 499997 |
| bincode2 | decode | 157.8 µs | 499997 |
| minicbor | encode | 275.9 µs | 499997 |
| minicbor | decode | 568.4 µs | 499997 |
| postcard | encode | 793.1 µs | 491367 |
| postcard | decode | 277.6 µs | 491367 |
| rustbinary | encode | 1.7 ms | 599994 |
| rustbinary | decode | 2.3 ms | 599994 |
| rustbinary compact | encode | 311.1 µs | 499997 |
| rustbinary compact | decode | 344.8 µs | 499997 |

## schema-evolution

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode-v1 | 78.9 ns | 18 |
| bincode-next | decode-v1-as-v2 | 49.7 ns | 18 |
| bincode1 | encode-v1 | 23.8 ns | 26 |
| bincode1 | decode-v1-as-v2 | error (see notes) | 26 |
| bincode2 | encode-v1 | 79.8 ns | 18 |
| bincode2 | decode-v1-as-v2 | error (see notes) | 18 |
| postcard | encode-v1 | 88.7 ns | 17 |
| postcard | decode-v1-as-v2 | error (see notes) | 17 |
| rustbinary | encode-v1 | 219.5 ns | 68 |
| rustbinary | decode-v1-as-v2 | 101.8 ns | 68 |

## Notes

- Measured by [criterion](https://github.com/bheisler/criterion.rs) (median of many samples, outlier-filtered, `black_box` on every payload); lower is better on time and bytes.

- **borrowed**: bincode 2 and bincode-next are absent because their `decode_from_slice` requires `T: for<'de> Deserialize<'de>`, which a borrowed serde type cannot satisfy (a real limitation of those opponents, reported rather than hidden).

- **schema-evolution**: the serde codecs are probed for the `V1 bytes -> V2 type with an appended #[serde(default)] field` case. bincode 1, bincode 2 and postcard fail it (their sequential format carries no field metadata, so the missing value errors); bincode-next tracks the field count and succeeds. rustbinary succeeds via stable field IDs. Rows marked `error (see notes)` are that failure, reported rather than hidden.

- Numbers vary by machine and load; the `BENCH_RUN_ID` header above identifies the exact run that produced this file.

