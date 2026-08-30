# Benchmark lab (criterion)

| field | value |
| --- | --- |
| OS | Linux 6.17.0-1022-azure |
| CPU | INTEL(R) XEON(R) PLATINUM 8573C |
| Rust | rustc 1.98.0 (88d9e12ae 2026-08-18) |
| Run | https://github.com/blueokanna/RustBinary/actions/runs/33306190370 |
| Date (UTC) | 2026-08-30T18:19:09+08:00 |

## homogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 8.6 µs | 13829 |
| bincode-next | decode | 5.6 µs | 13829 |
| bincode1 | encode | 5.5 µs | 14344 |
| bincode1 | decode | 1.2 µs | 14344 |
| bincode2 | encode | 8.8 µs | 13829 |
| bincode2 | decode | 3.9 µs | 13829 |
| minicbor | encode | 9.9 µs | 14795 |
| minicbor | decode | 20.8 µs | 14795 |
| postcard | encode | 18.7 µs | 13686 |
| postcard | decode | 6.3 µs | 13686 |
| rkyv | encode | 8.9 µs | 24584 |
| rkyv | decode | 304.2 ns | 24584 |
| rustbinary | encode | 90.8 µs | 51716 |
| rustbinary | decode | 151.2 µs | 51716 |
| rustbinary compact | encode | 13.3 µs | 13829 |
| rustbinary compact | decode | 6.5 µs | 13829 |

## heterogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 5.8 µs | 7687 |
| bincode-next | decode | 15.0 µs | 7687 |
| bincode1 | encode | 6.0 µs | 14344 |
| bincode1 | decode | 12.5 µs | 14344 |
| bincode2 | encode | 5.6 µs | 7687 |
| bincode2 | decode | 13.4 µs | 7687 |
| minicbor | encode | 8.2 µs | 10103 |
| minicbor | decode | 25.6 µs | 10103 |
| postcard | encode | 7.1 µs | 7362 |
| postcard | decode | 13.1 µs | 7362 |
| rustbinary | encode | 37.8 µs | 23046 |
| rustbinary | decode | 75.4 µs | 23046 |
| rustbinary compact | encode | 6.7 µs | 7687 |
| rustbinary compact | decode | 16.5 µs | 7687 |

## borrowed

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode1 | encode | 28.1 ns | 66 |
| bincode1 | decode | 18.1 ns | 66 |
| minicbor | encode | 88.4 ns | 48 |
| minicbor | decode | 32.2 ns | 48 |
| postcard | encode | 93.7 ns | 45 |
| postcard | decode | 21.4 ns | 45 |
| rustbinary | encode | 138.2 ns | 66 |
| rustbinary | decode | 105.8 ns | 66 |
| rustbinary compact | encode | 91.4 ns | 45 |
| rustbinary compact | decode | 22.0 ns | 45 |

## adversarial

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 299.5 µs | 499997 |
| bincode-next | decode | 307.1 µs | 499997 |
| bincode1 | encode | 90.0 µs | 800008 |
| bincode1 | decode | 83.3 µs | 800008 |
| bincode2 | encode | 252.0 µs | 499997 |
| bincode2 | decode | 126.0 µs | 499997 |
| minicbor | encode | 154.2 µs | 499997 |
| minicbor | decode | 336.7 µs | 499997 |
| postcard | encode | 734.0 µs | 491367 |
| postcard | decode | 223.5 µs | 491367 |
| rustbinary | encode | 1.0 ms | 599994 |
| rustbinary | decode | 1.5 ms | 599994 |
| rustbinary compact | encode | 230.7 µs | 499997 |
| rustbinary compact | decode | 306.6 µs | 499997 |

## schema-evolution

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode-v1 | 64.8 ns | 18 |
| bincode-next | decode-v1-as-v2 | 35.0 ns | 18 |
| bincode1 | encode-v1 | 19.3 ns | 26 |
| bincode1 | decode-v1-as-v2 | error (see notes) | 26 |
| bincode2 | encode-v1 | 67.9 ns | 18 |
| bincode2 | decode-v1-as-v2 | error (see notes) | 18 |
| postcard | encode-v1 | 74.0 ns | 17 |
| postcard | decode-v1-as-v2 | error (see notes) | 17 |
| rustbinary | encode-v1 | 92.5 ns | 68 |
| rustbinary | decode-v1-as-v2 | 70.7 ns | 68 |

## Notes

- Measured by [criterion](https://github.com/bheisler/criterion.rs) (median of many samples, outlier-filtered, `black_box` on every payload); lower is better on time and bytes.

- **borrowed**: bincode 2 and bincode-next are absent because their `decode_from_slice` requires `T: for<'de> Deserialize<'de>`, which a borrowed serde type cannot satisfy (a real limitation of those opponents, reported rather than hidden).

- **schema-evolution**: the serde codecs are probed for the `V1 bytes -> V2 type with an appended #[serde(default)] field` case. bincode 1, bincode 2 and postcard fail it (their sequential format carries no field metadata, so the missing value errors); bincode-next tracks the field count and succeeds. rustbinary succeeds via stable field IDs. Rows marked `error (see notes)` are that failure, reported rather than hidden.

- Numbers vary by machine and load; the `BENCH_RUN_ID` header above identifies the exact run that produced this file.

