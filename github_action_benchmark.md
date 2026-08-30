# Benchmark lab (criterion)

| field | value |
| --- | --- |
| OS | Linux 6.17.0-1022-azure |
| CPU | AMD EPYC 9V74 80-Core Processor |
| Rust | rustc 1.97.1 (8bab26f4f 2026-07-14) |
| Run | https://github.com/blueokanna/RustBinary/actions/runs/32004097962 |
| Date (UTC) | 2026-08-17T15:02:41+08:00 |

## homogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 13.3 µs | 13829 |
| bincode-next | decode | 6.3 µs | 13829 |
| bincode1 | encode | 8.4 µs | 14344 |
| bincode1 | decode | 2.2 µs | 14344 |
| bincode2 | encode | 14.1 µs | 13829 |
| bincode2 | decode | 5.3 µs | 13829 |
| minicbor | encode | 14.5 µs | 14795 |
| minicbor | decode | 26.6 µs | 14795 |
| postcard | encode | 23.1 µs | 13686 |
| postcard | decode | 8.3 µs | 13686 |
| rkyv | encode | 13.5 µs | 24584 |
| rkyv | decode | 377.2 ns | 24584 |
| rustbinary | encode | 151.4 µs | 51716 |
| rustbinary | decode | 357.3 µs | 51716 |
| rustbinary compact | encode | 19.2 µs | 13829 |
| rustbinary compact | decode | 10.1 µs | 13829 |

## heterogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 7.0 µs | 7687 |
| bincode-next | decode | 17.7 µs | 7687 |
| bincode1 | encode | 8.3 µs | 14344 |
| bincode1 | decode | 15.0 µs | 14344 |
| bincode2 | encode | 7.4 µs | 7687 |
| bincode2 | decode | 16.5 µs | 7687 |
| minicbor | encode | 12.3 µs | 10103 |
| minicbor | decode | 35.7 µs | 10103 |
| postcard | encode | 9.4 µs | 7362 |
| postcard | decode | 17.2 µs | 7362 |
| rustbinary | encode | 65.5 µs | 23046 |
| rustbinary | decode | 166.2 µs | 23046 |
| rustbinary compact | encode | 8.7 µs | 7687 |
| rustbinary compact | decode | 19.4 µs | 7687 |

## borrowed

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode1 | encode | 26.5 ns | 66 |
| bincode1 | decode | 18.3 ns | 66 |
| minicbor | encode | 93.7 ns | 48 |
| minicbor | decode | 37.9 ns | 48 |
| postcard | encode | 93.5 ns | 45 |
| postcard | decode | 24.9 ns | 45 |
| rustbinary | encode | 209.6 ns | 66 |
| rustbinary | decode | 263.5 ns | 66 |
| rustbinary compact | encode | 95.5 ns | 45 |
| rustbinary compact | decode | 21.8 ns | 45 |

## adversarial

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 360.0 µs | 499997 |
| bincode-next | decode | 354.5 µs | 499997 |
| bincode1 | encode | 73.7 µs | 800008 |
| bincode1 | decode | 74.9 µs | 800008 |
| bincode2 | encode | 325.7 µs | 499997 |
| bincode2 | decode | 178.2 µs | 499997 |
| minicbor | encode | 165.9 µs | 499997 |
| minicbor | decode | 436.8 µs | 499997 |
| postcard | encode | 929.9 µs | 491367 |
| postcard | decode | 281.6 µs | 491367 |
| rustbinary | encode | 1.5 ms | 599994 |
| rustbinary | decode | 4.1 ms | 599994 |
| rustbinary compact | encode | 371.2 µs | 499997 |
| rustbinary compact | decode | 759.0 µs | 499997 |

## schema-evolution

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode-v1 | 66.9 ns | 18 |
| bincode-next | decode-v1-as-v2 | 61.6 ns | 18 |
| bincode1 | encode-v1 | 32.4 ns | 26 |
| bincode1 | decode-v1-as-v2 | error (see notes) | 26 |
| bincode2 | encode-v1 | 68.5 ns | 18 |
| bincode2 | decode-v1-as-v2 | error (see notes) | 18 |
| postcard | encode-v1 | 77.3 ns | 17 |
| postcard | decode-v1-as-v2 | error (see notes) | 17 |
| rustbinary | encode-v1 | 153.1 ns | 68 |
| rustbinary | decode-v1-as-v2 | 205.8 ns | 68 |

## Notes

- Measured by [criterion](https://github.com/bheisler/criterion.rs) (median of many samples, outlier-filtered, `black_box` on every payload); lower is better on time and bytes.

- **borrowed**: bincode 2 and bincode-next are absent because their `decode_from_slice` requires `T: for<'de> Deserialize<'de>`, which a borrowed serde type cannot satisfy (a real limitation of those opponents, reported rather than hidden).

- **schema-evolution**: the serde codecs are probed for the `V1 bytes -> V2 type with an appended #[serde(default)] field` case. bincode 1, bincode 2 and postcard fail it (their sequential format carries no field metadata, so the missing value errors); bincode-next tracks the field count and succeeds. rustbinary succeeds via stable field IDs. Rows marked `error (see notes)` are that failure, reported rather than hidden.

- Numbers vary by machine and load; the `BENCH_RUN_ID` header above identifies the exact run that produced this file.

