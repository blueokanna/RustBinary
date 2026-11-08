# Benchmark lab (criterion)

| field | value |
| --- | --- |
| OS | Linux 7.0.0-1019-azure |
| CPU | Intel(R) Xeon(R) 6973P-C |
| Rust | rustc 1.99.1 (58cf8f9c3 2026-10-13) |
| Run | https://github.com/blueokanna/RustBinary/actions/runs/42486673197 |
| Date (UTC) | 2026-11-08T21:47:58+08:00 |

## homogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 8.0 µs | 13829 |
| bincode-next | decode | 4.7 µs | 13829 |
| bincode1 | encode | 4.7 µs | 14344 |
| bincode1 | decode | 1.1 µs | 14344 |
| bincode2 | encode | 8.1 µs | 13829 |
| bincode2 | decode | 2.7 µs | 13829 |
| minicbor | encode | 8.5 µs | 14795 |
| minicbor | decode | 18.5 µs | 14795 |
| postcard | encode | 16.2 µs | 13686 |
| postcard | decode | 5.7 µs | 13686 |
| rkyv | encode | 8.3 µs | 24584 |
| rkyv | decode | 269.6 ns | 24584 |
| rustbinary | encode | 82.0 µs | 51716 |
| rustbinary | decode | 154.0 µs | 51716 |
| rustbinary compact | encode | 11.7 µs | 13829 |
| rustbinary compact | decode | 6.1 µs | 13829 |

## heterogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 5.4 µs | 7687 |
| bincode-next | decode | 12.5 µs | 7687 |
| bincode1 | encode | 4.7 µs | 14344 |
| bincode1 | decode | 10.7 µs | 14344 |
| bincode2 | encode | 5.1 µs | 7687 |
| bincode2 | decode | 11.9 µs | 7687 |
| minicbor | encode | 7.4 µs | 10103 |
| minicbor | decode | 22.5 µs | 10103 |
| postcard | encode | 6.4 µs | 7362 |
| postcard | decode | 11.8 µs | 7362 |
| rustbinary | encode | 34.3 µs | 23046 |
| rustbinary | decode | 77.2 µs | 23046 |
| rustbinary compact | encode | 5.9 µs | 7687 |
| rustbinary compact | decode | 14.0 µs | 7687 |

## borrowed

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode1 | encode | 23.3 ns | 66 |
| bincode1 | decode | 14.8 ns | 66 |
| minicbor | encode | 70.0 ns | 48 |
| minicbor | decode | 26.4 ns | 48 |
| postcard | encode | 74.9 ns | 45 |
| postcard | decode | 21.4 ns | 45 |
| rustbinary | encode | 127.8 ns | 66 |
| rustbinary | decode | 121.6 ns | 66 |
| rustbinary compact | encode | 73.6 ns | 45 |
| rustbinary compact | decode | 22.4 ns | 45 |

## adversarial

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 144.7 µs | 499997 |
| bincode-next | decode | 212.8 µs | 499997 |
| bincode1 | encode | 63.9 µs | 800008 |
| bincode1 | decode | 58.3 µs | 800008 |
| bincode2 | encode | 190.4 µs | 499997 |
| bincode2 | decode | 94.5 µs | 499997 |
| minicbor | encode | 112.9 µs | 499997 |
| minicbor | decode | 222.5 µs | 499997 |
| postcard | encode | 590.8 µs | 491367 |
| postcard | decode | 191.6 µs | 491367 |
| rustbinary | encode | 884.1 µs | 599994 |
| rustbinary | decode | 1.3 ms | 599994 |
| rustbinary compact | encode | 257.4 µs | 499997 |
| rustbinary compact | decode | 177.3 µs | 499997 |

## schema-evolution

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode-v1 | 63.2 ns | 18 |
| bincode-next | decode-v1-as-v2 | 30.2 ns | 18 |
| bincode1 | encode-v1 | 15.8 ns | 26 |
| bincode1 | decode-v1-as-v2 | error (see notes) | 26 |
| bincode2 | encode-v1 | 67.0 ns | 18 |
| bincode2 | decode-v1-as-v2 | error (see notes) | 18 |
| postcard | encode-v1 | 69.9 ns | 17 |
| postcard | decode-v1-as-v2 | error (see notes) | 17 |
| rustbinary | encode-v1 | 71.8 ns | 68 |
| rustbinary | decode-v1-as-v2 | 57.4 ns | 68 |

## Notes

- Measured by [criterion](https://github.com/bheisler/criterion.rs) (median of many samples, outlier-filtered, `black_box` on every payload); lower is better on time and bytes.

- **borrowed**: bincode 2 and bincode-next are absent because their `decode_from_slice` requires `T: for<'de> Deserialize<'de>`, which a borrowed serde type cannot satisfy (a real limitation of those opponents, reported rather than hidden).

- **schema-evolution**: the serde codecs are probed for the `V1 bytes -> V2 type with an appended #[serde(default)] field` case. bincode 1, bincode 2 and postcard fail it (their sequential format carries no field metadata, so the missing value errors); bincode-next tracks the field count and succeeds. rustbinary succeeds via stable field IDs. Rows marked `error (see notes)` are that failure, reported rather than hidden.

- Numbers vary by machine and load; the `BENCH_RUN_ID` header above identifies the exact run that produced this file.

