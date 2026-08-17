# Benchmark lab (criterion)

| field | value |
| --- | --- |
| OS | Linux 6.17.0-1022-azure |
| CPU | Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz |
| Rust | rustc 1.97.1 (8bab26f4f 2026-07-14) |
| Run | https://github.com/blueokanna/RustBinary/actions/runs/31940177408 |
| Date (UTC) | 2026-08-16T17:51:55+08:00 |

## homogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 11.4 µs | 13829 |
| bincode-next | decode | 6.3 µs | 13829 |
| bincode1 | encode | 6.1 µs | 14344 |
| bincode1 | decode | 1.8 µs | 14344 |
| bincode2 | encode | 12.7 µs | 13829 |
| bincode2 | decode | 4.3 µs | 13829 |
| minicbor | encode | 11.9 µs | 14795 |
| minicbor | decode | 21.5 µs | 14795 |
| postcard | encode | 20.3 µs | 13686 |
| postcard | decode | 8.3 µs | 13686 |
| rkyv | encode | 9.2 µs | 24584 |
| rkyv | decode | 465.6 ns | 24584 |
| rustbinary | encode | 120.5 µs | 51716 |
| rustbinary | decode | 268.2 µs | 51716 |

## heterogeneous

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 6.0 µs | 7687 |
| bincode-next | decode | 17.0 µs | 7687 |
| bincode1 | encode | 6.3 µs | 14344 |
| bincode1 | decode | 14.2 µs | 14344 |
| bincode2 | encode | 7.2 µs | 7687 |
| bincode2 | decode | 15.5 µs | 7687 |
| minicbor | encode | 9.7 µs | 10103 |
| minicbor | decode | 28.1 µs | 10103 |
| postcard | encode | 7.9 µs | 7362 |
| postcard | decode | 15.7 µs | 7362 |
| rustbinary | encode | 51.0 µs | 23046 |
| rustbinary | decode | 128.8 µs | 23046 |

## borrowed

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode1 | encode | 31.5 ns | 66 |
| bincode1 | decode | 20.3 ns | 66 |
| minicbor | encode | 94.5 ns | 48 |
| minicbor | decode | 34.1 ns | 48 |
| postcard | encode | 104.1 ns | 45 |
| postcard | decode | 25.4 ns | 45 |
| rustbinary | encode | 198.2 ns | 66 |
| rustbinary | decode | 199.5 ns | 66 |

## adversarial

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode | 249.2 µs | 499997 |
| bincode-next | decode | 350.9 µs | 499997 |
| bincode1 | encode | 97.3 µs | 800008 |
| bincode1 | decode | 94.9 µs | 800008 |
| bincode2 | encode | 279.0 µs | 499997 |
| bincode2 | decode | 205.8 µs | 499997 |
| minicbor | encode | 167.1 µs | 499997 |
| minicbor | decode | 395.0 µs | 499997 |
| postcard | encode | 802.6 µs | 491367 |
| postcard | decode | 275.0 µs | 491367 |
| rustbinary | encode | 1.4 ms | 599994 |
| rustbinary | decode | 2.9 ms | 599994 |

## schema-evolution

| codec | op | time (median) | encoded bytes |
| --- | --- | ---: | ---: |
| bincode-next | encode-v1 | 71.0 ns | 18 |
| bincode-next | decode-v1-as-v2 | 41.5 ns | 18 |
| bincode1 | encode-v1 | 20.9 ns | 26 |
| bincode1 | decode-v1-as-v2 | error (see notes) | 26 |
| bincode2 | encode-v1 | 73.3 ns | 18 |
| bincode2 | decode-v1-as-v2 | error (see notes) | 18 |
| postcard | encode-v1 | 80.6 ns | 17 |
| postcard | decode-v1-as-v2 | error (see notes) | 17 |
| rustbinary | encode-v1 | 140.6 ns | 68 |
| rustbinary | decode-v1-as-v2 | 159.1 ns | 68 |

## Notes

- Measured by [criterion](https://github.com/bheisler/criterion.rs) (median of many samples, outlier-filtered, `black_box` on every payload); lower is better on time and bytes.

- **borrowed**: bincode 2 and bincode-next are absent because their `decode_from_slice` requires `T: for<'de> Deserialize<'de>`, which a borrowed serde type cannot satisfy (a real limitation of those opponents, reported rather than hidden).

- **schema-evolution**: the serde codecs are probed for the `V1 bytes -> V2 type with an appended #[serde(default)] field` case. bincode 1, bincode 2 and postcard fail it (their sequential format carries no field metadata, so the missing value errors); bincode-next tracks the field count and succeeds. rustbinary succeeds via stable field IDs. Rows marked `error (see notes)` are that failure, reported rather than hidden.

- Numbers vary by machine and load; the `BENCH_RUN_ID` header above identifies the exact run that produced this file.

