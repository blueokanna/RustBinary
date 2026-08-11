use std::{
    env,
    hint::black_box,
    time::{Duration, Instant},
};

use nextjson::{NsonDeserialize, NsonSerialize};

const DEFAULT_SAMPLE_TIME: Duration = Duration::from_millis(200);
const SAMPLES: usize = 9;

#[derive(Clone, Debug, NsonDeserialize, PartialEq, NsonSerialize)]
struct Telemetry {
    sequence: u64,
    timestamp_delta: i64,
    status: u16,
    topic: String,
    readings: Vec<i32>,
    payload: Vec<u8>,
}

struct CodecResult {
    codec: &'static str,
    encoded_size: usize,
    encode_ns: f64,
    decode_ns: f64,
}

fn main() {
    let sample_time = env::var("RUSTBINARY_BENCH_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_SAMPLE_TIME);

    println!("| shape | codec | bytes | encode ns/op | decode ns/op |");
    println!("| --- | --- | ---: | ---: | ---: |");
    run_shape("small", &small_record(), sample_time);
    run_shape("telemetry", &telemetry_record(32, 128), sample_time);
    run_shape("bulk", &telemetry_record(4_096, 16_384), sample_time);
}

fn small_record() -> Telemetry {
    Telemetry {
        sequence: 42,
        timestamp_delta: -7,
        status: 3,
        topic: "edge/a".to_owned(),
        readings: vec![17, 18, 19],
        payload: vec![0, 1, 2, 3],
    }
}

fn telemetry_record(readings: usize, payload: usize) -> Telemetry {
    Telemetry {
        sequence: 4_294_967_296,
        timestamp_delta: -86_400_000,
        status: 0x20,
        topic: "factory/line-07/temperature".to_owned(),
        readings: (0..readings)
            .map(|index| 20_000 + (index % 97) as i32)
            .collect(),
        payload: (0..payload)
            .map(|index| ((index.wrapping_mul(31)) % 251) as u8)
            .collect(),
    }
}

fn run_shape<T>(shape: &str, value: &T, sample_time: Duration)
where
    T: for<'de> nextjson::NsonDeserialize<'de> + PartialEq + NsonSerialize,
{
    let owned = benchmark_owned(value, sample_time);
    let caller_buffer = benchmark_caller_buffer(value, sample_time);

    for result in [owned, caller_buffer] {
        println!(
            "| {shape} | {} | {} | {:.1} | {:.1} |",
            result.codec, result.encoded_size, result.encode_ns, result.decode_ns
        );
    }
}

fn benchmark_owned<T>(value: &T, sample_time: Duration) -> CodecResult
where
    T: for<'de> nextjson::NsonDeserialize<'de> + PartialEq + NsonSerialize,
{
    let config = rustbinary::options();
    let encoded = config.serialize(value).expect("RustBinary encode failed");
    assert!(
        config
            .deserialize::<T>(&encoded)
            .expect("RustBinary decode failed")
            == *value
    );
    CodecResult {
        codec: "Compact V1 owned",
        encoded_size: encoded.len(),
        encode_ns: median_ns(sample_time, || {
            black_box(config.serialize(black_box(value)).expect("encode failed"));
        }),
        decode_ns: median_ns(sample_time, || {
            black_box(
                config
                    .deserialize::<T>(black_box(&encoded))
                    .expect("decode failed"),
            );
        }),
    }
}

fn benchmark_caller_buffer<T>(value: &T, sample_time: Duration) -> CodecResult
where
    T: for<'de> nextjson::NsonDeserialize<'de> + PartialEq + NsonSerialize,
{
    let config = rustbinary::options();
    let required = usize::try_from(
        config
            .serialized_size(value)
            .expect("size calculation failed"),
    )
    .expect("encoded size does not fit usize");
    let mut encoded = vec![0_u8; required];
    let written = config
        .serialize_into_slice(&mut encoded, value)
        .expect("caller-buffer encode failed");
    assert_eq!(written, required);
    assert!(
        config
            .deserialize::<T>(&encoded)
            .expect("caller-buffer decode failed")
            == *value
    );

    CodecResult {
        codec: "Compact V1 caller buffer",
        encoded_size: encoded.len(),
        encode_ns: median_ns(sample_time, || {
            let written = config
                .serialize_into_slice(black_box(&mut encoded), black_box(value))
                .expect("encode failed");
            black_box(written);
        }),
        decode_ns: median_ns(sample_time, || {
            black_box(
                config
                    .deserialize::<T>(black_box(&encoded))
                    .expect("decode failed"),
            );
        }),
    }
}

fn median_ns(mut minimum_time: Duration, mut operation: impl FnMut()) -> f64 {
    if minimum_time.is_zero() {
        minimum_time = Duration::from_millis(1);
    }
    let iterations = calibrate_iterations(minimum_time, &mut operation);
    let mut samples = [0.0; SAMPLES];
    for sample in &mut samples {
        let started = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        *sample = started.elapsed().as_nanos() as f64 / iterations as f64;
    }
    samples.sort_by(f64::total_cmp);
    samples[SAMPLES / 2]
}

fn calibrate_iterations(minimum_time: Duration, operation: &mut impl FnMut()) -> u64 {
    let mut iterations = 1_u64;
    loop {
        let started = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        let elapsed = started.elapsed();
        if elapsed >= minimum_time || iterations >= 1 << 30 {
            return iterations;
        }
        let elapsed_ns = elapsed.as_nanos().max(1);
        let target_ns = minimum_time.as_nanos();
        let factor = (target_ns / elapsed_ns).clamp(2, 10) as u64;
        iterations = iterations.saturating_mul(factor);
    }
}
