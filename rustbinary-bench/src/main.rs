//! Codec comparison benchmark: rustbinary vs bincode 1/2, postcard, cbor4ii,
//! and minicbor on shared workloads.
//!
//! Run with `cargo run --release` from this crate. It reports median-of-9
//! encode/decode latencies and the encoded size for each codec and dataset,
//! so the comparison covers both the wire (bytes) and the CPU cost.

mod dataset;

use std::hint::black_box;
use std::time::Instant;

use dataset::{
    datasets, to_cbor_numerics, to_cbor_small, to_cbor_strings, to_cbor_telemetry, to_ser_numerics,
    to_ser_small, to_ser_strings, to_ser_telemetry, BulkNumerics, BulkStrings, Small, Telemetry,
};

/// Median-of-9 elapsed time for `f` (with calibration subtracted).
fn bench<T, F: FnMut() -> T>(mut f: F) -> f64 {
    // Warm-up.
    for _ in 0..200 {
        black_box(f());
    }
    let mut samples = Vec::with_capacity(9);
    for _ in 0..9 {
        let start = Instant::now();
        for _ in 0..32 {
            black_box(f());
        }
        samples.push(start.elapsed().as_nanos() as f64 / 32.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[4]
}

macro_rules! codec_row {
    ($name:expr, $dataset:expr, $encode:expr, $decode:expr, $bytes:expr) => {{
        let e = bench(|| black_box($encode));
        let d = bench(|| black_box($decode));
        println!(
            "| {:<22} | {:<16} | {:>10.0} | {:>10.0} | {:>8} |",
            $name,
            $dataset,
            e,
            d,
            $bytes.len()
        );
    }};
}

fn main() {
    let d = datasets();

    println!("# rustbinary-bench: codec comparison (median of 9, ns/op)\n");
    println!("| codec | dataset | encode ns | decode ns | bytes |");
    println!("|---|---|---:|---:|---:|");

    // --- Small ------------------------------------------------------------
    let small = &d.small;
    let rb_small = dataset::RbSmall {
        enabled: small.enabled,
        mode: small.mode,
        sequence: small.sequence,
        delta: small.delta,
    };
    let ser_small = to_ser_small(small);
    let cbor_small = to_cbor_small(small);

    let rb_cfg = rustbinary::options().with_limit(1 << 20);
    let rb_frame = rb_cfg.serialize(&rb_small).unwrap();
    codec_row!("rustbinary", "small", {
        rb_cfg.serialize(&rb_small).unwrap()
    }, {
        rb_cfg.deserialize::<dataset::RbSmall>(&rb_frame).unwrap()
    }, rb_frame);

    let b1 = bincode::serialize(&ser_small).unwrap();
    codec_row!("bincode 1", "small", {
        bincode::serialize(&ser_small).unwrap()
    }, {
        bincode::deserialize::<dataset::SerSmall>(&b1).unwrap()
    }, b1);

    let b2 = bincode2::serde::encode_to_vec(&ser_small, bincode2::config::standard()).unwrap();
    codec_row!("bincode 2", "small", {
        bincode2::serde::encode_to_vec(&ser_small, bincode2::config::standard()).unwrap()
    }, {
        bincode2::serde::decode_from_slice::<dataset::SerSmall, _>(
            &b2,
            bincode2::config::standard(),
        )
        .unwrap()
        .0
    }, b2);

    let pc = postcard::to_allocvec(&ser_small).unwrap();
    codec_row!("postcard", "small", {
        postcard::to_allocvec(&ser_small).unwrap()
    }, {
        postcard::from_bytes::<dataset::SerSmall>(&pc).unwrap()
    }, pc);

    let c4 = cbor4ii::serde::to_vec(Vec::new(), &ser_small).unwrap();
    codec_row!("cbor4ii", "small", {
        cbor4ii::serde::to_vec(Vec::new(), &ser_small).unwrap()
    }, {
        cbor4ii::serde::from_slice::<dataset::SerSmall>(&c4).unwrap()
    }, c4);

    let mc = minicbor::to_vec(&cbor_small).unwrap();
    codec_row!("minicbor", "small", {
        minicbor::to_vec(&cbor_small).unwrap()
    }, {
        minicbor::decode::<dataset::CborSmall>(&mc).unwrap()
    }, mc);

    bench_compact("rustbinary compact", "small", &rb_small);

    // --- Telemetry ---------------------------------------------------------
    let telemetry = &d.telemetry;
    let rb_telemetry = dataset::RbTelemetry {
        device: telemetry.device.clone(),
        metric: telemetry.metric.clone(),
        value: telemetry.value,
        samples: telemetry.samples.clone(),
        status: telemetry.status,
    };
    let ser_telemetry = to_ser_telemetry(telemetry);
    let cbor_telemetry = to_cbor_telemetry(telemetry);

    let rb_frame = rb_cfg.serialize(&rb_telemetry).unwrap();
    codec_row!("rustbinary", "telemetry", {
        rb_cfg.serialize(&rb_telemetry).unwrap()
    }, {
        rb_cfg
            .deserialize::<dataset::RbTelemetry>(&rb_frame)
            .unwrap()
    }, rb_frame);

    let b1 = bincode::serialize(&ser_telemetry).unwrap();
    codec_row!("bincode 1", "telemetry", {
        bincode::serialize(&ser_telemetry).unwrap()
    }, {
        bincode::deserialize::<dataset::SerTelemetry>(&b1).unwrap()
    }, b1);

    let b2 =
        bincode2::serde::encode_to_vec(&ser_telemetry, bincode2::config::standard()).unwrap();
    codec_row!("bincode 2", "telemetry", {
        bincode2::serde::encode_to_vec(&ser_telemetry, bincode2::config::standard()).unwrap()
    }, {
        bincode2::serde::decode_from_slice::<dataset::SerTelemetry, _>(
            &b2,
            bincode2::config::standard(),
        )
        .unwrap()
        .0
    }, b2);

    let pc = postcard::to_allocvec(&ser_telemetry).unwrap();
    codec_row!("postcard", "telemetry", {
        postcard::to_allocvec(&ser_telemetry).unwrap()
    }, {
        postcard::from_bytes::<dataset::SerTelemetry>(&pc).unwrap()
    }, pc);

    let c4 = cbor4ii::serde::to_vec(Vec::new(), &ser_telemetry).unwrap();
    codec_row!("cbor4ii", "telemetry", {
        cbor4ii::serde::to_vec(Vec::new(), &ser_telemetry).unwrap()
    }, {
        cbor4ii::serde::from_slice::<dataset::SerTelemetry>(&c4).unwrap()
    }, c4);

    let mc = minicbor::to_vec(&cbor_telemetry).unwrap();
    codec_row!("minicbor", "telemetry", {
        minicbor::to_vec(&cbor_telemetry).unwrap()
    }, {
        minicbor::decode::<dataset::CborTelemetry>(&mc).unwrap()
    }, mc);

    bench_compact("rustbinary compact", "telemetry", &rb_telemetry);

    // --- Bulk numerics -----------------------------------------------------
    bench_numerics(&d.bulk_numerics, &rb_cfg);
    // --- Bulk strings ------------------------------------------------------
    bench_strings(&d.bulk_strings, &rb_cfg);

    // --- rustbinary entropy (rANS byte codec) on bulk ----------------------
    entropy_benchmark(&d);

    println!();
    println!("Note: latencies are ns/op on this machine; compare rows within a dataset, not across runs. \"rustbinary\" is a type-tagged self-describing format; \"rustbinary compact\" is the schema-guided compact profile (no tags, no field names, length-prefixed containers) and is the apples-to-apples comparison against bincode/postcard. The entropy row measures the standalone rANS byte codec, not the tagged stream.");
}

fn bench_numerics(d: &BulkNumerics, rb_cfg: &rustbinary::Config) {
    let rb = dataset::RbBulkNumerics {
        id: d.id,
        values: d.values.clone(),
    };
    let ser = to_ser_numerics(d);
    let cbor = to_cbor_numerics(d);

    let rb_frame = rb_cfg.serialize(&rb).unwrap();
    codec_row!("rustbinary", "bulk-numerics", {
        rb_cfg.serialize(&rb).unwrap()
    }, {
        rb_cfg.deserialize::<dataset::RbBulkNumerics>(&rb_frame).unwrap()
    }, rb_frame);

    let b1 = bincode::serialize(&ser).unwrap();
    codec_row!("bincode 1", "bulk-numerics", {
        bincode::serialize(&ser).unwrap()
    }, {
        bincode::deserialize::<dataset::SerBulkNumerics>(&b1).unwrap()
    }, b1);

    let b2 = bincode2::serde::encode_to_vec(&ser, bincode2::config::standard()).unwrap();
    codec_row!("bincode 2", "bulk-numerics", {
        bincode2::serde::encode_to_vec(&ser, bincode2::config::standard()).unwrap()
    }, {
        bincode2::serde::decode_from_slice::<dataset::SerBulkNumerics, _>(
            &b2,
            bincode2::config::standard(),
        )
        .unwrap()
        .0
    }, b2);

    let pc = postcard::to_allocvec(&ser).unwrap();
    codec_row!("postcard", "bulk-numerics", {
        postcard::to_allocvec(&ser).unwrap()
    }, {
        postcard::from_bytes::<dataset::SerBulkNumerics>(&pc).unwrap()
    }, pc);

    let c4 = cbor4ii::serde::to_vec(Vec::new(), &ser).unwrap();
    codec_row!("cbor4ii", "bulk-numerics", {
        cbor4ii::serde::to_vec(Vec::new(), &ser).unwrap()
    }, {
        cbor4ii::serde::from_slice::<dataset::SerBulkNumerics>(&c4).unwrap()
    }, c4);

    let mc = minicbor::to_vec(&cbor).unwrap();
    codec_row!("minicbor", "bulk-numerics", {
        minicbor::to_vec(&cbor).unwrap()
    }, {
        minicbor::decode::<dataset::CborBulkNumerics>(&mc).unwrap()
    }, mc);

    bench_compact("rustbinary compact", "bulk-numerics", &rb);
}

fn bench_strings(d: &BulkStrings, rb_cfg: &rustbinary::Config) {
    let rb = dataset::RbBulkStrings {
        id: d.id,
        entries: d.entries.clone(),
    };
    let ser = to_ser_strings(d);
    let cbor = to_cbor_strings(d);

    let rb_frame = rb_cfg.serialize(&rb).unwrap();
    codec_row!("rustbinary", "bulk-strings", {
        rb_cfg.serialize(&rb).unwrap()
    }, {
        rb_cfg.deserialize::<dataset::RbBulkStrings>(&rb_frame).unwrap()
    }, rb_frame);

    let b1 = bincode::serialize(&ser).unwrap();
    codec_row!("bincode 1", "bulk-strings", {
        bincode::serialize(&ser).unwrap()
    }, {
        bincode::deserialize::<dataset::SerBulkStrings>(&b1).unwrap()
    }, b1);

    let b2 = bincode2::serde::encode_to_vec(&ser, bincode2::config::standard()).unwrap();
    codec_row!("bincode 2", "bulk-strings", {
        bincode2::serde::encode_to_vec(&ser, bincode2::config::standard()).unwrap()
    }, {
        bincode2::serde::decode_from_slice::<dataset::SerBulkStrings, _>(
            &b2,
            bincode2::config::standard(),
        )
        .unwrap()
        .0
    }, b2);

    let pc = postcard::to_allocvec(&ser).unwrap();
    codec_row!("postcard", "bulk-strings", {
        postcard::to_allocvec(&ser).unwrap()
    }, {
        postcard::from_bytes::<dataset::SerBulkStrings>(&pc).unwrap()
    }, pc);

    let c4 = cbor4ii::serde::to_vec(Vec::new(), &ser).unwrap();
    codec_row!("cbor4ii", "bulk-strings", {
        cbor4ii::serde::to_vec(Vec::new(), &ser).unwrap()
    }, {
        cbor4ii::serde::from_slice::<dataset::SerBulkStrings>(&c4).unwrap()
    }, c4);

    let mc = minicbor::to_vec(&cbor).unwrap();
    codec_row!("minicbor", "bulk-strings", {
        minicbor::to_vec(&cbor).unwrap()
    }, {
        minicbor::decode::<dataset::CborBulkStrings>(&mc).unwrap()
    }, mc);

    bench_compact("rustbinary compact", "bulk-strings", &rb);
}

/// Compact-profile row: schema-known direct codec (no tags, no field names).
fn bench_compact<T>(name: &str, dataset: &str, value: &T)
where
    T: rustbinary::compact::CompactEncode + for<'de> rustbinary::compact::CompactDecode<'de>,
{
    let config = rustbinary::options()
        .with_limit(1 << 20)
        .with_compact_format();
    let frame = config.serialize(value).unwrap();
    codec_row!(name, dataset, {
        config.serialize(value).unwrap()
    }, {
        config.deserialize::<T>(&frame).unwrap()
    }, frame);
}

/// The standalone rANS byte codec on repetitive bulk data: the schema-driven
/// entropy layer measured on its own terms (a static byte model with a skewed
/// prior, plus the exact-alphabet enum case).
fn entropy_benchmark(d: &dataset::Datasets) {
    // Repetitive telemetry text: compressible under a skewed byte model.
    let text: Vec<u8> = d
        .bulk_strings
        .entries
        .iter()
        .flat_map(|s| s.bytes())
        .collect();
    let weights: Vec<u32> = {
        let mut weights = vec![1u32; 256];
        for &byte in &text {
            weights[byte as usize] = weights[byte as usize].saturating_add(1);
        }
        weights
    };
    let model = rustbinary::Model::from_weights(&weights).unwrap();
    let entropy = rustbinary::options()
        .with_limit(1 << 20)
        .with_entropy_encoding();

    let frame = entropy.compress(&text, &model).unwrap();
    let raw_len = text.len();
    let e = bench(|| entropy.compress(&text, &model).unwrap());
    let d = bench(|| entropy.decompress(&frame, &model).unwrap());
    println!(
        "| {:<22} | {:<16} | {:>10.0} | {:>10.0} | {:>8} |",
        "rustbinary entropy", "bulk-strings", e, d, frame.len()
    );
    println!(
        "| {:<22} | {:<16} | {:>10} | {:>10} | {:>8} |",
        "rustbinary entropy", "compression ratio", "-", "-",
        format!("{:.2}x", raw_len as f64 / frame.len().max(1) as f64)
    );

    // Exact-alphabet enum discriminant coding.
    let enum_model = rustbinary::Model::from_uniform(5).unwrap();
    let mut symbols = Vec::with_capacity(1000);
    for i in 0..1000 {
        symbols.push((i % 5) as u32);
    }
    let models: Vec<&rustbinary::Model> = (0..symbols.len()).map(|_| &enum_model).collect();
    let enum_frame = entropy.encode_sequence(&models, &symbols).unwrap();
    let e = bench(|| entropy.encode_sequence(&models, &symbols).unwrap());
    let d = bench(|| entropy.decode_sequence(&models, &enum_frame).unwrap());
    println!(
        "| {:<22} | {:<16} | {:>10.0} | {:>10.0} | {:>8} |",
        "rustbinary entropy", "enum x1000", e, d, enum_frame.len()
    );
    println!(
        "| {:<22} | {:<16} | {:>10} | {:>10} | {:>8} |",
        "rustbinary entropy", "enum bits/symbol", "-", "-",
        format!("{:.2}", enum_frame.len() as f64 * 8.0 / 1000.0)
    );
}

// Keep the dataset types referenced in signatures so the module is coherent.
#[allow(dead_code)]
fn _type_anchors(_: &Small, _: &Telemetry, _: &BulkNumerics, _: &BulkStrings) {}
