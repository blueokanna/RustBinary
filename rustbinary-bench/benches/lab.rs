//! Fair benchmark lab: rustbinary vs bincode 1, bincode 2, bincode-next,
//! postcard, rkyv, and minicbor across five workload classes.
//!
//! Run from this crate with:
//!
//! ```text
//! cargo bench --bench lab
//! ```
//!
//! # Lab protocol
//!
//! - **Same hardware, same toolchain**: every codec is compiled by the same
//!   `cargo bench` invocation with `[profile.release]` (`lto = "thin"`,
//!   `codegen-units = 1`), so all measurements share one compiler, one set of
//!   flags, and one machine.
//! - **Criterion statistics**: median-of-N with outlier filtering and
//!   calibration subtraction, `black_box` on every payload, `BatchSize` set so
//!   per-iteration setup does not dominate.
//! - **Cache regimes**: `criterion` runs each measurement loop repeatedly over
//!   the same buffer, so the reported decode numbers are *warm-cache*. A cold
//!   cache would favor the smaller encoded buffers; the encoded byte counts
//!   are reported alongside every pair so that trade-off stays visible.
//! - **CPU pinning / perf counters**: run under `taskset`/`cpuset` and
//!   `perf stat` on Linux for the pinned, counter-backed numbers; the
//!   criterion numbers themselves are the portable baseline. See
//!   `docs/benchmark-lab.md` for the exact commands.
//!
//! # Workload classes
//!
//! - `homogeneous` — 1024 identical small records (`Vec<Small>`): the
//!   throughput-shaped bulk case.
//! - `heterogeneous` — a `Vec` of mixed enum variants: the tag-dispatch case.
//! - `borrowed` — decode into borrowed `&str` / `&[u8]` (zero-copy where the
//!   codec supports it).
//! - `adversarial` — 100k-element `Vec<u64>` (maximal element count under a
//!   fixed budget): the per-element worst case.
//! - `schema-evolution` — decode old-schema bytes with a new-schema type
//!   (added field with a default): the forward-compatibility cost.
//!
//! # Reading the report
//!
//! Every row prints encode ns/op, decode ns/op, and encoded bytes. Lower is
//! better on all three, but the three are in tension: a format that wins on
//! bytes may lose on decode CPU (and vice versa). The lab reports the
//! trade-off rather than a single winner.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

// ---------------------------------------------------------------------------
// Shared data
// ---------------------------------------------------------------------------

const N_RECORDS: usize = 1024;
const N_ELEMENTS: usize = 100_000;

fn small_values() -> Vec<Small> {
    (0..N_RECORDS)
        .map(|i| Small {
            enabled: i % 3 != 0,
            mode: (i % 8) as u8,
            sequence: i as u64 * 0x9e37_79b9_7f4a_7c15,
            delta: (i as i32) - 512,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Workload 1: homogeneous
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Small {
    enabled: bool,
    mode: u8,
    sequence: u64,
    delta: i32,
}

#[derive(Debug, nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::CompactBinary)]
struct RbSmall {
    enabled: bool,
    mode: u8,
    sequence: u64,
    delta: i32,
}

fn to_rb(small: &Small) -> RbSmall {
    RbSmall {
        enabled: small.enabled,
        mode: small.mode,
        sequence: small.sequence,
        delta: small.delta,
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerSmall {
    enabled: bool,
    mode: u8,
    sequence: u64,
    delta: i32,
}

fn to_ser(small: &Small) -> SerSmall {
    SerSmall {
        enabled: small.enabled,
        mode: small.mode,
        sequence: small.sequence,
        delta: small.delta,
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct RkSmall {
    enabled: bool,
    mode: u8,
    sequence: u64,
    delta: i32,
}

fn to_rk(small: &Small) -> RkSmall {
    RkSmall {
        enabled: small.enabled,
        mode: small.mode,
        sequence: small.sequence,
        delta: small.delta,
    }
}

#[derive(minicbor::Encode, minicbor::Decode)]
struct CbSmall {
    #[n(0)]
    enabled: bool,
    #[n(1)]
    mode: u8,
    #[n(2)]
    sequence: u64,
    #[n(3)]
    delta: i32,
}

fn to_cb(small: &Small) -> CbSmall {
    CbSmall {
        enabled: small.enabled,
        mode: small.mode,
        sequence: small.sequence,
        delta: small.delta,
    }
}

// ---------------------------------------------------------------------------
// Workload 2: heterogeneous
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Msg {
    Version(u32),
    Heartbeat { seq: u64, ts: f64 },
    Payload(String),
    Terminate,
}

fn messages() -> Vec<Msg> {
    (0..N_RECORDS)
        .map(|i| match i % 4 {
            0 => Msg::Version(i as u32),
            1 => Msg::Heartbeat {
                seq: i as u64,
                ts: i as f64 * 0.25,
            },
            2 => Msg::Payload(format!("payload/{i:04}")),
            _ => Msg::Terminate,
        })
        .collect()
}

#[derive(nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::CompactBinary)]
enum RbMsg {
    Version(u32),
    Heartbeat { seq: u64, ts: f64 },
    Payload(String),
    Terminate,
}

fn to_rb_msg(msg: &Msg) -> RbMsg {
    match msg {
        Msg::Version(v) => RbMsg::Version(*v),
        Msg::Heartbeat { seq, ts } => RbMsg::Heartbeat { seq: *seq, ts: *ts },
        Msg::Payload(p) => RbMsg::Payload(p.clone()),
        Msg::Terminate => RbMsg::Terminate,
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
enum SerMsg {
    Version(u32),
    Heartbeat { seq: u64, ts: f64 },
    Payload(String),
    Terminate,
}

fn to_ser_msg(msg: &Msg) -> SerMsg {
    match msg {
        Msg::Version(v) => SerMsg::Version(*v),
        Msg::Heartbeat { seq, ts } => SerMsg::Heartbeat { seq: *seq, ts: *ts },
        Msg::Payload(p) => SerMsg::Payload(p.clone()),
        Msg::Terminate => SerMsg::Terminate,
    }
}

#[derive(minicbor::Encode, minicbor::Decode)]
enum CbMsg {
    #[n(0)]
    Version(#[n(0)] u32),
    #[n(1)]
    Heartbeat {
        #[n(0)]
        seq: u64,
        #[n(1)]
        ts: f64,
    },
    #[n(2)]
    Payload(#[n(0)] String),
    #[n(3)]
    Terminate,
}

fn to_cb_msg(msg: &Msg) -> CbMsg {
    match msg {
        Msg::Version(v) => CbMsg::Version(*v),
        Msg::Heartbeat { seq, ts } => CbMsg::Heartbeat { seq: *seq, ts: *ts },
        Msg::Payload(p) => CbMsg::Payload(p.clone()),
        Msg::Terminate => CbMsg::Terminate,
    }
}

// ---------------------------------------------------------------------------
// Workload 3: borrowed
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct BorrowedOwned {
    id: u64,
    name: String,
    note: String,
}

fn borrowed_value() -> BorrowedOwned {
    BorrowedOwned {
        id: 42,
        name: "sensor/alpha-7/telemetry".to_string(),
        note: "ok; sample_rate=1s".to_string(),
    }
}

#[derive(Debug, nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::CompactBinary)]
struct RbBorrowed<'a> {
    id: u64,
    #[njson(borrow)]
    name: &'a str,
    #[njson(borrow)]
    note: &'a str,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerBorrowed<'a> {
    id: u64,
    #[serde(borrow)]
    name: &'a str,
    #[serde(borrow)]
    note: &'a str,
}

#[derive(minicbor::Encode, minicbor::Decode)]
struct CbBorrowed<'a> {
    #[n(0)]
    id: u64,
    #[n(1)]
    name: &'a str,
    #[n(2)]
    note: &'a str,
}

// ---------------------------------------------------------------------------
// Workload 4: adversarial (maximal element count)
// ---------------------------------------------------------------------------

fn adversarial_values() -> Vec<u64> {
    (0..N_ELEMENTS).map(|i| (i as u64) * 31_337).collect()
}

// ---------------------------------------------------------------------------
// Workload 5: schema evolution
// ---------------------------------------------------------------------------

const TELEMETRY_SCHEMA_ID: u64 = 0x4859_5048_5445_4c45;

#[derive(Debug)]
struct TelemetryV1 {
    device_name: String,
    sample_count: u32,
}

impl rustbinary::protocol::SchemaEncode for TelemetryV1 {
    const SCHEMA_ID: u64 = TELEMETRY_SCHEMA_ID;
    const SCHEMA_VERSION: u32 = 1;
    fn encode_fields(
        &self,
        encoder: &mut rustbinary::protocol::FieldEncoder,
    ) -> rustbinary::Result<()> {
        encoder.field(10, &self.device_name)?;
        encoder.field(20, &self.sample_count)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct TelemetryV2 {
    device_name: String,
    sample_count: u32,
    enabled: bool,
}

impl<'de> rustbinary::protocol::SchemaDecode<'de> for TelemetryV2 {
    const SCHEMA_ID: u64 = TELEMETRY_SCHEMA_ID;
    fn decode_fields(
        decoder: &mut rustbinary::protocol::FieldDecoder<'de>,
        _encoded_version: u32,
    ) -> rustbinary::Result<Self> {
        let device_name = decoder.required(10)?;
        let sample_count = decoder.required(20)?;
        let enabled = decoder.optional(30)?.unwrap_or(false);
        Ok(Self {
            device_name,
            sample_count,
            enabled,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SerV1 {
    device_name: String,
    sample_count: u32,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct SerV2 {
    device_name: String,
    sample_count: u32,
    #[serde(default)]
    enabled: bool,
}

fn evolution_value() -> TelemetryV1 {
    TelemetryV1 {
        device_name: "sensor/alpha-7".to_string(),
        sample_count: 4096,
    }
}

// ---------------------------------------------------------------------------
// Benchmark registration
// ---------------------------------------------------------------------------

/// The workload name of the benchmark group currently being registered, so
/// the [`codec_pair!`] macro can emit a machine-readable byte report without
/// every call site repeating it.
use std::cell::Cell;
thread_local! {
    static CURRENT_WORKLOAD: Cell<&'static str> = const { Cell::new("") };
}

/// Records the workload name for the current benchmark group.
fn set_workload(name: &'static str) {
    CURRENT_WORKLOAD.with(|cell| cell.set(name));
}

/// Registers an encode/decode pair for one codec under one workload.
/// `$bytes` must be a binding holding the encoded buffer (or an `&[u8]`).
///
/// Every registration emits a machine-readable byte line
/// (`BENCH_BYTES\t<workload>\t<codec>\t<bytes>`) that `scripts/bench_to_md.py`
/// merges with criterion's timing output into the markdown report.
macro_rules! codec_pair {
    ($group:expr, $codec:expr, $bytes:ident, $encode:expr, $decode:expr) => {{
        let encoded_len = black_box($bytes.len()) as u64;
        CURRENT_WORKLOAD.with(|cell| {
            println!("BENCH_BYTES\t{}\t{}\t{}", cell.get(), $codec, encoded_len);
        });
        $group.throughput(Throughput::Bytes(encoded_len));
        $group.bench_function(concat!($codec, "/encode"), |b| {
            b.iter_batched(|| (), |_| black_box($encode), BatchSize::SmallInput)
        });
        $group.bench_function(concat!($codec, "/decode"), |b| {
            b.iter(|| black_box($decode))
        });
    }};
}

fn homogeneous(c: &mut Criterion) {
    set_workload("homogeneous");
    let values = small_values();
    let mut group = c.benchmark_group("homogeneous");

    let rb: Vec<RbSmall> = values.iter().map(to_rb).collect();
    let rb_bytes = rustbinary::options()
        .with_limit(1 << 20)
        .serialize(&rb)
        .unwrap();
    codec_pair!(
        group,
        "rustbinary",
        rb_bytes,
        rustbinary::options()
            .with_limit(1 << 20)
            .serialize(&rb)
            .unwrap(),
        rustbinary::options()
            .with_limit(1 << 20)
            .deserialize::<Vec<RbSmall>>(&rb_bytes)
            .unwrap()
    );

    let compact = rustbinary::options()
        .with_limit(1 << 20)
        .with_compact_format();
    let rb_compact = compact.serialize(&rb).unwrap();
    codec_pair!(
        group,
        "rustbinary compact",
        rb_compact,
        compact.serialize(&rb).unwrap(),
        compact.deserialize::<Vec<RbSmall>>(&rb_compact).unwrap()
    );

    let ser: Vec<SerSmall> = values.iter().map(to_ser).collect();
    let b1 = bincode::serialize(&ser).unwrap();
    codec_pair!(
        group,
        "bincode1",
        b1,
        bincode::serialize(&ser).unwrap(),
        bincode::deserialize::<Vec<SerSmall>>(&b1).unwrap()
    );

    let b2 = bincode2::serde::encode_to_vec(&ser, bincode2::config::standard()).unwrap();
    codec_pair!(
        group,
        "bincode2",
        b2,
        bincode2::serde::encode_to_vec(&ser, bincode2::config::standard()).unwrap(),
        bincode2::serde::decode_from_slice::<Vec<SerSmall>, _>(&b2, bincode2::config::standard())
            .unwrap()
            .0
    );

    let b2n = bincode_next::serde::encode_to_vec(&ser, bincode_next::config::standard()).unwrap();
    codec_pair!(
        group,
        "bincode-next",
        b2n,
        bincode_next::serde::encode_to_vec(&ser, bincode_next::config::standard()).unwrap(),
        bincode_next::serde::decode_from_slice::<Vec<SerSmall>, _>(
            &b2n,
            bincode_next::config::standard(),
        )
        .unwrap()
        .0
    );

    let pc = postcard::to_allocvec(&ser).unwrap();
    codec_pair!(
        group,
        "postcard",
        pc,
        postcard::to_allocvec(&ser).unwrap(),
        postcard::from_bytes::<Vec<SerSmall>>(&pc).unwrap()
    );

    let rk: Vec<RkSmall> = values.iter().map(to_rk).collect();
    let rk_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&rk).unwrap();
    let rk_slice = rk_bytes.as_slice();
    codec_pair!(
        group,
        "rkyv",
        rk_slice,
        rkyv::to_bytes::<rkyv::rancor::Error>(&rk).unwrap(),
        rkyv::access::<rkyv::Archived<Vec<RkSmall>>, rkyv::rancor::Error>(&rk_bytes).unwrap()
    );

    let cb: Vec<CbSmall> = values.iter().map(to_cb).collect();
    let cb_bytes = minicbor::to_vec(&cb).unwrap();
    codec_pair!(
        group,
        "minicbor",
        cb_bytes,
        minicbor::to_vec(&cb).unwrap(),
        minicbor::decode::<Vec<CbSmall>>(&cb_bytes).unwrap()
    );

    group.finish();
}

fn heterogeneous(c: &mut Criterion) {
    set_workload("heterogeneous");
    let values = messages();
    let mut group = c.benchmark_group("heterogeneous");

    let rb: Vec<RbMsg> = values.iter().map(to_rb_msg).collect();
    let rb_bytes = rustbinary::options()
        .with_limit(1 << 20)
        .serialize(&rb)
        .unwrap();
    codec_pair!(
        group,
        "rustbinary",
        rb_bytes,
        rustbinary::options()
            .with_limit(1 << 20)
            .serialize(&rb)
            .unwrap(),
        rustbinary::options()
            .with_limit(1 << 20)
            .deserialize::<Vec<RbMsg>>(&rb_bytes)
            .unwrap()
    );

    let compact = rustbinary::options()
        .with_limit(1 << 20)
        .with_compact_format();
    let rb_compact = compact.serialize(&rb).unwrap();
    codec_pair!(
        group,
        "rustbinary compact",
        rb_compact,
        compact.serialize(&rb).unwrap(),
        compact.deserialize::<Vec<RbMsg>>(&rb_compact).unwrap()
    );

    let ser: Vec<SerMsg> = values.iter().map(to_ser_msg).collect();
    let b1 = bincode::serialize(&ser).unwrap();
    codec_pair!(
        group,
        "bincode1",
        b1,
        bincode::serialize(&ser).unwrap(),
        bincode::deserialize::<Vec<SerMsg>>(&b1).unwrap()
    );

    let b2 = bincode2::serde::encode_to_vec(&ser, bincode2::config::standard()).unwrap();
    codec_pair!(
        group,
        "bincode2",
        b2,
        bincode2::serde::encode_to_vec(&ser, bincode2::config::standard()).unwrap(),
        bincode2::serde::decode_from_slice::<Vec<SerMsg>, _>(&b2, bincode2::config::standard())
            .unwrap()
            .0
    );

    let b2n = bincode_next::serde::encode_to_vec(&ser, bincode_next::config::standard()).unwrap();
    codec_pair!(
        group,
        "bincode-next",
        b2n,
        bincode_next::serde::encode_to_vec(&ser, bincode_next::config::standard()).unwrap(),
        bincode_next::serde::decode_from_slice::<Vec<SerMsg>, _>(
            &b2n,
            bincode_next::config::standard(),
        )
        .unwrap()
        .0
    );

    let pc = postcard::to_allocvec(&ser).unwrap();
    codec_pair!(
        group,
        "postcard",
        pc,
        postcard::to_allocvec(&ser).unwrap(),
        postcard::from_bytes::<Vec<SerMsg>>(&pc).unwrap()
    );

    let cb: Vec<CbMsg> = values.iter().map(to_cb_msg).collect();
    let cb_bytes = minicbor::to_vec(&cb).unwrap();
    codec_pair!(
        group,
        "minicbor",
        cb_bytes,
        minicbor::to_vec(&cb).unwrap(),
        minicbor::decode::<Vec<CbMsg>>(&cb_bytes).unwrap()
    );

    group.finish();
}

fn borrowed(c: &mut Criterion) {
    set_workload("borrowed");
    let value = borrowed_value();
    let mut group = c.benchmark_group("borrowed");

    let rb = RbBorrowed {
        id: value.id,
        name: &value.name,
        note: &value.note,
    };
    let rb_bytes = rustbinary::options()
        .with_limit(1 << 16)
        .serialize(&rb)
        .unwrap();
    codec_pair!(
        group,
        "rustbinary",
        rb_bytes,
        rustbinary::options()
            .with_limit(1 << 16)
            .serialize(&rb)
            .unwrap(),
        rustbinary::options()
            .with_limit(1 << 16)
            .deserialize::<RbBorrowed<'_>>(&rb_bytes)
            .unwrap()
    );

    let compact = rustbinary::options()
        .with_limit(1 << 16)
        .with_compact_format();
    let rb_compact = compact.serialize(&rb).unwrap();
    codec_pair!(
        group,
        "rustbinary compact",
        rb_compact,
        compact.serialize(&rb).unwrap(),
        compact.deserialize::<RbBorrowed<'_>>(&rb_compact).unwrap()
    );

    let ser = SerBorrowed {
        id: value.id,
        name: &value.name,
        note: &value.note,
    };
    let b1 = bincode::serialize(&ser).unwrap();
    codec_pair!(
        group,
        "bincode1",
        b1,
        bincode::serialize(&ser).unwrap(),
        bincode::deserialize::<SerBorrowed<'_>>(&b1).unwrap()
    );

    // NOTE: bincode 2 and bincode-next are intentionally absent from this
    // workload. Their `decode_from_slice` requires
    // `T: for<'de> Deserialize<'de>`, which a borrowed serde type cannot
    // satisfy (a fixed `'a` cannot outlive every `'de`). That is a real
    // limitation of those opponents, not of the harness; it is reported
    // rather than papered over.

    let pc = postcard::to_allocvec(&ser).unwrap();
    codec_pair!(
        group,
        "postcard",
        pc,
        postcard::to_allocvec(&ser).unwrap(),
        postcard::from_bytes::<SerBorrowed<'_>>(&pc).unwrap()
    );

    let cb = CbBorrowed {
        id: value.id,
        name: &value.name,
        note: &value.note,
    };
    let cb_bytes = minicbor::to_vec(&cb).unwrap();
    codec_pair!(
        group,
        "minicbor",
        cb_bytes,
        minicbor::to_vec(&cb).unwrap(),
        minicbor::decode::<CbBorrowed<'_>>(&cb_bytes).unwrap()
    );

    group.finish();
}

fn adversarial(c: &mut Criterion) {
    set_workload("adversarial");
    let values = adversarial_values();
    let mut group = c.benchmark_group("adversarial");

    let rb_bytes = rustbinary::options()
        .with_limit(1 << 22)
        .with_collection_limit(200_000)
        .serialize(&values)
        .unwrap();
    codec_pair!(
        group,
        "rustbinary",
        rb_bytes,
        rustbinary::options()
            .with_limit(1 << 22)
            .with_collection_limit(200_000)
            .serialize(&values)
            .unwrap(),
        rustbinary::options()
            .with_limit(1 << 22)
            .with_collection_limit(200_000)
            .deserialize::<Vec<u64>>(&rb_bytes)
            .unwrap()
    );

    let compact = rustbinary::options()
        .with_limit(1 << 22)
        .with_collection_limit(200_000)
        .with_compact_format();
    let rb_compact = compact.serialize(&values).unwrap();
    codec_pair!(
        group,
        "rustbinary compact",
        rb_compact,
        compact.serialize(&values).unwrap(),
        compact.deserialize::<Vec<u64>>(&rb_compact).unwrap()
    );

    let b1 = bincode::serialize(&values).unwrap();
    codec_pair!(
        group,
        "bincode1",
        b1,
        bincode::serialize(&values).unwrap(),
        bincode::deserialize::<Vec<u64>>(&b1).unwrap()
    );

    let b2 = bincode2::serde::encode_to_vec(&values, bincode2::config::standard()).unwrap();
    codec_pair!(
        group,
        "bincode2",
        b2,
        bincode2::serde::encode_to_vec(&values, bincode2::config::standard()).unwrap(),
        bincode2::serde::decode_from_slice::<Vec<u64>, _>(&b2, bincode2::config::standard())
            .unwrap()
            .0
    );

    let b2n =
        bincode_next::serde::encode_to_vec(&values, bincode_next::config::standard()).unwrap();
    codec_pair!(
        group,
        "bincode-next",
        b2n,
        bincode_next::serde::encode_to_vec(&values, bincode_next::config::standard()).unwrap(),
        bincode_next::serde::decode_from_slice::<Vec<u64>, _>(
            &b2n,
            bincode_next::config::standard(),
        )
        .unwrap()
        .0
    );

    let pc = postcard::to_allocvec(&values).unwrap();
    codec_pair!(
        group,
        "postcard",
        pc,
        postcard::to_allocvec(&values).unwrap(),
        postcard::from_bytes::<Vec<u64>>(&pc).unwrap()
    );

    let cb_bytes = minicbor::to_vec(&values).unwrap();
    codec_pair!(
        group,
        "minicbor",
        cb_bytes,
        minicbor::to_vec(&values).unwrap(),
        minicbor::decode::<Vec<u64>>(&cb_bytes).unwrap()
    );

    group.finish();
}

fn schema_evolution(c: &mut Criterion) {
    set_workload("schema-evolution");
    let value = evolution_value();
    let mut group = c.benchmark_group("schema-evolution");

    // rustbinary: stable field-ID frame, V1 encode -> V2 decode.
    let rb_bytes = rustbinary::options()
        .with_schema_evolution()
        .serialize(&value)
        .unwrap();
    println!(
        "BENCH_BYTES\tschema-evolution\t{}\t{}",
        "rustbinary",
        rb_bytes.len()
    );
    let rb_bytes_ref = &rb_bytes;
    group.bench_function("rustbinary/decode-v1-as-v2", |b| {
        b.iter(|| {
            black_box(
                rustbinary::options()
                    .with_schema_evolution()
                    .deserialize::<TelemetryV2>(rb_bytes_ref)
                    .unwrap(),
            )
        })
    });
    group.bench_function("rustbinary/encode-v1", |b| {
        b.iter(|| {
            black_box(
                rustbinary::options()
                    .with_schema_evolution()
                    .serialize(&value)
                    .unwrap(),
            )
        })
    });

    // serde: V1 bytes decoded by a V2 type with a defaulted field.
    //
    // Sequential serde formats carry no field metadata, so a struct with an
    // appended field cannot always be decoded from older bytes: bincode 1,
    // bincode 2 and postcard error on the missing value, while bincode-next
    // (which tracks the field count) honours #[serde(default)]. Each codec
    // is probed once; codecs that cannot do it are reported via
    // `BENCH_EVO_FAIL` instead of panicking, so the report says so plainly.
    let ser_v1 = SerV1 {
        device_name: value.device_name.clone(),
        sample_count: value.sample_count,
    };
    let b1 = bincode::serialize(&ser_v1).unwrap();
    println!("BENCH_BYTES\tschema-evolution\tbincode1\t{}", b1.len());
    group.bench_function("bincode1/encode-v1", |b| {
        b.iter(|| black_box(bincode::serialize(&ser_v1).unwrap()))
    });
    if bincode::deserialize::<SerV2>(&b1).is_ok() {
        let b1_ref = &b1;
        group.bench_function("bincode1/decode-v1-as-v2", |b| {
            b.iter(|| black_box(bincode::deserialize::<SerV2>(b1_ref).unwrap()))
        });
    } else {
        println!("BENCH_EVO_FAIL\tschema-evolution\tbincode1");
    }
    let b2 = bincode2::serde::encode_to_vec(&ser_v1, bincode2::config::standard()).unwrap();
    println!("BENCH_BYTES\tschema-evolution\tbincode2\t{}", b2.len());
    group.bench_function("bincode2/encode-v1", |b| {
        b.iter(|| {
            black_box(
                bincode2::serde::encode_to_vec(&ser_v1, bincode2::config::standard()).unwrap(),
            )
        })
    });
    if bincode2::serde::decode_from_slice::<SerV2, _>(&b2, bincode2::config::standard()).is_ok() {
        let b2_ref = &b2;
        group.bench_function("bincode2/decode-v1-as-v2", |b| {
            b.iter(|| {
                black_box(
                    bincode2::serde::decode_from_slice::<SerV2, _>(
                        b2_ref,
                        bincode2::config::standard(),
                    )
                    .unwrap()
                    .0,
                )
            })
        });
    } else {
        println!("BENCH_EVO_FAIL\tschema-evolution\tbincode2");
    }
    let b2n =
        bincode_next::serde::encode_to_vec(&ser_v1, bincode_next::config::standard()).unwrap();
    println!("BENCH_BYTES\tschema-evolution\tbincode-next\t{}", b2n.len());
    group.bench_function("bincode-next/encode-v1", |b| {
        b.iter(|| {
            black_box(
                bincode_next::serde::encode_to_vec(&ser_v1, bincode_next::config::standard())
                    .unwrap(),
            )
        })
    });
    if bincode_next::serde::decode_from_slice::<SerV2, _>(&b2n, bincode_next::config::standard())
        .is_ok()
    {
        let b2n_ref = &b2n;
        group.bench_function("bincode-next/decode-v1-as-v2", |b| {
            b.iter(|| {
                black_box(
                    bincode_next::serde::decode_from_slice::<SerV2, _>(
                        b2n_ref,
                        bincode_next::config::standard(),
                    )
                    .unwrap()
                    .0,
                )
            })
        });
    } else {
        println!("BENCH_EVO_FAIL\tschema-evolution\tbincode-next");
    }
    let pc = postcard::to_allocvec(&ser_v1).unwrap();
    println!("BENCH_BYTES\tschema-evolution\tpostcard\t{}", pc.len());
    group.bench_function("postcard/encode-v1", |b| {
        b.iter(|| black_box(postcard::to_allocvec(&ser_v1).unwrap()))
    });
    if postcard::from_bytes::<SerV2>(&pc).is_ok() {
        let pc_ref = &pc;
        group.bench_function("postcard/decode-v1-as-v2", |b| {
            b.iter(|| black_box(postcard::from_bytes::<SerV2>(pc_ref).unwrap()))
        });
    } else {
        println!("BENCH_EVO_FAIL\tschema-evolution\tpostcard");
    }

    group.finish();
}

criterion_group!(
    benches,
    homogeneous,
    heterogeneous,
    borrowed,
    adversarial,
    schema_evolution
);
criterion_main!(benches);
