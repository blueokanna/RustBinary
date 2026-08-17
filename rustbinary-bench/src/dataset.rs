//! Shared benchmark datasets, defined once in plain Rust and mapped onto each
//! codec's traits.
//!
//! The datasets mirror the workloads rustbinary targets:
//!
//! - **Small** — a hot-path header-like record (few fields, small integers).
//! - **Telemetry** — a realistic sensor frame with strings, floats, and a
//!   nested array of readings.
//! - **BulkNumerics** — a large `Vec<i64>` (the adaptive delta/RLE use case).
//! - **BulkStrings** — a large `Vec<String>` (the entropy byte-model case).

#[derive(Clone, Debug, PartialEq)]
pub struct Small {
    pub enabled: bool,
    pub mode: u8,
    pub sequence: u64,
    pub delta: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Telemetry {
    pub device: String,
    pub metric: String,
    pub value: f64,
    pub samples: Vec<i32>,
    pub status: Option<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BulkNumerics {
    pub id: u64,
    pub values: Vec<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BulkStrings {
    pub id: u64,
    pub entries: Vec<String>,
}

pub struct Datasets {
    pub small: Small,
    pub telemetry: Telemetry,
    pub bulk_numerics: BulkNumerics,
    pub bulk_strings: BulkStrings,
}

pub fn datasets() -> Datasets {
    Datasets {
        small: Small {
            enabled: true,
            mode: 3,
            sequence: 4_294_967_296,
            delta: -42,
        },
        telemetry: Telemetry {
            device: "sensor/alpha-7".to_string(),
            metric: "temperature/cpu".to_string(),
            value: 47.25,
            samples: (0..16).map(|i| (i * 37 - 100) as i32).collect(),
            status: Some(0x0a),
        },
        bulk_numerics: BulkNumerics {
            id: 99,
            values: (0..4096).map(|i| (i as i64) * 3 - 2000).collect(),
        },
        bulk_strings: BulkStrings {
            id: 7,
            entries: (0..256)
                .map(|i| format!("entry/{i:04}/metric/temperature"))
                .collect(),
        },
    }
}

// ---------------------------------------------------------------------------
// rustbinary (nextjson) mappings
// ---------------------------------------------------------------------------

#[derive(
    Debug, nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::CompactBinary
)]
pub struct RbSmall {
    pub enabled: bool,
    pub mode: u8,
    pub sequence: u64,
    pub delta: i32,
}

#[derive(
    Debug, nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::CompactBinary
)]
pub struct RbTelemetry {
    pub device: String,
    pub metric: String,
    pub value: f64,
    pub samples: Vec<i32>,
    pub status: Option<u8>,
}

#[derive(
    Debug, nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::CompactBinary
)]
pub struct RbBulkNumerics {
    pub id: u64,
    pub values: Vec<i64>,
}

#[derive(
    Debug, nextjson::NsonSerialize, nextjson::NsonDeserialize, rustbinary::CompactBinary
)]
pub struct RbBulkStrings {
    pub id: u64,
    pub entries: Vec<String>,
}

// ---------------------------------------------------------------------------
// serde-family mappings (bincode 1/2, postcard, cbor4ii)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SerSmall {
    pub enabled: bool,
    pub mode: u8,
    pub sequence: u64,
    pub delta: i32,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SerTelemetry {
    pub device: String,
    pub metric: String,
    pub value: f64,
    pub samples: Vec<i32>,
    pub status: Option<u8>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SerBulkNumerics {
    pub id: u64,
    pub values: Vec<i64>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SerBulkStrings {
    pub id: u64,
    pub entries: Vec<String>,
}

pub fn to_ser_small(d: &Small) -> SerSmall {
    SerSmall {
        enabled: d.enabled,
        mode: d.mode,
        sequence: d.sequence,
        delta: d.delta,
    }
}
pub fn to_ser_telemetry(d: &Telemetry) -> SerTelemetry {
    SerTelemetry {
        device: d.device.clone(),
        metric: d.metric.clone(),
        value: d.value,
        samples: d.samples.clone(),
        status: d.status,
    }
}
pub fn to_ser_numerics(d: &BulkNumerics) -> SerBulkNumerics {
    SerBulkNumerics {
        id: d.id,
        values: d.values.clone(),
    }
}
pub fn to_ser_strings(d: &BulkStrings) -> SerBulkStrings {
    SerBulkStrings {
        id: d.id,
        entries: d.entries.clone(),
    }
}

// ---------------------------------------------------------------------------
// minicbor mappings
// ---------------------------------------------------------------------------

#[derive(minicbor::Encode, minicbor::Decode, Clone, Debug)]
pub struct CborSmall {
    #[n(0)]
    pub enabled: bool,
    #[n(1)]
    pub mode: u8,
    #[n(2)]
    pub sequence: u64,
    #[n(3)]
    pub delta: i32,
}

#[derive(minicbor::Encode, minicbor::Decode, Clone, Debug)]
pub struct CborTelemetry {
    #[n(0)]
    pub device: String,
    #[n(1)]
    pub metric: String,
    #[n(2)]
    pub value: f64,
    #[n(3)]
    pub samples: Vec<i32>,
    #[n(4)]
    pub status: Option<u8>,
}

#[derive(minicbor::Encode, minicbor::Decode, Clone, Debug)]
pub struct CborBulkNumerics {
    #[n(0)]
    pub id: u64,
    #[n(1)]
    pub values: Vec<i64>,
}

#[derive(minicbor::Encode, minicbor::Decode, Clone, Debug)]
pub struct CborBulkStrings {
    #[n(0)]
    pub id: u64,
    #[n(1)]
    pub entries: Vec<String>,
}

pub fn to_cbor_small(d: &Small) -> CborSmall {
    CborSmall {
        enabled: d.enabled,
        mode: d.mode,
        sequence: d.sequence,
        delta: d.delta,
    }
}
pub fn to_cbor_telemetry(d: &Telemetry) -> CborTelemetry {
    CborTelemetry {
        device: d.device.clone(),
        metric: d.metric.clone(),
        value: d.value,
        samples: d.samples.clone(),
        status: d.status,
    }
}
pub fn to_cbor_numerics(d: &BulkNumerics) -> CborBulkNumerics {
    CborBulkNumerics {
        id: d.id,
        values: d.values.clone(),
    }
}
pub fn to_cbor_strings(d: &BulkStrings) -> CborBulkStrings {
    CborBulkStrings {
        id: d.id,
        entries: d.entries.clone(),
    }
}
