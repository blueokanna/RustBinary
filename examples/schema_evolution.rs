use rustbinary::{FieldDecoder, FieldEncoder, SchemaDecode, SchemaEncode};

const TELEMETRY_SCHEMA_ID: u64 = 0x4859_5048_5445_4c45;

#[derive(Debug, PartialEq)]
struct TelemetryV1 {
    device_name: String,
    sample_count: u32,
}

impl SchemaEncode for TelemetryV1 {
    const SCHEMA_ID: u64 = TELEMETRY_SCHEMA_ID;
    const SCHEMA_VERSION: u32 = 1;

    fn encode_fields(&self, encoder: &mut FieldEncoder) -> rustbinary::Result<()> {
        // IDs are permanent protocol identifiers; declaration order is irrelevant.
        encoder.field(20, &self.sample_count)?;
        encoder.field(10, &self.device_name)
    }
}

impl<'de> SchemaDecode<'de> for TelemetryV1 {
    const SCHEMA_ID: u64 = TELEMETRY_SCHEMA_ID;

    fn decode_fields(
        decoder: &mut FieldDecoder<'de>,
        _encoded_version: u32,
    ) -> rustbinary::Result<Self> {
        Ok(Self {
            device_name: decoder.required(10)?,
            sample_count: decoder.required(20)?,
        })
    }
}

#[derive(Debug, PartialEq)]
struct TelemetryV2<'a> {
    // The Rust field was renamed. Stable field ID 10 preserves compatibility.
    display_name: &'a str,
    sample_count: u32,
    enabled: bool,
    encoded_version: u32,
    unknown_field_ids: Vec<u32>,
}

impl SchemaEncode for TelemetryV2<'_> {
    const SCHEMA_ID: u64 = TELEMETRY_SCHEMA_ID;
    const SCHEMA_VERSION: u32 = 2;

    fn encode_fields(&self, encoder: &mut FieldEncoder) -> rustbinary::Result<()> {
        encoder.field(10, self.display_name)?;
        encoder.field(20, &self.sample_count)?;
        encoder.field(30, &self.enabled)
    }
}

impl<'de> SchemaDecode<'de> for TelemetryV2<'de> {
    const SCHEMA_ID: u64 = TELEMETRY_SCHEMA_ID;

    fn decode_fields(
        decoder: &mut FieldDecoder<'de>,
        encoded_version: u32,
    ) -> rustbinary::Result<Self> {
        let display_name = decoder.required(10)?;
        let sample_count = decoder.required(20)?;
        let enabled = decoder.or_default(30)?;
        let unknown_field_ids = decoder.unknown_fields().map(|field| field.id).collect();
        Ok(Self {
            display_name,
            sample_count,
            enabled,
            encoded_version,
            unknown_field_ids,
        })
    }
}

fn main() -> rustbinary::Result<()> {
    let codec = rustbinary::options()
        .with_limit(64 * 1024)
        .with_collection_limit(128)
        .with_schema_evolution();

    let old = TelemetryV1 {
        device_name: "edge-07".into(),
        sample_count: 91,
    };
    let old_frame = codec.serialize(&old)?;
    let upgraded: TelemetryV2<'_> = codec.deserialize(&old_frame)?;
    assert_eq!(upgraded.display_name, "edge-07");
    assert_eq!(upgraded.sample_count, 91);
    assert!(!upgraded.enabled); // Field 30 was absent, so Default is used.
    assert_eq!(upgraded.encoded_version, 1);

    let current = TelemetryV2 {
        display_name: "edge-09",
        sample_count: 144,
        enabled: true,
        encoded_version: 2,
        unknown_field_ids: Vec::new(),
    };
    let current_frame = codec.serialize(&current)?;
    let downgraded: TelemetryV1 = codec.deserialize(&current_frame)?;
    assert_eq!(downgraded.device_name, "edge-09");
    assert_eq!(downgraded.sample_count, 144);

    Ok(())
}
