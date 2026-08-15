//! Schema-driven static-model rANS entropy coding.
//!
//! Run: `cargo run --example entropy --features entropy,derive`
//!
//! This example shows the non-compositional entropy layer: a from-scratch rANS
//! coder whose static models are derived from `Reflect` metadata. No
//! dictionary is transmitted — both sides derive identical alphabets from the
//! compiled schema.

use rustbinary::{Config, Model, RansDecoder, RansEncoder, Reflect, SchemaModel};

#[derive(Debug, Reflect)]
#[allow(dead_code)]
struct Telemetry {
    kind: TelemetryKind,
    #[entropy(symbols = 10)]
    priority: u8,
    level: bool,
    // Unknown alphabet -> byte model (256 symbols).
    payload: u8,
}

#[derive(Debug, Reflect)]
#[allow(dead_code)]
enum TelemetryKind {
    Temperature,
    Pressure,
    Humidity,
    Wind,
    Gust,
}

fn main() -> rustbinary::Result<()> {
    let config = rustbinary::options()
        .with_limit(1 << 16)
        .with_entropy_encoding();

    // 1. Derive one static model per field from the schema. This is the same
    //    on every peer that compiles the same type: no table crosses the wire.
    let schema = SchemaModel::from_reflect::<Telemetry>();
    for field in schema.fields() {
        println!("field {:>8}: {} symbols", field.name, field.model.symbols());
    }

    // 2. Code a symbol stream with the schema models. The enum discriminant
    //    is coded over its exact cardinality (5 variants -> ~2.32 bits each),
    //    the priority over 10 symbols, and the bool over 2. Two records are
    //    coded, so the model list repeats the four field models.
    let field_models = schema.models();
    let models: Vec<&Model> = [field_models.as_slice(), field_models.as_slice()]
        .concat()
        .into_iter()
        .collect();
    let symbols = [2u32, 7, 1, 200, 0, 3, 0, 0]; // (kind,priority,level,payload) x2
    let frame = config.encode_sequence(&models, &symbols)?;
    let decoded = config.decode_sequence(&models, &frame)?;
    assert_eq!(decoded, symbols);
    println!("sequence frame: {} bytes for 8 schema symbols", frame.len());

    // 3. Byte-alphabet compression with a skewed static prior: repetitive
    //    telemetry compresses hard, and replay verification (the hash-free
    //    re-encode check) confirms the frame is canonical on decode.
    let weights: Vec<u32> = {
        let mut weights = vec![1u32; 256];
        weights[b'0' as usize] = 1000;
        weights[b'1' as usize] = 500;
        weights
    };
    let model = Model::from_weights(&weights)?;
    let samples = vec![b'0'; 1024];
    let compressed = config.compress(&samples, &model)?;
    let restored = config.decompress(&compressed, &model)?;
    assert_eq!(restored, samples);
    println!(
        "byte frame: {} bytes for {} samples (raw would be {})",
        compressed.len(),
        samples.len(),
        samples.len()
    );

    // 4. Low-level coder: an enum discriminant at its information-theoretic
    //    rate, verifiable against the canonical final state.
    let kind_model = Model::from_uniform(5)?;
    let mut encoder = RansEncoder::new();
    for _ in 0..100 {
        encoder.put_symbol(&kind_model, 3)?; // 100 x "Gust"
    }
    let (final_state, payload) = encoder.finish();
    let mut decoder = RansDecoder::new(final_state, &payload);
    let mut restored_kinds = Vec::new();
    for _ in 0..100 {
        restored_kinds.push(decoder.get_symbol(&kind_model)?);
    }
    decoder.finish()?;
    restored_kinds.reverse();
    assert!(restored_kinds.iter().all(|&kind| kind == 3));
    println!(
        "100 enum symbols (5 variants) coded in {} bytes",
        payload.len()
    );
    Ok(())
}

// Keep `Config` in scope for doc clarity.
#[allow(dead_code)]
fn _uses(_: Config) {}
