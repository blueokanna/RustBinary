use nextjson::{NsonDeserialize, NsonSerialize};

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
struct Envelope<'a> {
    #[njson(borrow)]
    topic: &'a str,
    #[njson(borrow)]
    payload: &'a str,
    nested: Metadata<'a>,
}

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
struct Metadata<'a> {
    #[njson(borrow)]
    source: &'a str,
}

fn points_into(whole: &[u8], part: &[u8]) -> bool {
    let start = whole.as_ptr() as usize;
    let end = start + whole.len();
    let part_start = part.as_ptr() as usize;
    part_start >= start && part_start + part.len() <= end
}

fn main() -> rustbinary::Result<()> {
    let value = Envelope {
        topic: "events/temperature",
        payload: "sensor-frame",
        nested: Metadata { source: "edge-07" },
    };
    let config = rustbinary::core::options()
        .with_limit(4096)
        .with_collection_limit(64);

    let required = config.serialized_size(&value)? as usize;
    let mut frame = vec![0; required];
    let written = config.serialize_into_slice(&mut frame, &value)?;

    let decoded: Envelope<'_> = config.deserialize(&frame[..written])?;
    assert_eq!(decoded, value);
    assert!(points_into(&frame, decoded.topic.as_bytes()));
    assert!(points_into(&frame, decoded.payload.as_bytes()));
    assert!(points_into(&frame, decoded.nested.source.as_bytes()));
    assert_eq!(written, required);

    println!("decoded 3 borrowed fields from a {written}-byte caller-owned frame");
    Ok(())
}
