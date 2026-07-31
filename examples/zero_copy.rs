use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Envelope<'a> {
    topic: &'a str,
    #[serde(borrow)]
    payload: &'a [u8],
    nested: Metadata<'a>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Metadata<'a> {
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
        payload: b"sensor-frame",
        nested: Metadata { source: "edge-07" },
    };
    let config = rustbinary::options().with_limit(4096);

    let required = config.serialized_size(&value)? as usize;
    let mut frame = vec![0; required];
    let written = config.serialize_into_slice(&mut frame, &value)?;

    let decoded: Envelope<'_> = config.deserialize(&frame[..written])?;
    assert_eq!(decoded, value);
    assert!(points_into(&frame, decoded.topic.as_bytes()));
    assert!(points_into(&frame, decoded.payload));
    assert!(points_into(&frame, decoded.nested.source.as_bytes()));
    Ok(())
}
