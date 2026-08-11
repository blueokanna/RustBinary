use nextjson::{NsonDeserialize, NsonSerialize};
use rustbinary::core::{Error, ErrorCategory};

#[derive(Debug, PartialEq, NsonSerialize, NsonDeserialize)]
struct Packet<'a> {
    sequence: u64,
    #[njson(borrow)]
    topic: &'a str,
    #[njson(borrow)]
    payload: &'a str,
}

fn points_into(whole: &[u8], part: &[u8]) -> bool {
    let whole_start = whole.as_ptr() as usize;
    let whole_end = whole_start + whole.len();
    let part_start = part.as_ptr() as usize;
    part_start >= whole_start && part_start.saturating_add(part.len()) <= whole_end
}

fn main() -> rustbinary::core::Result<()> {
    let config = rustbinary::core::options()
        .with_limit(1024)
        .with_collection_limit(32)
        .reject_trailing_bytes();
    let value = Packet {
        sequence: 65_536,
        topic: "telemetry/temperature",
        payload: "23.5 C",
    };

    // Exact sizing and caller-owned output use one explicit wire profile.
    let required = usize::try_from(config.serialized_size(&value)?)
        .map_err(|_| Error::IntegerOverflow { target: "usize" })?;
    let mut frame = vec![0_u8; required];
    let written = config.serialize_into_slice(&mut frame, &value)?;
    assert_eq!(written, required);
    let mut repeated = vec![0_u8; required];
    assert_eq!(
        config.serialize_into_slice(&mut repeated, &value)?,
        required
    );
    assert_eq!(repeated, frame, "Core bytes must be stable");

    let decoded: Packet<'_> = config.deserialize(&frame)?;
    assert_eq!(decoded, value);
    assert!(points_into(&frame, decoded.topic.as_bytes()));
    assert!(points_into(&frame, decoded.payload.as_bytes()));

    // Caller capacity is a configuration failure and reports the exact need.
    let mut short = [0_u8; 4];
    let short_error = config.serialize_into_slice(&mut short, &value).unwrap_err();
    assert!(matches!(
        short_error,
        Error::BufferTooSmall {
            required: actual,
            available: 4,
        } if actual == required
    ));
    assert_eq!(short_error.category(), ErrorCategory::Configuration);

    // Strict decoding rejects unowned trailing bytes; permissive parsing is explicit.
    let mut with_trailing = frame.clone();
    with_trailing.push(0xaa);
    let trailing_error = config
        .deserialize::<Packet<'_>>(&with_trailing)
        .unwrap_err();
    assert!(matches!(
        trailing_error,
        Error::TrailingBytes { remaining: 1 }
    ));
    assert_eq!(trailing_error.category(), ErrorCategory::UserInput);
    assert_eq!(
        config
            .allow_trailing_bytes()
            .deserialize::<Packet<'_>>(&with_trailing)?,
        value
    );

    // Limits are checked before an oversized value is accepted.
    let mut limited_output = [0_u8; 16];
    let limit_error = rustbinary::core::options()
        .with_limit(2)
        .serialize_into_slice(&mut limited_output, &u64::MAX)
        .unwrap_err();
    assert!(matches!(limit_error, Error::SizeLimit { limit: 2 }));
    assert_eq!(limit_error.category(), ErrorCategory::Configuration);

    println!("Core encoded and borrowed a {written}-byte packet with strict policies");
    Ok(())
}
