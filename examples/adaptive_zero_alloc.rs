use std::borrow::Cow;

use rustbinary::{CollectionStrategy, Error, StringStrategy};

fn main() -> rustbinary::Result<()> {
    let codec = rustbinary::options()
        .with_limit(64 * 1024)
        .with_collection_limit(4096)
        .with_adaptive_encoding();

    // A monotonic series normally selects delta encoding. Selection compares
    // complete payload sizes and has a deterministic tie-break order.
    let samples = [10_000_i64, 10_001, 10_003, 10_006, 10_010];
    let encoded_len = codec.encoded_i64_slice_size(&samples)?;
    let mut encoded = vec![0_u8; encoded_len];
    assert_eq!(
        codec.encode_i64_slice_into_slice(&mut encoded, &samples)?,
        encoded_len
    );
    assert_eq!(
        codec.collection_strategy(&encoded)?,
        CollectionStrategy::Delta
    );

    // Decoding into a stack buffer performs no allocator call in the codec.
    let mut decoded = [0_i64; 5];
    assert_eq!(
        codec.decode_i64_slice_into(&mut decoded, &encoded)?,
        samples.len()
    );
    assert_eq!(decoded, samples);

    // Capacity is checked before output is modified.
    let mut short = [i64::MIN; 4];
    assert!(matches!(
        codec.decode_i64_slice_into(&mut short, &encoded),
        Err(Error::BufferTooSmall {
            required: 5,
            available: 4
        })
    ));
    assert_eq!(short, [i64::MIN; 4]);

    let ascii_frame = codec.encode_string("telemetry/primary/healthy")?;
    assert_eq!(codec.string_strategy(&ascii_frame)?, StringStrategy::Ascii7);
    assert!(matches!(
        codec.decode_string_borrowed(&ascii_frame)?,
        Cow::Owned(_)
    ));
    let mut text_storage = [0_u8; 64];
    assert_eq!(
        codec.decode_string_into_slice(&mut text_storage, &ascii_frame)?,
        "telemetry/primary/healthy"
    );

    // Non-ASCII text remains raw UTF-8 and can borrow directly from the frame.
    let utf8_frame = codec.encode_string("\u{6e29}\u{5ea6}/edge-07")?;
    let borrowed = codec.decode_string_borrowed(&utf8_frame)?;
    assert_eq!(codec.string_strategy(&utf8_frame)?, StringStrategy::RawUtf8);
    assert!(matches!(
        borrowed,
        Cow::Borrowed("\u{6e29}\u{5ea6}/edge-07")
    ));

    Ok(())
}
