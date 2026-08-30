use rustbinary::{protocol::CollectionStrategy, protocol::StringStrategy, Error};

fn main() -> rustbinary::Result<()> {
    let codec = rustbinary::options()
        .with_limit(64 * 1024)
        .with_collection_limit(4096)
        .with_adaptive_encoding()
        .with_adaptive_mode(rustbinary::AdaptiveMode::Exact);

    let samples = [10_000_i64, 10_001, 10_003, 10_006, 10_010];
    let encoded_len = codec.encoded_i64_slice_size(&samples)?;
    let mut encoded_storage = [0_u8; 64];
    assert_eq!(
        codec.encode_i64_slice_into_slice(&mut encoded_storage, &samples)?,
        encoded_len
    );
    let encoded = &encoded_storage[..encoded_len];
    assert_eq!(
        codec.collection_strategy(encoded)?,
        CollectionStrategy::Delta
    );

    // Decoding into a stack buffer performs no allocator call in the codec.
    let mut decoded = [0_i64; 5];
    assert_eq!(
        codec.decode_i64_slice_into(&mut decoded, encoded)?,
        samples.len()
    );
    assert_eq!(decoded, samples);

    // Capacity is checked before output is modified.
    let mut short = [i64::MIN; 4];
    assert!(matches!(
        codec.decode_i64_slice_into(&mut short, encoded),
        Err(Error::BufferTooSmall {
            required: 5,
            available: 4
        })
    ));
    assert_eq!(short, [i64::MIN; 4]);

    let ascii = "telemetry/primary/healthy";
    let ascii_len = codec.encoded_string_size(ascii)?;
    let mut ascii_storage = [0_u8; 64];
    assert_eq!(
        codec.encode_string_into_slice(&mut ascii_storage, ascii)?,
        ascii_len
    );
    let ascii_frame = &ascii_storage[..ascii_len];
    assert_eq!(codec.string_strategy(ascii_frame)?, StringStrategy::Ascii7);
    let mut text_storage = [0_u8; 64];
    assert_eq!(
        codec.decode_string_into_slice(&mut text_storage, ascii_frame)?,
        ascii
    );

    // Non-ASCII text remains raw UTF-8 and can borrow directly from the frame.
    let utf8 = "\u{6e29}\u{5ea6}/edge-07";
    let utf8_len = codec.encoded_string_size(utf8)?;
    let mut utf8_storage = [0_u8; 64];
    assert_eq!(
        codec.encode_string_into_slice(&mut utf8_storage, utf8)?,
        utf8_len
    );
    let utf8_frame = &utf8_storage[..utf8_len];
    assert_eq!(codec.string_strategy(utf8_frame)?, StringStrategy::RawUtf8);
    let borrowed = codec.decode_string_borrowed(utf8_frame)?;
    assert_eq!(borrowed, utf8);
    assert!(matches!(borrowed, std::borrow::Cow::Borrowed(_)));

    println!(
        "adaptive caller-buffer paths: {encoded_len} integer bytes, {ascii_len} ASCII bytes, {utf8_len} UTF-8 bytes"
    );

    Ok(())
}
