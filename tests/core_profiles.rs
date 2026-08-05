use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Borrowed<'a> {
    id: u64,
    delta: i32,
    name: &'a str,
    #[serde(borrow)]
    payload: &'a [u8],
}

#[cfg(feature = "bincode-compat")]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
enum CompatEvent {
    Idle,
    Data(u32),
    Point { x: i16, y: i16 },
}

#[cfg(feature = "bincode-compat")]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct CompatFrame<'a> {
    tag: u16,
    active: bool,
    scalar: char,
    ratio: f32,
    event: CompatEvent,
    optional: Option<i64>,
    name: &'a str,
    #[serde(borrow)]
    payload: &'a [u8],
}

#[test]
fn core_slice_codec_needs_neither_std_io_nor_codec_allocation() {
    let value = Borrowed {
        id: 65_536,
        delta: -7,
        name: "compact-v1",
        payload: b"caller-owned",
    };
    let config = rustbinary::options().with_limit(128);
    let required = config.serialized_size(&value).unwrap() as usize;
    let mut output = [0u8; 128];
    let written = config.serialize_into_slice(&mut output, &value).unwrap();
    assert_eq!(written, required);

    let decoded: Borrowed<'_> = config.deserialize(&output[..written]).unwrap();
    assert_eq!(decoded, value);
    let start = output.as_ptr() as usize;
    let pointer = decoded.name.as_ptr() as usize;
    assert!((start..start + written).contains(&pointer));

    let mut short = [0u8; 3];
    assert!(matches!(
        config.serialize_into_slice(&mut short, &value),
        Err(rustbinary::Error::BufferTooSmall {
            required: actual,
            available: 3
        }) if actual == required
    ));
}

#[test]
fn public_slice_and_count_writers_report_exact_capacity() {
    use rustbinary::EncodeWriter;

    let mut output = [0u8; 3];
    let mut writer = rustbinary::SliceWriter::new(&mut output);
    writer.write_all(b"abcdef").unwrap();
    assert_eq!(writer.required_len(), 6);
    assert_eq!(writer.written_len(), 3);
    assert!(matches!(
        writer.finish(),
        Err(rustbinary::Error::BufferTooSmall {
            required: 6,
            available: 3
        })
    ));
    assert_eq!(&output, b"abc");

    let mut counter = rustbinary::CountWriter::new();
    counter.write_all(b"abc").unwrap();
    counter.write_all(b"def").unwrap();
    assert_eq!(counter.written(), 6);
}

#[cfg(feature = "adaptive")]
#[test]
fn adaptive_profile_has_pure_no_std_caller_buffer_paths() {
    let codec = rustbinary::options().with_adaptive_encoding();

    let text = "telemetry/edge";
    let mut encoded_text = [0u8; 64];
    let text_written = codec
        .encode_string_into_slice(&mut encoded_text, text)
        .unwrap();
    let mut decoded_text = [0u8; 32];
    assert_eq!(
        codec
            .decode_string_into_slice(&mut decoded_text, &encoded_text[..text_written])
            .unwrap(),
        text
    );

    let values = [1_000i64, 1_001, 1_002, 1_003];
    let mut encoded_values = [0u8; 64];
    let values_written = codec
        .encode_i64_slice_into_slice(&mut encoded_values, &values)
        .unwrap();
    let mut decoded_values = [0i64; 4];
    assert_eq!(
        codec
            .decode_i64_slice_into(&mut decoded_values, &encoded_values[..values_written],)
            .unwrap(),
        values.len()
    );
    assert_eq!(decoded_values, values);
}

#[cfg(feature = "alloc")]
#[test]
fn alloc_profile_preserves_owned_values() {
    let value = ("owned".to_owned(), vec![1u32, 251, 65_536]);
    let bytes = rustbinary::options().serialize(&value).unwrap();
    let decoded: (String, Vec<u32>) = rustbinary::options().deserialize(&bytes).unwrap();
    assert_eq!(decoded, value);
}

#[cfg(feature = "bincode-compat")]
#[test]
fn bincode_compat_primitive_golden_vectors_are_stable() {
    type GoldenVector<'a> = ((u64, i64, &'a str, &'a [u8]), &'a [u8]);
    let values: &[GoldenVector<'_>] = &[
        ((0, -1, "", &[0]), &[0, 1, 0, 1, 0]),
        (
            (250, 251, "edge", &[1, 2, 3]),
            &[250, 251, 246, 1, 4, b'e', b'd', b'g', b'e', 3, 1, 2, 3],
        ),
        (
            (65_536, -65_536, "telemetry", &[0, 255]),
            &[
                252, 0, 0, 1, 0, 252, 255, 255, 1, 0, 9, b't', b'e', b'l', b'e', b'm', b'e', b't',
                b'r', b'y', 2, 0, 255,
            ],
        ),
    ];
    for &(value, golden) in values {
        let mut compact = [0u8; 128];
        let compact_written = rustbinary::options()
            .serialize_into_slice(&mut compact, &value)
            .unwrap();
        let mut own = vec![
            0u8;
            rustbinary::bincode_compat()
                .serialized_size(&value)
                .unwrap() as usize
        ];
        let written = rustbinary::bincode_compat()
            .serialize_into_slice(&mut own, &value)
            .unwrap();
        own.truncate(written);
        assert_eq!(own, golden);
        assert_eq!(&compact[..compact_written], golden);

        let (decoded, consumed): ((u64, i64, &str, &[u8]), usize) =
            rustbinary::bincode_compat().deserialize(&own).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(consumed, own.len());
    }
}

#[cfg(feature = "bincode-compat")]
#[test]
fn independent_bincode_profile_matches_structural_golden() {
    let value = CompatFrame {
        tag: 65_535,
        active: true,
        scalar: '\u{754c}',
        ratio: 1.5,
        event: CompatEvent::Point { x: -9, y: 17 },
        optional: Some(-251),
        name: "rustbinary",
        payload: b"borrowed",
    };
    let golden = [
        251, 255, 255, 1, 0xe7, 0x95, 0x8c, 0, 0, 0xc0, 0x3f, 2, 17, 34, 1, 251, 245, 1, 10, b'r',
        b'u', b's', b't', b'b', b'i', b'n', b'a', b'r', b'y', 8, b'b', b'o', b'r', b'r', b'o',
        b'w', b'e', b'd',
    ];
    let mut output = [0u8; 128];
    let written = rustbinary::bincode_compat()
        .serialize_into_slice(&mut output, &value)
        .unwrap();
    assert_eq!(&output[..written], golden);

    output[written] = 0xaa;
    let (decoded, consumed): (CompatFrame<'_>, usize) = rustbinary::bincode_compat()
        .deserialize(&output[..written + 1])
        .unwrap();
    assert_eq!(decoded, value);
    assert_eq!(consumed, written);
}
