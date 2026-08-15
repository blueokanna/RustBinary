use nextjson::{NsonDeserialize, NsonSerialize};

use rustbinary::ErrorCategory;

#[derive(Debug, NsonDeserialize, PartialEq, NsonSerialize)]
struct Borrowed<'a> {
    id: u64,
    delta: i32,
    #[njson(borrow)]
    name: &'a str,
    #[njson(borrow)]
    payload: &'a str,
}

#[test]
fn core_slice_codec_needs_neither_std_io_nor_codec_allocation() {
    let value = Borrowed {
        id: 65_536,
        delta: -7,
        name: "compact-v1",
        payload: "caller-owned",
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

#[test]
fn defaults_are_bounded_and_errors_have_stable_responsibility() {
    assert_eq!(
        rustbinary::options(),
        rustbinary::Config::default(),
        "the documented Core profile must remain the Rust default"
    );
    assert_eq!(rustbinary::DEFAULT_SIZE_LIMIT, 64 * 1024 * 1024);
    assert_eq!(rustbinary::DEFAULT_COLLECTION_LIMIT, 1_000_000);
    assert_eq!(
        rustbinary::Error::UnexpectedEnd.category(),
        ErrorCategory::UserInput
    );
    assert_eq!(
        rustbinary::Error::InvalidFrame("bad magic").category(),
        ErrorCategory::Protocol
    );
    assert_eq!(
        rustbinary::Error::BufferTooSmall {
            required: 2,
            available: 1,
        }
        .category(),
        ErrorCategory::Configuration
    );
}

#[cfg(feature = "alloc")]
#[test]
fn top_level_api_uses_the_compact_core_profile() {
    let value = (251_u64, -2_i32, "A");
    let expected = rustbinary::options().serialize(&value).unwrap();
    assert_eq!(rustbinary::serialize(&value).unwrap(), expected);
    assert_eq!(
        rustbinary::deserialize::<(u64, i32, String)>(&expected).unwrap(),
        (251, -2, "A".to_owned())
    );
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

#[cfg(feature = "alloc")]
#[test]
fn type_mismatch_errors_name_the_expecting_type() {
    // nextjson 0.1.3's `FormatDecoder::set_expecting` lets a derived decoder
    // install a type description so container mismatches name the type the
    // caller actually tried to decode instead of a bare structural token.
    #[derive(Debug, NsonDeserialize, NsonSerialize)]
    #[njson(expecting = "a telemetry packet")]
    struct TelemetryPacket {
        sequence: u64,
    }

    // A scalar where the struct is expected: the error must name the type.
    let scalar = rustbinary::options().serialize(&42_u64).unwrap();
    let error = rustbinary::options()
        .deserialize::<TelemetryPacket>(&scalar)
        .unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("a telemetry packet"),
        "container mismatch should name the expecting type, got: {message}"
    );
    assert!(
        message.contains("number"),
        "container mismatch should report the found token, got: {message}"
    );

    // An array where the struct is expected: same richer diagnostic.
    let array = rustbinary::options().serialize(&vec![1_u64]).unwrap();
    let error = rustbinary::options()
        .deserialize::<TelemetryPacket>(&array)
        .unwrap_err();
    assert!(
        error.to_string().contains("a telemetry packet"),
        "array mismatch should also name the expecting type, got: {error}"
    );

    // Scalar expectations stay descriptive even with `set_expecting` installed
    // (they are already meaningful without the surrounding type), matching
    // nextjson 0.1.3's `expecting_for` behavior.
    #[derive(Debug, NsonDeserialize, NsonSerialize)]
    #[njson(expecting = "a labeled sample")]
    struct LabeledSample {
        label: String,
    }
    let bool_frame = rustbinary::options().serialize(&true).unwrap();
    let error = rustbinary::options()
        .deserialize::<LabeledSample>(&bool_frame)
        .unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("a labeled sample"),
        "expected the container mismatch to name the type, got: {message}"
    );
}

#[cfg(feature = "alloc")]
#[test]
fn collection_limit_applies_to_nested_sibling_containers() {
    // Per-collection accounting: each nested container gets its own element
    // budget, so many small siblings are legal while one oversized container
    // is rejected. This locks the `container_sep` counting contract.
    #[derive(Debug, NsonDeserialize, NsonSerialize)]
    struct Grid {
        rows: Vec<Vec<u64>>,
    }

    let limit = rustbinary::options().with_collection_limit(4);
    let ok = Grid {
        rows: vec![vec![1, 2], vec![3, 4]],
    };
    let frame = limit.serialize(&ok).unwrap();
    let decoded: Grid = limit.deserialize(&frame).unwrap();
    assert_eq!(decoded.rows, ok.rows);

    let too_many = Grid {
        rows: vec![vec![1, 2, 3, 4, 5]],
    };
    // The encoder enforces the collection limit too, so serialize under an
    // unlimited config and decode under the strict limit to exercise the
    // decoder-side per-collection accounting.
    let frame = rustbinary::options().serialize(&too_many).unwrap();
    assert!(matches!(
        limit.deserialize::<Grid>(&frame),
        Err(rustbinary::Error::CollectionLimit { limit: 4 })
    ));
}
