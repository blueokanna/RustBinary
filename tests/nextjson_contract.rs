use nextjson::{FormatEncoder, NsonSerialize};
use rustbinary::{options, Error};

struct InvalidEvents(u8);

impl nextjson::NsonSchema for InvalidEvents {
    const SCHEMA: nextjson::TypeSchema = nextjson::TypeSchema::Unit;
}

impl NsonSerialize for InvalidEvents {
    fn nextencode<E: FormatEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        match self.0 {
            0 => Ok(()),
            1 => {
                encoder.write_null()?;
                encoder.write_null()
            }
            2 => {
                encoder.begin_array()?;
                encoder.end_object()
            }
            3 => {
                encoder.begin_object()?;
                encoder.key("missing")?;
                encoder.end_object()
            }
            4 => {
                encoder.begin_array()?;
                encoder.separator()?;
                encoder.end_array()
            }
            5 => {
                encoder.begin_array()?;
                encoder.write_null()?;
                encoder.end_array()
            }
            6 => {
                encoder.begin_object()?;
                encoder.write_null()?;
                encoder.end_object()
            }
            _ => {
                encoder.begin_object()?;
                encoder.separator()?;
                encoder.end_object()
            }
        }
    }
}

#[test]
fn invalid_event_streams_never_report_success() {
    for case in 0..8 {
        assert!(
            options().serialize(&InvalidEvents(case)).is_err(),
            "binary case {case}"
        );
        #[cfg(feature = "cbor")]
        assert!(
            options()
                .with_cbor_format()
                .serialize(&InvalidEvents(case))
                .is_err(),
            "CBOR case {case}"
        );
    }
}

struct SwallowsWriteFailure;

impl nextjson::NsonSchema for SwallowsWriteFailure {
    const SCHEMA: nextjson::TypeSchema = nextjson::TypeSchema::Unit;
}

impl NsonSerialize for SwallowsWriteFailure {
    fn nextencode<E: FormatEncoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        let _ = encoder.write_str("longer than the budget");
        let _ = encoder.end_array();
        Ok(())
    }
}

#[test]
fn encoder_keeps_the_first_failure_even_if_custom_code_swallows_it() {
    assert!(matches!(
        options().with_limit(0).serialize(&SwallowsWriteFailure),
        Err(Error::SizeLimit { limit: 0 })
    ));
    #[cfg(feature = "cbor")]
    assert!(matches!(
        options()
            .with_limit(0)
            .with_cbor_format()
            .serialize(&SwallowsWriteFailure),
        Err(Error::SizeLimit { limit: 0 })
    ));
}

struct RecoversAfterLimit;

impl<'de> nextjson::NsonDeserialize<'de> for RecoversAfterLimit {
    fn nextdecode_into<D: nextjson::FormatDecoder<'de>>(
        decoder: &mut D,
        out: &mut nextjson::de::DecodeSlot<Self>,
    ) -> Result<(), D::Error> {
        let mark = decoder.save();
        let _ = <Vec<u8> as nextjson::NsonDeserialize>::nextdecode(decoder);
        decoder.restore(mark);
        let _ = decoder.next_token();
        out.write(Self);
        Ok(())
    }
}

#[test]
fn speculative_recovery_cannot_clear_collection_or_depth_limits() {
    let value = vec![1u8];
    for config in [
        options().with_collection_limit(0),
        options().with_depth_limit(0),
    ] {
        let bytes = options().serialize(&value).unwrap();
        assert!(config
            .allow_trailing_bytes()
            .deserialize::<RecoversAfterLimit>(&bytes)
            .is_err());
        #[cfg(feature = "cbor")]
        {
            let bytes = options().with_cbor_format().serialize(&value).unwrap();
            assert!(config
                .allow_trailing_bytes()
                .with_cbor_format()
                .deserialize::<RecoversAfterLimit>(&bytes)
                .is_err());
        }
    }
}

#[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
#[njson(untagged)]
enum Choice {
    Pair((u32, String)),
    Numbers(Vec<u32>),
    Text(String),
}

#[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
#[njson(tag = "kind", content = "payload")]
enum Tagged {
    Empty,
    Values(Vec<Choice>),
}

#[test]
fn nextjson_derived_tagged_and_backtracking_shapes_roundtrip() {
    for value in [
        Tagged::Empty,
        Tagged::Values(vec![
            Choice::Numbers(vec![1, 2, 3]),
            Choice::Text("text".into()),
            Choice::Pair((4, "four".into())),
        ]),
    ] {
        for config in [
            options(),
            options().with_big_endian(),
            options().with_fixint_encoding(),
            options().with_fixint_encoding().with_big_endian(),
        ] {
            let bytes = config.serialize(&value).unwrap();
            assert_eq!(config.deserialize::<Tagged>(&bytes).unwrap(), value);
        }
        #[cfg(feature = "cbor")]
        {
            let config = options().with_cbor_format();
            let bytes = config.serialize(&value).unwrap();
            assert_eq!(config.deserialize::<Tagged>(&bytes).unwrap(), value);
        }
    }
}

#[cfg(feature = "cbor")]
#[test]
fn cbor_borrows_native_strings_bytes_and_fingerprinted_payloads() {
    let config = options().with_cbor_format();
    let text = config.serialize("borrowed").unwrap();
    let borrowed = config.deserialize::<&str>(&text).unwrap();
    assert_eq!(borrowed, "borrowed");
    assert_eq!(borrowed.as_ptr(), text[1..].as_ptr());
    let bytes = config.serialize(&nextjson::Bytes(b"bytes")).unwrap();
    let borrowed = config.deserialize::<nextjson::Bytes<'_>>(&bytes).unwrap();
    assert_eq!(borrowed.0, b"bytes");
    assert_eq!(borrowed.0.as_ptr(), bytes[1..].as_ptr());
    #[cfg(feature = "fingerprint")]
    {
        let codec = config.with_fingerprint();
        let frame = codec.serialize(&"framed").unwrap();
        let borrowed = codec.deserialize::<&str>(&frame).unwrap();
        assert_eq!(borrowed, "framed");
        assert_eq!(
            borrowed.as_ptr(),
            frame[frame.len() - borrowed.len()..].as_ptr()
        );
    }
}

#[cfg(feature = "cbor")]
#[test]
fn cbor_stream_slice_and_count_writers_agree() {
    let value = (17u64, "text", vec![1i64, -2, 3]);
    for config in [
        options().with_cbor_format(),
        options().with_cbor_format().with_deterministic_encoding(),
    ] {
        let bytes = config.serialize(&value).unwrap();
        assert_eq!(config.serialized_size(&value).unwrap(), bytes.len() as u64);
        let mut buffer = vec![0; bytes.len()];
        assert_eq!(
            config.serialize_into_slice(&mut buffer, &value).unwrap(),
            bytes.len()
        );
        assert_eq!(buffer, bytes);
        assert!(
            matches!(config.serialize_into_slice(&mut buffer[..1], &value), Err(Error::BufferTooSmall { required, available: 1 }) if required == bytes.len())
        );
        #[cfg(feature = "std")]
        {
            let mut streamed = Vec::new();
            config.serialize_into(&mut streamed, &value).unwrap();
            assert_eq!(streamed, bytes);
        }
    }
}

#[derive(Debug, PartialEq, nextjson::NsonSerialize, nextjson::NsonDeserialize)]
struct Flattened {
    #[njson(rename = "wire_name")]
    name: String,
    #[njson(default)]
    attempts: u32,
    #[njson(flatten)]
    extra: std::collections::BTreeMap<String, u64>,
}

#[test]
fn nextjson_rename_default_and_flatten_keep_their_wire_semantics() {
    let value = nextjson::json!({"wire_name": "sensor", "sequence": 23});
    let expected = Flattened {
        name: "sensor".into(),
        attempts: 0,
        extra: [("sequence".into(), 23)].into_iter().collect(),
    };
    let bytes = options().serialize(&value).unwrap();
    assert_eq!(
        options().deserialize::<Flattened>(&bytes).unwrap(),
        expected
    );
    #[cfg(feature = "cbor")]
    {
        let config = options().with_cbor_format();
        let bytes = config.serialize(&value).unwrap();
        assert_eq!(config.deserialize::<Flattened>(&bytes).unwrap(), expected);
    }
}

#[test]
fn null_options_follow_the_selected_wire_profile() {
    let bytes = options().serialize(&Some(())).unwrap();
    assert_eq!(bytes, options().serialize(&None::<()>).unwrap());
    assert_eq!(options().deserialize::<Option<()>>(&bytes).unwrap(), None);
    #[cfg(feature = "cbor")]
    {
        let config = options().with_cbor_format();
        let bytes = config.serialize(&Some(())).unwrap();
        assert_eq!(bytes, config.serialize(&None::<()>).unwrap());
        assert_eq!(config.deserialize::<Option<()>>(&bytes).unwrap(), None);
    }
    #[cfg(feature = "compact")]
    {
        let config = options().with_compact_format();
        let bytes = config.serialize(&Some(())).unwrap();
        assert_ne!(bytes, config.serialize(&None::<()>).unwrap());
        assert_eq!(config.deserialize::<Option<()>>(&bytes).unwrap(), Some(()));
    }
}

#[cfg(all(feature = "std", feature = "cbor"))]
#[test]
fn cbor_streaming_preserves_io_failures() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = options()
        .with_cbor_format()
        .serialize_into(Broken, &42u64)
        .unwrap_err();
    assert!(matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::BrokenPipe));
}
