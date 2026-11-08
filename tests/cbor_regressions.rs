#![cfg(feature = "cbor")]

use rustbinary::options;

#[derive(Debug, nextjson::NsonDeserialize)]
struct Empty {}

#[test]
fn invalid_indefinite_integer_and_tag_heads_return_errors() {
    for byte in [0x1f, 0x3f, 0xdf] {
        assert!(options()
            .with_cbor_format()
            .deserialize::<nextjson::Value>(&[byte])
            .is_err());
    }
}

#[test]
fn negative_bignums_do_not_wrap_or_panic() {
    let mut bytes = vec![0xc3, 0x50];
    bytes.extend_from_slice(&(i128::MAX as u128).to_be_bytes());
    assert_eq!(
        options()
            .with_cbor_format()
            .deserialize::<i128>(&bytes)
            .unwrap(),
        i128::MIN
    );
    for magnitude in [1u128 << 127, u128::MAX] {
        bytes[2..].copy_from_slice(&magnitude.to_be_bytes());
        assert!(options()
            .with_cbor_format()
            .deserialize::<i128>(&bytes)
            .is_err());
    }
}

#[test]
fn every_indefinite_text_chunk_must_be_valid_utf8() {
    let bytes = [0x7f, 0x61, 0xc2, 0x61, 0xa2, 0xff];
    assert!(options()
        .with_cbor_format()
        .deserialize::<String>(&bytes)
        .is_err());
    let valid = [0x7f, 0x62, 0xc2, 0xa2, 0x61, b'x', 0xff];
    assert_eq!(
        options()
            .with_cbor_format()
            .deserialize::<String>(&valid)
            .unwrap(),
        "\u{a2}x"
    );
}

#[derive(Debug, PartialEq)]
struct Bytes(Vec<u8>);

impl<'de> nextjson::NsonDeserialize<'de> for Bytes {
    fn nextdecode_into<D: nextjson::FormatDecoder<'de>>(
        decoder: &mut D,
        out: &mut nextjson::de::DecodeSlot<Self>,
    ) -> Result<(), D::Error> {
        out.write(Self(decoder.bytes()?.into_owned()));
        Ok(())
    }
}

#[test]
fn definite_arrays_count_options_and_native_byte_strings_once() {
    let bytes = [0x83, 0xf6, 0x42, 1, 2, 0x5f, 0x41, 3, 0xff];
    let value = options()
        .with_cbor_format()
        .deserialize::<Vec<Option<Bytes>>>(&bytes)
        .unwrap();
    assert_eq!(
        value,
        vec![None, Some(Bytes(vec![1, 2])), Some(Bytes(vec![3]))]
    );
}

#[test]
fn skipped_cbor_fields_obey_grammar_and_limits() {
    let nested = [0xbf, 0x61, b'x', 0x9f, 1, 2, 0xff, 0xff];
    assert!(options()
        .with_cbor_format()
        .deserialize::<Empty>(&nested)
        .is_ok());
    assert!(options()
        .with_depth_limit(1)
        .with_cbor_format()
        .deserialize::<Empty>(&nested)
        .is_err());
    assert!(options()
        .with_collection_limit(1)
        .with_cbor_format()
        .deserialize::<Empty>(&nested)
        .is_err());
    let invalid_key = [0xbf, 0x61, b'x', 0xbf, 1, 2, 0xff, 0xff];
    assert!(options()
        .with_cbor_format()
        .deserialize::<Empty>(&invalid_key)
        .is_err());
    let missing_value = [0xbf, 0x61, b'x', 0xbf, 0x61, b'y', 0xff, 0xff];
    assert!(options()
        .with_cbor_format()
        .deserialize::<Empty>(&missing_value)
        .is_err());
}

#[test]
fn untagged_variants_restore_pending_container_heads() {
    #[derive(Debug, PartialEq, nextjson::NsonDeserialize)]
    #[njson(untagged)]
    enum Choice {
        Text(String),
        Pair((u8, u8)),
    }
    let bytes = [0x82, 0x82, 1, 2, 0x82, 3, 4];
    let values = options()
        .with_cbor_format()
        .deserialize::<Vec<Choice>>(&bytes)
        .unwrap();
    assert_eq!(values, vec![Choice::Pair((1, 2)), Choice::Pair((3, 4))]);
}
