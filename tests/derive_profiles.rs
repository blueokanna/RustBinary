#![no_std]

#[cfg(test)]
extern crate std;

#[cfg(all(
    feature = "derive",
    feature = "fingerprint",
    feature = "reflection",
    feature = "static-size",
    feature = "bit-packing"
))]
#[derive(
    rustbinary::Fingerprint, rustbinary::Reflect, rustbinary::StaticSize, rustbinary::BitPacked,
)]
struct NoStdHeader {
    #[bits = 1]
    active: bool,
    #[bits = 3]
    mode: u8,
    #[bits = 12]
    sequence: u16,
}

#[cfg(all(
    test,
    feature = "derive",
    feature = "fingerprint",
    feature = "reflection",
    feature = "static-size",
    feature = "bit-packing"
))]
#[test]
fn derives_expand_against_the_no_std_runtime() {
    use rustbinary::{Fingerprint as _, Reflect as _, StaticSize as _};

    let value = NoStdHeader {
        active: true,
        mode: 5,
        sequence: 0xabc,
    };
    let codec = rustbinary::options().with_bit_packing();
    let mut output = [0u8; NoStdHeader::PACKED_MAX_SIZE];
    let written = codec.serialize_into_slice(&mut output, &value).unwrap();
    let decoded: NoStdHeader = codec.deserialize(&output[..written]).unwrap();

    core::assert!(decoded.active);
    core::assert_eq!(decoded.mode, 5);
    core::assert_eq!(decoded.sequence, 0xabc);
    core::assert_ne!(NoStdHeader::TYPE_FINGERPRINT, 0);
    core::assert!(matches!(
        NoStdHeader::SHAPE,
        rustbinary::TypeShape::Struct(_)
    ));
}
