use rustbinary::{
    core::{Error, ErrorCategory},
    protocol::{Fingerprint as _, Reflect as _, StaticSize as _, TypeShape},
};
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    PartialEq,
    Serialize,
    Deserialize,
    rustbinary::protocol::Fingerprint,
    rustbinary::protocol::Reflect,
    rustbinary::protocol::StaticSize,
)]
struct Header {
    online: bool,
    partition: u16,
    coordinates: [i32; 2],
}

#[derive(Serialize, Deserialize, rustbinary::protocol::Fingerprint)]
struct ReorderedHeader {
    partition: u16,
    online: bool,
    coordinates: [i32; 2],
}

#[derive(Debug, PartialEq, rustbinary::protocol::BitPacked)]
struct PackedFlags {
    online: bool,
    #[bits = 3]
    priority: u8,
    #[bits = 12]
    sequence: u16,
}

fn main() -> rustbinary::Result<()> {
    let value = Header {
        online: true,
        partition: 17,
        coordinates: [-4, 9],
    };
    let base = rustbinary::options().with_limit(4096);

    assert!(base.serialize(&value)?.len() <= Header::MAX_SIZE);
    assert_ne!(
        Header::fingerprint(base),
        ReorderedHeader::fingerprint(base)
    );
    if let TypeShape::Struct(fields) = Header::SHAPE {
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[1].name, "partition");
        assert_eq!(fields[1].type_name, "u16");
    }

    let framed = base.with_fingerprint().serialize(&value)?;
    assert_eq!(
        base.with_fingerprint().deserialize::<Header>(&framed)?,
        value
    );
    assert!(matches!(
        base.with_fingerprint()
            .deserialize::<ReorderedHeader>(&framed),
        Err(Error::SchemaMismatch { .. })
    ));

    let flags = PackedFlags {
        online: true,
        priority: 5,
        sequence: 2047,
    };
    let packed = base.with_bit_packing().serialize(&flags)?;
    assert_eq!(packed.len(), 2);
    assert_eq!(
        base.with_bit_packing()
            .deserialize::<PackedFlags>(&packed)?,
        flags
    );

    let invalid = PackedFlags {
        online: true,
        priority: 8,
        sequence: 1,
    };
    let width_error = base.with_bit_packing().serialize(&invalid).unwrap_err();
    assert!(matches!(
        &width_error,
        Error::BitPacking("unsigned field value is out of range")
    ));
    assert_eq!(width_error.category(), ErrorCategory::Protocol);

    println!(
        "metadata: {} fields, max {} bytes, packed {} bytes, fingerprint {:#018x}",
        match Header::SHAPE {
            TypeShape::Struct(fields) => fields.len(),
            TypeShape::Enum(_) => 0,
        },
        Header::MAX_SIZE,
        packed.len(),
        Header::fingerprint(base)
    );

    Ok(())
}
