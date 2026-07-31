use crate::{Error, Result};

pub(crate) const HEADER_LEN: usize = 16;
const VERSION: u16 = 1;

pub(crate) fn encode_header(magic: [u8; 4], fingerprint: u64) -> [u8; HEADER_LEN] {
    let mut bytes = [0; HEADER_LEN];
    bytes[..4].copy_from_slice(&magic);
    bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
    bytes[8..16].copy_from_slice(&fingerprint.to_le_bytes());
    bytes
}

pub(crate) fn validate_header(magic: [u8; 4], input: &[u8], expected: u64) -> Result<&[u8]> {
    let bytes = input
        .get(..HEADER_LEN)
        .ok_or(Error::InvalidFrame("truncated fingerprint header"))?;
    if bytes[..4] != magic {
        return Err(Error::InvalidFrame("bad fingerprint magic"));
    }
    if u16::from_le_bytes(bytes[4..6].try_into().expect("fixed header field")) != VERSION {
        return Err(Error::InvalidFrame("unsupported fingerprint frame version"));
    }
    if bytes[6..8] != [0, 0] {
        return Err(Error::InvalidFrame(
            "reserved fingerprint flags are not zero",
        ));
    }
    let actual = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed header field"));
    if actual != expected {
        return Err(Error::SchemaMismatch { expected, actual });
    }
    Ok(&input[HEADER_LEN..])
}
