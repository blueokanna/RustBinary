#![cfg(feature = "compact")]

use rustbinary::compact::{CompactCursor, CompactDecode};
use rustbinary::{options, Error};
use std::cell::Cell;

#[test]
fn bulk_float_decoding_handles_every_input_alignment() {
    for offset in 0..8 {
        let mut storage = [0u8; 40];
        storage[offset] = 3;
        let bits = [0u64, 0x8000_0000_0000_0000, 0x7ff8_1234_5678_9abc];
        for (index, value) in bits.iter().enumerate() {
            storage[offset + 1 + index * 8..offset + 9 + index * 8]
                .copy_from_slice(&value.to_le_bytes());
        }
        let values: Vec<f64> = options()
            .with_compact_format()
            .deserialize(&storage[offset..offset + 25])
            .unwrap();
        assert_eq!(
            values
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            bits
        );

        let bits = [0u32, 0x8000_0000, 0x7fc1_2345];
        for (index, value) in bits.iter().enumerate() {
            storage[offset + 1 + index * 4..offset + 5 + index * 4]
                .copy_from_slice(&value.to_le_bytes());
        }
        let values: Vec<f32> = options()
            .with_compact_format()
            .deserialize(&storage[offset..offset + 13])
            .unwrap();
        assert_eq!(
            values
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            bits
        );
    }
}

#[test]
fn bulk_signed_bytes_preserve_all_bits() {
    let decoded: Vec<i8> = options()
        .with_compact_format()
        .deserialize(&[4, 0, 127, 128, 255])
        .unwrap();
    assert_eq!(decoded, [0, 127, -128, -1]);
}

thread_local! { static DROPS: Cell<usize> = const { Cell::new(0) }; }

#[derive(Debug)]
struct Tracked;

impl Drop for Tracked {
    fn drop(&mut self) {
        DROPS.with(|count| count.set(count.get() + 1));
    }
}

impl<'de> CompactDecode<'de> for Tracked {
    fn decode_compact(cursor: &mut CompactCursor<'de>) -> Result<Self, Error> {
        match u8::decode_compact(cursor)? {
            0 => Ok(Self),
            1 => Err(Error::Custom("test error".into())),
            _ => panic!("test panic"),
        }
    }
}

#[test]
fn partially_decoded_arrays_drop_initialized_elements() {
    for failed in 0..3 {
        for marker in [1, 2] {
            DROPS.with(|count| count.set(0));
            let mut input = [0; 3];
            input[failed] = marker;
            let result = std::panic::catch_unwind(|| {
                options()
                    .with_compact_format()
                    .deserialize::<[Tracked; 3]>(&input)
            });
            if marker == 1 {
                assert!(result.unwrap().is_err());
            } else {
                assert!(result.is_err());
            }
            assert_eq!(DROPS.with(Cell::get), failed);
        }
    }
    DROPS.with(|count| count.set(0));
    let value = options()
        .with_compact_format()
        .deserialize::<[Tracked; 3]>(&[0; 3])
        .unwrap();
    assert_eq!(DROPS.with(Cell::get), 0);
    drop(value);
    assert_eq!(DROPS.with(Cell::get), 3);
}
