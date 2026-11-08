#![cfg(any(feature = "cbor", feature = "compression"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static RECORD: Cell<bool> = const { Cell::new(false) };
    static STATS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

struct ObservedAllocator;

fn record(size: usize) {
    let _ = RECORD.try_with(|enabled| {
        if enabled.get() {
            let _ = STATS.try_with(|stats| {
                let (count, largest) = stats.get();
                stats.set((count + 1, largest.max(size)));
            });
        }
    });
}

// SAFETY: every operation is forwarded to System with unchanged arguments.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            RECORD.with(|enabled| enabled.set(false));
        }
    }
    STATS.with(|stats| stats.set((0, 0)));
    RECORD.with(|enabled| enabled.set(true));
    let guard = Reset;
    let value = operation();
    drop(guard);
    let (count, largest) = STATS.with(Cell::get);
    (value, count, largest)
}

#[cfg(feature = "cbor")]
#[test]
fn cbor_counting_and_caller_buffers_do_not_allocate() {
    let config = rustbinary::options().with_cbor_format();
    let value = (42u64, "borrowed", [1i32, -2, 3]);
    let mut output = [0u8; 128];
    let (size, count, _) = measured(|| config.serialized_size(&value));
    assert_eq!(count, 0);
    let (written, count, _) = measured(|| config.serialize_into_slice(&mut output, &value));
    assert_eq!(count, 0);
    assert_eq!(size.unwrap(), written.unwrap() as u64);
    #[cfg(feature = "std")]
    {
        let (result, count, _) = measured(|| config.serialize_into(std::io::sink(), &value));
        result.unwrap();
        assert_eq!(count, 0);
    }
}

#[cfg(feature = "compression")]
fn header(flags: u16, raw: u64, stored: u64) -> Vec<u8> {
    let mut bytes = b"RBZ1".to_vec();
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&raw.to_le_bytes());
    bytes.extend_from_slice(&stored.to_le_bytes());
    bytes
}

#[cfg(feature = "compression")]
#[test]
fn truncated_compression_headers_do_not_reserve_declared_storage() {
    const DECLARED: u64 = 16 << 20;
    let codec = rustbinary::options().with_compression(3);
    let raw = header(0, DECLARED, DECLARED);
    let (result, _, largest) = measured(|| codec.deserialize_from::<_, String>(&raw[..]));
    assert!(result.is_err());
    assert!(
        largest < 4096,
        "header-only input allocated {largest} bytes"
    );

    let mut packed = header(1, DECLARED, 6);
    packed.extend_from_slice(&(DECLARED as u32).to_le_bytes());
    packed.extend_from_slice(&[0x82, 0]); // one literal, then truncated data
    let (result, _, largest) = measured(|| codec.deserialize::<String>(&packed));
    assert!(result.is_err());
    assert!(
        largest < 4096,
        "truncated token stream allocated {largest} bytes"
    );
}

#[cfg(feature = "compression")]
#[test]
fn compression_match_history_has_fixed_storage() {
    let input = "a".repeat(2 << 20);
    let codec = rustbinary::options().with_compression(3);
    let (packed, _, largest) = measured(|| codec.serialize(&input));
    let packed = packed.unwrap();
    // The raw payload is about 2 MiB. The old history table alone was 8 MiB.
    assert!(
        largest < 4 << 20,
        "compression allocated a {largest}-byte buffer"
    );
    assert_eq!(codec.deserialize::<String>(&packed).unwrap(), input);
}
