#![cfg(feature = "compact")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::VecDeque;

thread_local! {
    static RECORD: Cell<bool> = const { Cell::new(false) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

struct ObservedAllocator;

fn record(size: usize) {
    let _ = RECORD.try_with(|enabled| {
        if enabled.get() {
            let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(size)));
        }
    });
}

// SAFETY: allocation and deallocation are delegated unchanged to System.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
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

fn rejects_without_bulk_reservation<T: for<'de> rustbinary::CompactDecode<'de>>() {
    let config = rustbinary::options().with_compact_format();
    LARGEST.with(|largest| largest.set(0));
    RECORD.with(|enabled| enabled.set(true));
    let result = config.deserialize::<T>(&[252, 0, 0, 1, 0]);
    RECORD.with(|enabled| enabled.set(false));
    let largest = LARGEST.with(Cell::get);
    assert!(result.is_err());
    assert!(
        largest < 4096,
        "truncated length header caused {largest}-byte allocation"
    );
}

#[test]
fn truncated_collection_headers_do_not_reserve_declared_storage() {
    rejects_without_bulk_reservation::<Vec<String>>();
    rejects_without_bulk_reservation::<Vec<u64>>();
    rejects_without_bulk_reservation::<VecDeque<String>>();
    #[cfg(feature = "std")]
    rejects_without_bulk_reservation::<std::collections::HashMap<String, u8>>();
}
