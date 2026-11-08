#![cfg(feature = "archive")]

use rustbinary::archive::{access, build, Archive, ArchiveLimits, ArchiveSchema, Serialize};
use rustbinary::archive_codec::{to_archive, CheckBytes};

#[derive(Archive, Serialize)]
struct Scalars {
    a: u64,
    b: u64,
}

#[derive(Archive, Serialize)]
struct Padded {
    wide: u64,
    small: u8,
}

#[derive(Archive, Serialize)]
struct Parent {
    child: Padded,
    tail: u8,
}

#[derive(Archive, Serialize)]
struct Child {
    name: String,
}

#[derive(Archive, Serialize)]
struct Family {
    children: Vec<Child>,
    title: String,
}

impl ArchiveSchema for Family {
    const SCHEMA_ID: u64 = 101;
}

#[derive(Archive, Serialize)]
struct Numbers {
    values: Vec<u64>,
}

impl ArchiveSchema for Numbers {
    const SCHEMA_ID: u64 = 102;
}

#[test]
fn scalar_skeleton_must_fit_including_trailing_padding() {
    let bytes = to_archive(&Scalars { a: 1, b: 2 }).unwrap();
    assert!(ArchivedScalars::check_at(&bytes, 0).is_ok());
    for len in 0..core::mem::size_of::<ArchivedScalars>() {
        assert!(ArchivedScalars::check_at(&bytes[..len], 0).is_err());
    }
    assert!(ArchivedScalars::check_at(&[0; 16], usize::MAX).is_err());
    let bytes = to_archive(&Padded { wide: 1, small: 2 }).unwrap();
    assert!(ArchivedPadded::check_at(&bytes, 0).is_ok());
    for len in 0..core::mem::size_of::<ArchivedPadded>() {
        assert!(ArchivedPadded::check_at(&bytes[..len], 0).is_err());
    }
}

#[test]
fn nested_struct_serialization_includes_tail_padding() {
    let value = Parent {
        child: Padded { wide: 42, small: 7 },
        tail: 9,
    };
    let bytes = to_archive(&value).unwrap();
    assert_eq!(bytes.len(), core::mem::size_of::<ArchivedParent>());
    assert_eq!(bytes[16], 9);
}

#[test]
fn nested_vector_positions_do_not_consume_parent_siblings() {
    let value = Family {
        children: vec![
            Child {
                name: "first".into(),
            },
            Child {
                name: "second".into(),
            },
        ],
        title: "family".into(),
    };
    let archive = build(&value, ArchiveLimits::new()).unwrap();
    assert_eq!(archive.root().title.as_str(), "family");
    assert_eq!(archive.root().children[0].name.as_str(), "first");
    assert_eq!(archive.root().children[1].name.as_str(), "second");
}

#[test]
fn payload_alignment_accounts_for_vector_elements() {
    let archive = build(&Numbers { values: vec![1, 2] }, ArchiveLimits::new()).unwrap();
    let mut shifted = vec![0; archive.as_bytes().len() + 8];
    let offset = (0..8)
        .find(|&i| (shifted.as_ptr() as usize + i) % 8 == 4)
        .unwrap();
    let len = archive.as_bytes().len();
    shifted[offset..offset + len].copy_from_slice(archive.as_bytes());
    assert!(access::<Numbers>(&shifted[offset..offset + len], ArchiveLimits::new()).is_err());
}

#[test]
fn validation_helpers_reject_overflow_and_invalid_alignment() {
    assert!(rustbinary::archive_codec::check_string_field(&[], usize::MAX).is_err());
    assert!(rustbinary::archive_codec::check_vec_field(&[0; 8], 0, 8, 0).is_err());
    for align in [3, usize::MAX] {
        assert!(rustbinary::archive_codec::check_vec_field(&[0; 8], 0, 8, align).is_err());
    }
    assert!(rustbinary::archive_codec::check_vec_field(&[0; 8], usize::MAX, 8, 8).is_err());
}

#[derive(Archive, Serialize)]
struct Group {
    prefix: u8,
    families: Vec<Family>,
    padded: Vec<Padded>,
    suffix: String,
}

impl ArchiveSchema for Group {
    const SCHEMA_ID: u64 = 103;
}

#[test]
fn nested_vectors_preserve_stride_and_all_sibling_positions() {
    let value = Group {
        prefix: 3,
        families: vec![
            Family {
                children: vec![
                    Child {
                        name: "first".into(),
                    },
                    Child {
                        name: "second".into(),
                    },
                ],
                title: "one".into(),
            },
            Family {
                children: vec![],
                title: "two".into(),
            },
        ],
        padded: vec![Padded { wide: 42, small: 7 }, Padded { wide: 43, small: 8 }],
        suffix: "last".into(),
    };
    let archive = build(&value, ArchiveLimits::new()).unwrap();
    let root = access::<Group>(archive.as_bytes(), ArchiveLimits::new()).unwrap();
    assert_eq!(root.prefix, 3);
    assert_eq!(root.families[0].children[1].name.as_str(), "second");
    assert_eq!(root.families[0].title.as_str(), "one");
    assert_eq!(root.families[1].title.as_str(), "two");
    assert!(root.families[1].children.is_empty());
    assert_eq!((root.padded[1].wide, root.padded[1].small), (43, 8));
    assert_eq!(root.suffix.as_str(), "last");
}

#[test]
fn pointer_patches_reject_unrepresentable_and_invalid_positions() {
    use rustbinary::archive_codec::ArchiveSerializer;
    let mut serializer = ArchiveSerializer::new();
    let first = serializer.reserve_ptr();
    let second = serializer.reserve_ptr();
    assert!(serializer.patch_ptr(first, i32::MAX as usize + 1).is_err());
    assert!(serializer.patch_ptr(second, first).is_err());
    assert!(serializer.patch_ptr(usize::MAX, usize::MAX).is_err());
    assert!(serializer.patch_ptr(first, serializer.len() + 1).is_err());
    assert_eq!(serializer.finish(), [0; 8]);
}

#[cfg(target_pointer_width = "64")]
#[test]
fn vector_count_overflow_is_rejected_without_allocating() {
    use rustbinary::archive_codec::{ArchiveSerializer, Pod};
    struct ZeroSize;
    impl Pod for ZeroSize {
        fn to_le_bytes(&self) -> Vec<u8> {
            Vec::new()
        }
    }
    // SAFETY: ZeroSize is an inhabited ZST, so every element occupies zero
    // bytes; the non-null, aligned reference stays alive for the whole call.
    let values = unsafe { core::slice::from_raw_parts(&ZeroSize, u32::MAX as usize + 1) };
    let mut serializer = ArchiveSerializer::new();
    let field = serializer.reserve_ptr();
    assert!(serializer.write_vec_at(field, values).is_err());
    assert_eq!(serializer.len(), 4);
}

#[derive(Archive, Serialize)]
struct Recursive {
    children: Vec<Recursive>,
}

#[test]
fn recursive_validation_is_bounded_and_resets_after_errors() {
    let mut value = Recursive { children: vec![] };
    for _ in 0..80 {
        value = Recursive {
            children: vec![value],
        };
    }
    let bytes = to_archive(&value).unwrap();
    assert!(ArchivedRecursive::check_at(&bytes, 0)
        .unwrap_err()
        .contains("depth limit"));
    let shallow = to_archive(&Recursive { children: vec![] }).unwrap();
    assert!(ArchivedRecursive::check_at(&shallow, 0).is_ok());
}

#[derive(Archive, Serialize)]
struct Empty {}

#[test]
fn zero_sized_vector_validation_has_a_visit_limit() {
    use rustbinary::archive_codec::check_vec_nested;
    let _empty = Empty {};
    let bytes = [4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
    assert!(check_vec_nested::<ArchivedEmpty>(&bytes, 0, 0, 1)
        .unwrap_err()
        .contains("visit limit"));
    assert!(ArchivedEmpty::check_at(&[], 0).is_ok());
}
