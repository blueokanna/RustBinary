use rustbinary::archive::{build, Archive, ArchiveLimits, ArchiveSchema, MappedArchive, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

struct TemporaryArchive {
    directory: PathBuf,
    file: PathBuf,
}

impl TemporaryArchive {
    fn create() -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();

        for _ in 0..1024 {
            let id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "rustbinary-mmap-{}-{timestamp}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let file = directory.join("catalog.rba");
                    return Ok(Self { directory, file });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not reserve a unique archive directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.file
    }
}

impl Drop for TemporaryArchive {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.file);
        let _ = fs::remove_dir(&self.directory);
    }
}

#[derive(Archive, Serialize)]
#[archive(check_bytes)]
struct Reading {
    sensor_id: u32,
    label: String,
    samples: Vec<i32>,
}

#[derive(Archive, Serialize)]
#[archive(check_bytes)]
struct Catalog {
    generation: u64,
    site: String,
    readings: Vec<Reading>,
}

impl ArchiveSchema for Catalog {
    // Application-owned schema identity. Change it for an incompatible layout.
    const SCHEMA_ID: u64 = 0x4341_5441_4c4f_4701;
}

fn range_is_mapped<T>(mapping: &[u8], pointer: *const T, count: usize) -> bool {
    let Some(byte_len) = core::mem::size_of::<T>().checked_mul(count) else {
        return false;
    };
    let mapping_start = mapping.as_ptr() as usize;
    let Some(mapping_end) = mapping_start.checked_add(mapping.len()) else {
        return false;
    };
    let value_start = pointer.cast::<u8>() as usize;
    let Some(value_end) = value_start.checked_add(byte_len) else {
        return false;
    };

    value_start >= mapping_start && value_end <= mapping_end
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let limits = ArchiveLimits::new().with_max_file_size(64 * 1024 * 1024);
    let catalog = Catalog {
        generation: 17,
        site: "plant-east".to_owned(),
        readings: vec![
            Reading {
                sensor_id: 1001,
                label: "compressor/intake".to_owned(),
                samples: vec![21_250, 21_375, 21_500],
            },
            Reading {
                sensor_id: 1002,
                label: "compressor/output".to_owned(),
                samples: vec![87_000, 87_125, 87_250],
            },
        ],
    };

    let archive = build(&catalog, limits)?;
    let temporary = TemporaryArchive::create()?;
    archive.write_new(temporary.path())?;
    drop(archive);

    // SAFETY: This process owns the unique directory and publishes the file
    // once with `write_new`. It opens no writer and removes the file only after
    // the mapping is dropped. No other process receives this private path.
    let mapped = unsafe { MappedArchive::<Catalog>::open(temporary.path(), limits) }?;
    let root = mapped.root();

    assert_eq!(mapped.header().schema_id(), Catalog::SCHEMA_ID);
    assert_eq!(mapped.header().file_len(), mapped.as_bytes().len() as u64);
    assert_eq!(root.generation, 17);
    assert_eq!(root.site.as_str(), "plant-east");
    assert_eq!(root.readings.len(), 2);
    assert_eq!(root.readings[0].sensor_id, 1001);
    assert_eq!(
        root.readings[0].samples.as_slice(),
        [21_250, 21_375, 21_500]
    );

    let mapping = mapped.as_bytes();
    assert!(range_is_mapped(
        mapping,
        root.site.as_bytes().as_ptr(),
        root.site.len()
    ));
    assert!(range_is_mapped(
        mapping,
        root.readings.as_ptr(),
        root.readings.len()
    ));
    for reading in root.readings.iter() {
        assert!(range_is_mapped(
            mapping,
            reading.label.as_bytes().as_ptr(),
            reading.label.len()
        ));
        assert!(range_is_mapped(
            mapping,
            reading.samples.as_ptr(),
            reading.samples.len()
        ));
    }

    println!(
        "validated {} mapped bytes, schema {:#018x}, {} records",
        mapped.as_bytes().len(),
        mapped.header().schema_id(),
        root.readings.len()
    );

    drop(mapped);
    Ok(())
}
