//! Opt-in targeted read-ahead for the large-bytecode benchmark.

use reth_libmdbx::{ffi, TableObject, TransactionKind};
use std::{borrow::Cow, io, sync::LazyLock};

/// Decodes a raw MDBX value while the transaction can still identify dirty pages.
pub(super) struct PrefetchValue<'a>(pub(super) Cow<'a, [u8]>);

impl<'a> TableObject for PrefetchValue<'a> {
    fn decode(_: &[u8]) -> reth_libmdbx::Result<Self> {
        unreachable!("prefetch requires the MDBX transaction context")
    }

    unsafe fn decode_val<K: TransactionKind>(
        txn: *const ffi::MDBX_txn,
        value: ffi::MDBX_val,
    ) -> reth_libmdbx::Result<Self> {
        if *ENABLED && value.iov_len > *PAGE_SIZE {
            // SAFETY: MDBX invokes this decoder with a value owned by this live transaction.
            // Clean RW values are mapped too; dirty values may instead be heap-backed.
            let mapped = K::IS_READ_ONLY ||
                unsafe { ffi::mdbx_is_dirty(txn, value.iov_base) } == ffi::MDBX_SUCCESS;
            if mapped {
                // SAFETY: A clean MDBX value and its endpoint pages lie in the live file mapping.
                let bytes = unsafe {
                    std::slice::from_raw_parts(value.iov_base.cast::<u8>(), value.iov_len)
                };
                // SAFETY: The mapping remains valid for the entire decoder call.
                unsafe { prefetch(bytes, !K::IS_READ_ONLY) };
            } else {
                metrics::counter!("db.bytecode_prefetch.skipped_dirty").increment(1);
            }
        }
        // SAFETY: Preserve libmdbx's existing borrowing/dirty-value-copy behavior.
        unsafe { <Cow<'a, [u8]> as TableObject>::decode_val::<K>(txn, value).map(Self) }
    }
}

static ENABLED: LazyLock<bool> = LazyLock::new(|| {
    let enabled = std::env::var("RETH_BYTECODE_PREFETCH").is_ok_and(|value| value == "1");
    metrics::gauge!("db.bytecode_prefetch.enabled").set(f64::from(u8::from(enabled)));
    tracing::info!(target: "storage::db::mdbx", enabled, "Targeted bytecode prefetch");
    enabled
});

static PAGE_SIZE: LazyLock<usize> = LazyLock::new(page_size::get);

/// Hints only the pages containing this value, without changing general read-ahead.
///
/// # Safety
/// `value` must be in a live file mapping. The mapping must include the
/// complete OS pages containing the value, not an owned heap copy of the bytes.
unsafe fn prefetch(value: &[u8], writable_transaction: bool) {
    // SAFETY: The caller guarantees the mapping remains valid for the hint.
    match unsafe { advise(value, *PAGE_SIZE) } {
        Ok(bytes) => {
            metrics::counter!("db.bytecode_prefetch.requests").increment(1);
            metrics::counter!("db.bytecode_prefetch.requests_rw")
                .increment(u64::from(writable_transaction));
            metrics::counter!("db.bytecode_prefetch.bytes").increment(bytes as u64);
            metrics::counter!("db.bytecode_prefetch.errors").increment(0);
        }
        Err(_) => {
            // Advice is optional; failed hints must never make a state read fail.
            metrics::counter!("db.bytecode_prefetch.errors").increment(1);
        }
    }
}

fn page_range(address: usize, len: usize, page_size: usize) -> Option<(usize, usize)> {
    if len == 0 || !page_size.is_power_of_two() {
        return None;
    }
    let start = address & !(page_size - 1);
    let end = address.checked_add(len)?.checked_add(page_size - 1)? & !(page_size - 1);
    Some((start, end.checked_sub(start)?))
}

/// The caller must meet the mapping requirements documented on `prefetch`.
unsafe fn advise(value: &[u8], page_size: usize) -> io::Result<usize> {
    let (start, len) = page_range(value.as_ptr() as usize, value.len(), page_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid mapped value range"))?;
    // SAFETY: The rounded range is contained in the caller's live MDBX mapping.
    // WILLNEED populates file cache; it does not invalidate or mutate the mapping.
    let result = unsafe { libc::madvise(start as *mut libc::c_void, len, libc::MADV_WILLNEED) };
    if result == 0 {
        Ok(len)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytecode_prefetch_page_range() {
        assert_eq!(page_range(0x1014, 27_693, 4096), Some((0x1000, 7 * 4096)));
        assert_eq!(page_range(0x1000, 4096, 4096), Some((0x1000, 4096)));
        assert_eq!(page_range(0x1fff, 2, 4096), Some((0x1000, 8192)));
        assert_eq!(page_range(0x1000, 0, 4096), None);
        assert_eq!(page_range(usize::MAX - 10, 20, 4096), None);
        assert_eq!(page_range(0x1000, 4096, 0), None);
        assert_eq!(page_range(0x1000, 4096, 3), None);
    }

    #[test]
    fn bytecode_prefetch_mapped_value() {
        use std::{io::Write, os::fd::AsRawFd};

        let page_size = page_size::get();
        let expected = vec![0x5b; 7 * page_size];
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&expected).unwrap();
        // SAFETY: The file has exactly the requested size and outlives the mapping.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                expected.len(),
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        // SAFETY: mmap returned a valid readable mapping of expected.len() bytes.
        let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), expected.len()) };
        // SAFETY: This slice, including its rounded endpoint pages, lies in the mapping.
        let advised = unsafe { advise(&bytes[20..bytes.len() - 19], page_size) };
        assert_eq!(advised.unwrap(), expected.len());
        assert_eq!(bytes, expected);
        // SAFETY: No references to the mapping are used after this unmap.
        assert_eq!(unsafe { libc::munmap(ptr, expected.len()) }, 0);
    }
}
