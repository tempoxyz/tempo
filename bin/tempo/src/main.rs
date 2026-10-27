//! Binary entrypoint for the Tempo node.

#[global_allocator]
static ALLOC: commonware_allocator::mimalloc::MiMalloc =
    commonware_allocator::mimalloc::MiMalloc::new(commonware_allocator::mimalloc::Config {
        purge: if cfg!(feature = "mimalloc-purge") {
            commonware_allocator::mimalloc::Purge::After(std::time::Duration::from_secs(10))
        } else {
            commonware_allocator::mimalloc::Purge::Default
        },
        reserve: if cfg!(feature = "mimalloc-reserve") {
            Some(commonware_allocator::mimalloc::Reserve {
                bytes: 2 << 30,
                pinned: true,
                prefault: cfg!(feature = "mimalloc-prefault"),
            })
        } else {
            None
        },
        ..commonware_allocator::mimalloc::Config::DEFAULT
    });

/// Compile-time jemalloc configuration for heap profiling.
///
/// tikv-jemallocator uses prefixed symbols, so the runtime `MALLOC_CONF` env var is ignored.
/// This exported symbol is read by jemalloc at init time to enable profiling unconditionally
/// when the `jemalloc-prof` feature is active.
///
/// See <https://github.com/jemalloc/jemalloc/wiki/Getting-Started>
#[cfg(all(feature = "jemalloc-prof", unix))]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

fn main() -> eyre::Result<()> {
    let _allocation = Box::new(0u8);
    eprintln!(
        "allocator benchmark: config={:?} status={:?} effective={:?} object_limit={}",
        ALLOC.config(),
        commonware_allocator::mimalloc::Status::read(),
        commonware_allocator::mimalloc::Effective::read(),
        commonware_allocator::mimalloc::LARGE_OBJECT_LIMIT,
    );

    tempo::tempo_main()
}
