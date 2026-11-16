//! Binary entrypoint for the Tempo node.

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

/// Compile-time jemalloc configuration.
///
/// tikv-jemallocator uses prefixed symbols, so the runtime `MALLOC_CONF` env var is ignored.
/// This exported symbol is read by jemalloc at init time.
///
/// Background threads purge unused pages by decay. Without them, a thread that exits as the last
/// one of its arena purges the whole arena, and parallel execution's per-block worker threads
/// then fault the pages back in on the next block.
///
/// See <https://github.com/jemalloc/jemalloc/wiki/Getting-Started>
#[cfg(all(feature = "jemalloc", not(feature = "jemalloc-prof"), unix))]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF: &[u8] = b"background_thread:true\0";

/// Compile-time jemalloc configuration that also enables heap profiling unconditionally.
#[cfg(all(feature = "jemalloc-prof", unix))]
#[unsafe(export_name = "_rjem_malloc_conf")]
static MALLOC_CONF: &[u8] = b"background_thread:true,prof:true,prof_active:true,lg_prof_sample:19\0";

fn main() -> eyre::Result<()> {
    tempo::tempo_main()
}
