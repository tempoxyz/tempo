//! Binary entrypoint for the Tempo node.

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

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
    tempo::tempo_main()
}
