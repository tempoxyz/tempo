//! Binary entrypoint for the Tempo node.

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

/// Compile-time jemalloc options, read by jemalloc at init time. The runtime env var still
/// overrides them.
///
/// reth-cli-util builds jemalloc with `override_allocator_on_supported_platforms`, so on Linux
/// (glibc) jemalloc replaces the system `malloc` with unprefixed symbols and reads `malloc_conf` and
/// `MALLOC_CONF`. On macOS and musl its symbols keep the `_rjem_` prefix, so it reads
/// `_rjem_malloc_conf` and `_RJEM_MALLOC_CONF` instead.
///
/// On Linux, `background_thread:true` purges unused dirty pages on jemalloc's own threads instead
/// of inline on whichever thread allocates or frees next, which keeps that work off hot paths
/// such as payload building and transaction validation. The `jemalloc-prof` feature also enables
/// heap profiling unconditionally.
///
/// See <https://github.com/jemalloc/jemalloc/wiki/Getting-Started>
#[cfg(all(
    unix,
    any(
        feature = "jemalloc-prof",
        all(feature = "jemalloc", target_os = "linux")
    )
))]
#[cfg_attr(
    all(target_os = "linux", not(target_env = "musl")),
    unsafe(export_name = "malloc_conf")
)]
#[cfg_attr(
    not(all(target_os = "linux", not(target_env = "musl"))),
    unsafe(export_name = "_rjem_malloc_conf")
)]
static MALLOC_CONF: &[u8] =
    std::cfg_select! {
        all(feature = "jemalloc-prof", target_os = "linux") => {
            b"background_thread:true,prof:true,prof_active:true,lg_prof_sample:19\0"
        }
        feature = "jemalloc-prof" => b"prof:true,prof_active:true,lg_prof_sample:19\0",
        _ => b"background_thread:true\0",
    };

fn main() -> eyre::Result<()> {
    tempo::tempo_main()
}
