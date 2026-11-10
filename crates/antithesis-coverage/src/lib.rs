//! Antithesis coverage runtime shim for binaries built with its sancov flags.
//!
//! A drop-in for [antithesis-instrumentation](https://crates.io/crates/antithesis-instrumentation):
//! it forwards the sancov callbacks to the platform's `/usr/lib/libvoidstar.so` (a no-op outside
//! Antithesis), which records coverage and lets Antithesis pause threads. A process started with
//! [`DISABLE_ENV`] set to a non-empty value never loads libvoidstar, so Antithesis treats it as
//! uninstrumented. Test template commands set it: they run the same binaries as the system under
//! test (or a client tool built in the same instrumented build), and their coverage would only steer
//! the fuzzer toward the workload. The Antithesis SDK's assertions and randomness don't depend on
//! this shim and keep working.
//!
//! Refer to the crate once in a binary (`use tempo_antithesis_coverage as _;`) to link it.

/// The environment variable that keeps a process from loading libvoidstar.
pub const DISABLE_ENV: &str = "TEMPO_ANTITHESIS_COVERAGE_DISABLED";

#[cfg(target_os = "linux")]
#[link(name = "tempo_antithesis_coverage", kind = "static")]
unsafe extern "C" {
    fn antithesis_load_libvoidstar();
}

// Load libvoidstar at startup, as antithesis-instrumentation does. The sancov module constructor
// also loads it on its first call, whichever runs first.
#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static LOAD_LIBVOIDSTAR: unsafe extern "C" fn() = antithesis_load_libvoidstar;
