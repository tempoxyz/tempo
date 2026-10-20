//! Backend construction for EVM2 JIT compilation.

pub use reth_node_core::args::JitArgs;

/// Starts a JIT backend whose folded gas constants match `spec`.
pub(crate) fn backend(
    args: &JitArgs,
    spec: tempo_chainspec::hardfork::TempoHardfork,
) -> eyre::Result<tempo_evm::jit::JitBackend> {
    let defaults = tempo_evm::jit::RuntimeTuning::default();
    let metrics = std::sync::Arc::new(tempo_evm::jit::Evm2Metrics::default());
    let backend = tempo_evm::jit::JitBackend::new(tempo_evm::jit::RuntimeConfig {
        enabled: args.enabled || args.blocking,
        blocking: args.blocking,
        debug_assertions: args.debug,
        single_error: false,
        gas_params: Some(
            tempo_evm::tempo_execution_config(spec, 0)
                .version()
                .gas_params,
        ),
        host: tempo_evm::jit::host_config(),
        tuning: tempo_evm::jit::RuntimeTuning {
            jit_hot_threshold: args.hot_threshold,
            jit_worker_count: args.worker_count.unwrap_or(defaults.jit_worker_count),
            channel_capacity: args.channel_capacity,
            jit_max_pending_jobs: args.max_pending_jobs,
            jit_max_bytecode_len: args.max_bytecode_len,
            resident_code_cache_bytes: args.code_cache_bytes,
            idle_evict_duration: Some(args.idle_evict_duration),
            ..defaults
        },
        on_compilation: Some(std::sync::Arc::new(move |event| {
            metrics.record_compilation(&event);
            reth_tracing::tracing::info!(target: "tempo::jit", code_hash = %event.code_hash,
                success = event.success, duration = ?event.duration, "JIT compilation completed");
        })),
        ..Default::default()
    })?;
    reth_tracing::tracing::info!(target: "tempo::jit", ?spec, hot_threshold = args.hot_threshold,
        blocking = args.blocking, "Started Tempo JIT backend");
    Ok(backend)
}
