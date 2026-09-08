use tempo_node::TempoNode;

/// Function used to modify the [`TempoNode`] before launch.
pub type TempoNodeMapper = dyn FnOnce(TempoNode) -> TempoNode + Send + 'static;

#[cfg(feature = "exex-overrides")]
pub(crate) mod exex {
    use std::{future::Future, pin::Pin};

    use reth_exex::ExExContext;
    use tempo_node::TempoNodeAdapter;

    /// Boxed running ExEx future.
    pub(crate) type TempoBoxedExEx = Pin<Box<dyn Future<Output = eyre::Result<()>> + Send>>;

    /// Boxed ExEx initialization future.
    pub(crate) type TempoBoxedExExLauncher =
        Pin<Box<dyn Future<Output = eyre::Result<TempoBoxedExEx>> + Send>>;

    /// Function used to create a Tempo ExEx from its Reth context.
    pub(crate) type TempoExExInstaller =
        dyn FnOnce(ExExContext<TempoNodeAdapter>) -> TempoBoxedExExLauncher + Send + 'static;
}

/// Optional programmatic overrides for [`tempo_main_with`](crate::tempo_main_with).
///
/// These hooks are applied during startup after CLI arguments have been parsed.
/// Empty overrides are a no-op, so embedding binaries can start from
/// [`TempoOverrides::default`] or [`TempoOverrides::new`] and opt into only the
/// hooks they need.
///
/// The initial one-shot hook surface maps the [`TempoNode`] produced from CLI arguments
/// before it is passed to Reth's node launcher. This is useful for settings that
/// are intentionally not exposed as CLI flags, such as additional transaction
/// pool validation.
///
/// # Example
///
/// This rejects externally sourced transactions whose encoded size exceeds a
/// local policy limit while preserving the rest of the CLI-derived node
/// configuration.
///
/// ```no_run
/// use tempo::{
///     InvalidPoolTransactionError, PoolTransaction, TempoOverrides, tempo_main_with,
/// };
///
/// fn main() -> eyre::Result<()> {
///     const MAX_EXTERNAL_TX_ENCODED_LEN: usize = 128 * 1024;
///
///     let overrides = TempoOverrides::new().map_tempo_node(|node| {
///         node.map_pool_builder(|pool| {
///             pool.with_additional_stateless_validation(|origin, tx| {
///                 let size = tx.encoded_length();
///                 if origin.is_external() && size > MAX_EXTERNAL_TX_ENCODED_LEN {
///                     return Err(InvalidPoolTransactionError::OversizedData {
///                         size,
///                         limit: MAX_EXTERNAL_TX_ENCODED_LEN,
///                     });
///                 }
///
///                 Ok(())
///             })
///         })
///     });
///
///     tempo_main_with(overrides)
/// }
/// ```
#[derive(Default)]
pub struct TempoOverrides {
    pub(crate) tempo_node_mapper: Option<Box<TempoNodeMapper>>,
    #[cfg(feature = "exex-overrides")]
    pub(crate) exex_installer: Option<(String, Box<exex::TempoExExInstaller>)>,
}

impl TempoOverrides {
    /// Creates empty overrides.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a mapper for the [`TempoNode`] built from CLI arguments.
    ///
    /// Multiple mappers are applied in the order they were added.
    pub fn map_tempo_node<F>(mut self, mapper: F) -> Self
    where
        F: FnOnce(TempoNode) -> TempoNode + Send + 'static,
    {
        self.tempo_node_mapper = Some(match self.tempo_node_mapper.take() {
            Some(previous) => Box::new(move |node| mapper(previous(node))),
            None => Box::new(mapper),
        });
        self
    }

    pub(crate) fn apply_tempo_node(&mut self, node: TempoNode) -> TempoNode {
        match self.tempo_node_mapper.take() {
            Some(mapper) => mapper(node),
            None => node,
        }
    }
}

#[cfg(feature = "exex-overrides")]
impl TempoOverrides {
    /// Installs an ExEx in the Tempo node launch path.
    pub fn install_exex<F, R, E>(mut self, id: impl Into<String>, exex: F) -> Self
    where
        F: FnOnce(reth_exex::ExExContext<tempo_node::TempoNodeAdapter>) -> R + Send + 'static,
        R: std::future::Future<Output = eyre::Result<E>> + Send + 'static,
        E: std::future::Future<Output = eyre::Result<()>> + Send + 'static,
    {
        self.exex_installer = Some((
            id.into(),
            Box::new(move |ctx| {
                Box::pin(async move {
                    let exex = exex(ctx).await?;
                    Ok(Box::pin(exex) as exex::TempoBoxedExEx)
                })
            }),
        ));
        self
    }

    pub(crate) fn take_exex_installer(
        &mut self,
    ) -> Option<(String, Box<exex::TempoExExInstaller>)> {
        self.exex_installer.take()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use super::TempoOverrides;
    use tempo_node::TempoNode;

    #[test]
    fn maps_tempo_node() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let mut overrides = TempoOverrides::new().map_tempo_node(move |node| {
            called_clone.store(true, Ordering::Relaxed);
            node
        });

        let _ = overrides.apply_tempo_node(TempoNode::default());

        assert!(called.load(Ordering::Relaxed));
    }

    #[test]
    fn applies_tempo_node_mappers_in_order() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let first = calls.clone();
        let second = calls.clone();

        let mut overrides = TempoOverrides::new()
            .map_tempo_node(move |node| {
                first.lock().unwrap().push(1);
                node
            })
            .map_tempo_node(move |node| {
                second.lock().unwrap().push(2);
                node
            });

        let _ = overrides.apply_tempo_node(TempoNode::default());

        assert_eq!(*calls.lock().unwrap(), vec![1, 2]);
    }
}
