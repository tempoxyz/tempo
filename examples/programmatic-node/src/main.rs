//! Template binary for launching Tempo with programmatic overrides.

use tempo::{
    InvalidPoolTransactionError, PoolTransaction, PoolTransactionError, TempoOverrides,
    tempo_main_with,
};

#[global_allocator]
static ALLOC: tempo::cli_util::allocator::Allocator = tempo::cli_util::allocator::new_allocator();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const MAX_EXTERNAL_TX_ENCODED_LEN: usize = 128 * 1024;

    let overrides = TempoOverrides::new().map_tempo_node(|node| {
        // Modify the node's transaction pool validation before the CLI launches Tempo.
        node.map_pool_builder(|pool| {
            // Reject externally sourced transactions whose encoded size exceeds a local limit.
            pool.with_additional_stateless_validation(|origin, tx| {
                let size = tx.encoded_length();
                if origin.is_external() && size > MAX_EXTERNAL_TX_ENCODED_LEN {
                    return Err(InvalidPoolTransactionError::OversizedData {
                        size,
                        limit: MAX_EXTERNAL_TX_ENCODED_LEN,
                    });
                }

                Ok(())
            })
            // Reject transactions whose sender state resolves to a zero-balance account.
            .with_additional_stateful_validation(|_origin, tx, state| {
                let account = match state.basic_account(tx.sender_ref()) {
                    Ok(account) => account.unwrap_or_default(),
                    Err(_err) => {
                        return Err(InvalidPoolTransactionError::other(
                            ProgrammaticPoolError::SenderStateUnavailable,
                        ));
                    }
                };

                if account.balance.is_zero() {
                    return Err(InvalidPoolTransactionError::other(
                        ProgrammaticPoolError::ZeroBalanceSender,
                    ));
                }

                Ok(())
            })
        })
    });

    tempo_main_with(overrides)?;
    Ok(())
}

/// Custom pool rejection reasons returned by this programmatic validation layer.
#[derive(Debug)]
enum ProgrammaticPoolError {
    SenderStateUnavailable,
    ZeroBalanceSender,
}

impl std::fmt::Display for ProgrammaticPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SenderStateUnavailable => f.write_str("failed to read sender account state"),
            Self::ZeroBalanceSender => f.write_str("sender account has zero balance"),
        }
    }
}

impl std::error::Error for ProgrammaticPoolError {}

impl PoolTransactionError for ProgrammaticPoolError {
    fn is_bad_transaction(&self) -> bool {
        // These are local policy rejections, not malformed peer data that should be penalized.
        false
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
