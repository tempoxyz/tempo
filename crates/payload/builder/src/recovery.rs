//! Containment of unwinding transaction panics during local payload construction.

use alloy_primitives::B256;
use reth_payload_builder::PayloadBuilderError;
use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
};

/// A local execution failure, not a consensus-invalid transaction.
#[derive(Debug)]
pub(crate) struct TransactionPanic {
    hash: B256,
    message: String,
}

impl std::error::Error for TransactionPanic {}

impl fmt::Display for TransactionPanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transaction {} panicked: {}", self.hash, self.message)
    }
}

impl From<TransactionPanic> for PayloadBuilderError {
    fn from(panic: TransactionPanic) -> Self {
        Self::other(panic)
    }
}

pub(crate) fn catch_transaction_panic<T>(
    hash: B256,
    execute: impl FnOnce() -> T,
) -> Result<T, TransactionPanic> {
    // Containment does not restore executor invariants. The caller must discard its EVM and
    // transaction state on error, including any partially committed state and recorded actions.
    catch_unwind(AssertUnwindSafe(execute)).map_err(|panic| {
        let message = match panic.downcast::<String>() {
            Ok(message) => *message,
            Err(panic) => match panic.downcast::<&str>() {
                Ok(message) => (*message).to_owned(),
                Err(panic) => {
                    // An opaque panic payload can itself panic when dropped. Leak only these
                    // exceptional payloads to avoid a second panic during recovery.
                    std::mem::forget(panic);
                    "non-string panic payload".to_owned()
                }
            },
        };
        TransactionPanic { hash, message }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::panic_any;

    #[test]
    fn panic_converts_to_build_error() {
        let hash = B256::repeat_byte(1);
        let panic = catch_transaction_panic(hash, || panic!("injected panic")).unwrap_err();
        let error: PayloadBuilderError = panic.into();
        assert_eq!(
            error.to_string(),
            format!("transaction {hash} panicked: injected panic")
        );
        let PayloadBuilderError::Other(error) = error else {
            panic!("expected a boxed transaction panic");
        };
        let panic = error.downcast_ref::<TransactionPanic>().unwrap();
        assert_eq!(panic.hash, hash);
        assert_eq!(panic.message, "injected panic");
    }

    #[test]
    fn execution_errors_are_preserved() {
        assert_eq!(
            catch_transaction_panic(B256::ZERO, || Err::<(), _>("invalid nonce")).unwrap(),
            Err("invalid nonce")
        );
    }

    #[test]
    fn string_panic_payload_is_preserved() {
        let result = catch_transaction_panic(B256::ZERO, || panic_any(String::from("owned panic")));
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("transaction {} panicked: owned panic", B256::ZERO)
        );
    }

    #[test]
    fn opaque_panic_payload_is_not_dropped() {
        struct PanickingDrop;
        impl Drop for PanickingDrop {
            fn drop(&mut self) {
                panic!("panic payload destructor")
            }
        }
        let result = catch_transaction_panic(B256::ZERO, || panic_any(PanickingDrop));
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "transaction {} panicked: non-string panic payload",
                B256::ZERO
            )
        );
    }
}
