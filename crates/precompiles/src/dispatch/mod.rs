mod macros;

use crate::{IntoPrecompileResult, Result, error, storage::StorageCtx};
use alloy::{
    primitives::{Address, Bytes},
    sol,
    sol_types::{SolCall, SolError},
};
use revm::precompile::{PrecompileHalt, PrecompileOutput, PrecompileResult};
use tempo_chainspec::hardfork::TempoHardfork;

sol! { error StaticCallNotAllowed(); }

/// Dispatches a parameterless view call, encoding the return via `T`.
#[inline]
pub(crate) fn metadata<T: SolCall>(f: impl FnOnce() -> Result<T::Return>) -> PrecompileResult {
    f().into_precompile_result(0, 0, |ret| T::abi_encode_returns(&ret).into())
}

/// Dispatches a read-only call with decoded arguments, encoding the return via `T`.
#[inline]
pub(crate) fn view<T: SolCall>(
    call: T,
    f: impl FnOnce(T) -> Result<T::Return>,
) -> PrecompileResult {
    f(call).into_precompile_result(0, 0, |ret| T::abi_encode_returns(&ret).into())
}

/// Dispatches a state-mutating call that returns ABI-encoded data.
///
/// Rejects static calls with [`StaticCallNotAllowed`].
#[inline]
pub(crate) fn mutate<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<T::Return>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::revert(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
            StorageCtx.reservoir(),
        ));
    }
    f(sender, call).into_precompile_result(0, 0, |ret| T::abi_encode_returns(&ret).into())
}

/// Dispatches a state-mutating call that returns no data (e.g. `approve`, `transfer`).
///
/// Rejects static calls with [`StaticCallNotAllowed`].
#[inline]
pub(crate) fn mutate_void<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<()>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::revert(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
            StorageCtx.reservoir(),
        ));
    }
    f(sender, call).into_precompile_result(0, 0, |()| Bytes::new())
}

/// A selector schedule at a given hardfork boundary.
///
/// Before the hardfork activates, selectors in `added` are treated as unknown.
/// After it activates, selectors in `dropped` are treated as unknown.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SelectorSchedule<'a> {
    hardfork: TempoHardfork,
    added: &'a [[u8; 4]],
    dropped: &'a [[u8; 4]],
}

impl<'a> SelectorSchedule<'a> {
    /// Creates a new schedule anchored at `hardfork` with no selectors registered yet.
    pub(crate) const fn new(hardfork: TempoHardfork) -> Self {
        Self {
            hardfork,
            added: &[],
            dropped: &[],
        }
    }

    /// Registers selectors that are introduced at this hardfork boundary.
    ///
    /// These selectors are treated as unknown BEFORE `hardfork` activates.
    pub(crate) const fn with_added(mut self, selectors: &'a [[u8; 4]]) -> Self {
        self.added = selectors;
        self
    }

    /// Registers selectors that are removed at this hardfork boundary.
    ///
    /// These selectors are treated as unknown ONCE `hardfork` activates.
    pub(crate) const fn with_dropped(mut self, selectors: &'a [[u8; 4]]) -> Self {
        self.dropped = selectors;
        self
    }

    /// Returns `true` if this schedule gates out `selector` under the `active` hardfork.
    #[inline]
    fn rejects(self, selector: [u8; 4], active: TempoHardfork) -> bool {
        if self.hardfork <= active {
            self.dropped
        } else {
            self.added
        }
        .contains(&selector)
    }
}

/// Applies hardfork selector schedules, decodes calldata via `decode`, then dispatches to `f`.
///
/// Handles missing selectors (revert on T1+, error on earlier forks), hardfork-gated selectors,
/// unknown selectors (ABI-encoded `UnknownFunctionSelector`), and malformed ABI data (empty
/// revert).
#[inline]
pub(crate) fn dispatch_call<T>(
    calldata: &[u8],
    hardforks: &[SelectorSchedule<'_>],
    decode: impl FnOnce(&[u8]) -> core::result::Result<T, alloy::sol_types::Error>,
    f: impl FnOnce(T) -> PrecompileResult,
) -> PrecompileResult {
    let storage = StorageCtx::default();

    if calldata.len() < 4 {
        if storage.spec().is_t1() {
            return Ok(storage.revert_output(Bytes::new()));
        } else {
            return Ok(storage.halt_output(PrecompileHalt::Other(
                "Invalid input: missing function selector".into(),
            )));
        }
    }

    let selector: [u8; 4] = calldata[..4].try_into().expect("calldata len >= 4");
    if hardforks
        .iter()
        .any(|schedule| schedule.rejects(selector, storage.spec()))
    {
        return storage.error_result(error::TempoPrecompileError::UnknownFunctionSelector(
            selector,
        ));
    }

    let result = decode(calldata);

    match result {
        Ok(call) => f(call).map(|mut res| {
            // TODO: fix this, each precompile handler should either return output with proper gas values or don't return any gas values at all.
            res.gas_used = storage.gas_used();
            crate::fill_state_gas(&mut res, &storage);
            res
        }),
        Err(alloy::sol_types::Error::UnknownSelector { selector, .. }) => storage.error_result(
            error::TempoPrecompileError::UnknownFunctionSelector(*selector),
        ),
        Err(_) => Ok(storage.revert_output(Bytes::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::{
        primitives::U256,
        sol_types::{SolCall, SolInterface},
    };
    use tempo_contracts::precompiles::UnknownFunctionSelector;

    #[test]
    fn test_dispatch_call_applies_hardfork_selector_gates() -> eyre::Result<()> {
        alloy::sol! {
            interface ISelectorGatedTest {
                function stable() external;
                function t2Added(uint256 value) external;
                function t3Removed() external;
            }
        }

        const SELECTOR_SCHEDULE: &[SelectorSchedule<'static>] = &[
            SelectorSchedule::new(TempoHardfork::T2)
                .with_added(&[ISelectorGatedTest::t2AddedCall::SELECTOR]),
            SelectorSchedule::new(TempoHardfork::T3)
                .with_dropped(&[ISelectorGatedTest::t3RemovedCall::SELECTOR]),
        ];

        let call_with_spec = |spec: TempoHardfork, calldata: &[u8]| {
            let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
            StorageCtx::enter(&mut storage, || {
                dispatch_call(
                    calldata,
                    SELECTOR_SCHEDULE,
                    ISelectorGatedTest::ISelectorGatedTestCalls::abi_decode,
                    |call| match call {
                        ISelectorGatedTest::ISelectorGatedTestCalls::stable(_) => {
                            Ok(PrecompileOutput::new(0, Bytes::from_static(b"stable"), 0))
                        }
                        ISelectorGatedTest::ISelectorGatedTestCalls::t2Added(_) => {
                            Ok(PrecompileOutput::new(0, Bytes::from_static(b"added"), 0))
                        }
                        ISelectorGatedTest::ISelectorGatedTestCalls::t3Removed(_) => {
                            Ok(PrecompileOutput::new(0, Bytes::from_static(b"removed"), 0))
                        }
                    },
                )
            })
        };

        let t2_added_calldata = ISelectorGatedTest::t2AddedCall { value: U256::ZERO }.abi_encode();
        let t3_removed_calldata = ISelectorGatedTest::t3RemovedCall {}.abi_encode();

        // pre-T2: selectors introduced at T2 must still look unknown.
        let pre_t2_added = call_with_spec(TempoHardfork::T1, &t2_added_calldata)?;
        assert!(pre_t2_added.is_revert());
        let decoded = UnknownFunctionSelector::abi_decode(&pre_t2_added.bytes)?;
        assert_eq!(
            decoded.selector.as_slice(),
            &ISelectorGatedTest::t2AddedCall::SELECTOR
        );

        // T2+: that selector becomes available and dispatches normally.
        let post_t2_added = call_with_spec(TempoHardfork::T2, &t2_added_calldata)?;
        assert!(!post_t2_added.is_revert());
        assert_eq!(post_t2_added.bytes.as_ref(), b"added");

        // pre-T3: selectors removed at T3 still dispatch normally.
        let pre_t3_removed = call_with_spec(TempoHardfork::T2, &t3_removed_calldata)?;
        assert!(!pre_t3_removed.is_revert());
        assert_eq!(pre_t3_removed.bytes.as_ref(), b"removed");

        // T3+: the removed selector must now revert as unknown.
        let post_t3_removed = call_with_spec(TempoHardfork::T3, &t3_removed_calldata)?;
        assert!(post_t3_removed.is_revert());
        let decoded = UnknownFunctionSelector::abi_decode(&post_t3_removed.bytes)?;
        assert_eq!(
            decoded.selector.as_slice(),
            &ISelectorGatedTest::t3RemovedCall::SELECTOR
        );

        // preT2: gated selectors must return `UnknownFunctionSelector` even for selector-only calldata.
        let malformed_added = call_with_spec(
            TempoHardfork::T1,
            &ISelectorGatedTest::t2AddedCall::SELECTOR,
        )?;
        assert!(malformed_added.is_revert());
        let decoded = UnknownFunctionSelector::abi_decode(&malformed_added.bytes)?;
        assert_eq!(
            decoded.selector.as_slice(),
            &ISelectorGatedTest::t2AddedCall::SELECTOR
        );

        Ok(())
    }
}
