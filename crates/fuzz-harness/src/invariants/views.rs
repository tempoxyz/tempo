//! View calls against the harness's state after a step or, with its changes undone, before it.

use std::fmt::{self, Display};

use alloy_primitives::{Address, B256, Bytes, U256};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, SystemTx},
};
use invariants_core::{Outcome, Views};
use reth_evm::{ConfigureEvm as _, Database};
use tempo_evm::{TempoEvm, TempoEvmConfig, TempoEvmEnv};

use crate::state::{Net, PreStateDb, Reader};

/// Read-only calls against the state an EVM reads, noting reads the seeded pre-state misses.
pub(super) struct EvmViews<'a> {
    evm: TempoEvm<'a>,
    pre_state: &'a PreStateDb,
}

impl<'a> EvmViews<'a> {
    pub(super) fn new(
        db: impl Database + 'a,
        evm_config: &TempoEvmConfig,
        env: TempoEvmEnv,
        pre_state: &'a PreStateDb,
    ) -> Self {
        Self {
            evm: evm_config.evm_with_env(db, env),
            pre_state,
        }
    }

    /// How `input` sent to `target` by `caller` ends. `Ok(None)` when nothing answers: the call
    /// read a key the pre-state lacks. `Err` when the call halts or cannot run.
    fn call_one(
        &mut self,
        caller: Address,
        target: Address,
        input: &Bytes,
    ) -> Result<Option<Outcome>, ViewFailed> {
        self.pre_state.restore_missed(false);
        let result = self
            .evm
            .system_call(SystemTx::new(target, input.clone()).with_caller(caller));
        if self.pre_state.missed() {
            return Ok(None);
        }
        let failed = |reason| ViewFailed::new(target, input, reason);
        let executed = result.map_err(|err| failed(err.to_string()))?;
        let result = executed.result();
        let output = result.output.clone();
        if result.is_success() {
            Ok(Some(Outcome::Return(output)))
        } else if result.is_revert() {
            Ok(Some(Outcome::Revert(output)))
        } else {
            Err(failed(format!("{result:?}")))
        }
    }
}

impl Views for EvmViews<'_> {
    type Error = ViewFailed;

    /// Each call's output, made by the zero address. `None` when nothing answers: `target` has no
    /// code, or the call read a key the pre-state lacks. `Err` when a call reverts or halts.
    fn call(&mut self, calls: &[(Address, Bytes)]) -> Result<Vec<Option<Bytes>>, ViewFailed> {
        calls
            .iter()
            .map(
                |(target, input)| match self.call_one(Address::ZERO, *target, input)? {
                    None => Ok(None),
                    Some(Outcome::Return(output)) => Ok(Some(output).filter(|o| !o.is_empty())),
                    Some(Outcome::Revert(output)) => Err(ViewFailed::new(
                        *target,
                        input,
                        format!("reverted with {output}"),
                    )),
                },
            )
            .collect()
    }

    fn call_from(
        &mut self,
        from: Address,
        calls: &[(Address, Bytes)],
    ) -> Result<Vec<Option<Outcome>>, ViewFailed> {
        calls
            .iter()
            .map(|(target, input)| self.call_one(from, *target, input))
            .collect()
    }

    /// The seeded pre-state may hold only the accounts and slots execution touched.
    fn partial(&self) -> bool {
        true
    }
}

/// The state before a step: what `reader` reads, with the step's `net` changes undone.
pub(super) struct PreView<'a> {
    pub(super) reader: Reader<'a>,
    pub(super) net: &'a Net,
}

impl Database for PreView<'_> {
    type Error = <Reader<'static> as Database>::Error;

    fn is_fatal(_error: &Self::Error) -> bool {
        false
    }

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.net.get(address) {
            Some(account) => Ok(account.original().cloned()),
            None => self.reader.get_account(address),
        }
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        self.reader.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &U256) -> Result<U256, Self::Error> {
        match self
            .net
            .get(address)
            .and_then(|account| account.original_slot(key))
        {
            Some(value) => Ok(value),
            None => self.reader.get_storage(address, key),
        }
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<B256, Self::Error> {
        self.reader.get_block_hash(number)
    }
}

/// A view call that reverted, halted or could not run.
#[derive(Debug)]
pub(super) struct ViewFailed {
    selector: Bytes,
    target: Address,
    reason: String,
}

impl ViewFailed {
    /// `input` sent to `target` failed for `reason`.
    fn new(target: Address, input: &Bytes, reason: String) -> Self {
        Self {
            selector: input
                .get(..4)
                .map(Bytes::copy_from_slice)
                .unwrap_or_default(),
            target,
            reason,
        }
    }

    /// The contract the call was made to.
    pub(super) fn target(&self) -> Address {
        self.target
    }
}

impl Display for ViewFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}: {}", self.selector, self.target, self.reason)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, address};
    use alloy_sol_types::SolCall;
    use invariants_core::view_from;
    use tempo_contracts::precompiles::{ITIP20, PATH_USD_ADDRESS};
    use tempo_fuzz_types::{BlockContextInput, BlockHeaderInput, ChainSpecInput, PreState};

    use super::*;
    use crate::{chain, state};

    #[test]
    fn call_from_answers_as_the_caller_whether_it_returns_or_reverts() {
        // Dev account 0 holds pathUSD in the dev genesis; the zero address holds none.
        let holder = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let to = Address::with_last_byte(0xaa);
        let spec = std::sync::Arc::new(chain::chain_spec(&ChainSpecInput::default()).unwrap());
        let header = chain::header(
            &spec,
            &BlockHeaderInput::Context(BlockContextInput::default()),
        )
        .unwrap();
        let evm_config = TempoEvmConfig::new(spec);
        let env = evm_config.evm_env(&header).unwrap();
        let db = state::seed(&PreState::Genesis(Default::default())).unwrap();
        let mut views = EvmViews::new(db.view(), &evm_config, env, &db.pre);
        let transfer = |amount| ITIP20::transferCall {
            to,
            amount: U256::from(amount),
        };

        let sent = view_from(&mut views, holder, PATH_USD_ADDRESS, transfer(1)).unwrap();
        assert_eq!(sent, Some(Ok(true)));
        let refused = view_from(&mut views, Address::ZERO, PATH_USD_ADDRESS, transfer(1)).unwrap();
        assert!(
            matches!(refused, Some(Err(ref data)) if !data.is_empty()),
            "{refused:?}"
        );

        let input: Bytes = transfer(1).abi_encode().into();
        let outcomes = views
            .call_from(
                holder,
                &[(PATH_USD_ADDRESS, input.clone()), (PATH_USD_ADDRESS, input)],
            )
            .unwrap();
        // Views change nothing: the second transfer answers like the first.
        assert_eq!(outcomes[0], outcomes[1]);
        assert!(matches!(outcomes[0], Some(Outcome::Return(_))));
        // A plain view call made by the zero address reports the revert as a failure.
        let input: Bytes = transfer(1).abi_encode().into();
        assert!(views.call(&[(PATH_USD_ADDRESS, input)]).is_err());
    }
}
