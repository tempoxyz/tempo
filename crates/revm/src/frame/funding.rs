//! Funding sequencing, independent of callback execution and frame bookkeeping.
use super::native::{NativeAction, NativeCall};
use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolCall;
use revm::{handler::FrameResult, interpreter::InstructionResult};
use tempo_contracts::precompiles::{IFundingSource, ITIP20Funder};

#[derive(Debug)]
pub(crate) struct FundingContinuation {
    pub(super) source: Address,
    pub(super) account: Address,
    pub(super) asset_out: Address,
    pub(super) amount_out: U256,
    pub(super) stage: Stage,
}

#[derive(Debug)]
pub(super) enum Stage {
    #[cfg_attr(not(test), expect(dead_code))]
    Prepare(Bytes),
    Fund(IFundingSource::Plan),
    Finished(InstructionResult, Bytes),
}

impl FundingContinuation {
    pub(super) fn action(&self) -> NativeAction {
        match &self.stage {
            Stage::Prepare(data) => NativeAction::Call(NativeCall {
                target: self.source,
                data: data.clone(),
                is_static: true,
            }),
            Stage::Fund(plan) => NativeAction::Call(NativeCall {
                target: self.source,
                data: IFundingSource::fundCall {
                    account: self.account,
                    assetOut: self.asset_out,
                    amountOut: self.amount_out,
                    data: plan.data.clone(),
                }
                .abi_encode()
                .into(),
                is_static: false,
            }),
            Stage::Finished(status, output) => NativeAction::Return(*status, output.clone()),
        }
    }

    pub(crate) fn resume(&mut self, result: &FrameResult) {
        let success = result.instruction_result().is_ok();
        let output = result.interpreter_result().output.clone();
        if !success {
            // A failed source call reverts funding; the native frame settles child gas before resuming.
            self.stage = Stage::Finished(InstructionResult::Revert, output);
            return;
        }
        self.stage = match self.stage {
            Stage::Prepare(_) => {
                match IFundingSource::prepareCall::abi_decode_returns_validate(&output) {
                    Ok(plan) => Stage::Fund(plan),
                    Err(_) => {
                        use alloy_sol_types::SolError;
                        Stage::Finished(
                            InstructionResult::Revert,
                            ITIP20Funder::InvalidFundingPlan {
                                source: self.source,
                            }
                            .abi_encode()
                            .into(),
                        )
                    }
                }
            }
            Stage::Fund(_) => Stage::Finished(InstructionResult::Return, output),
            Stage::Finished(_, _) => unreachable!("completed funding frame cannot resume"),
        };
    }
}
