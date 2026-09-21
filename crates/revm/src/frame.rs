//! Bytecode and native funding continuations on the same execution stack.

use alloy_evm::{Database, precompiles::PrecompilesMap};
use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolCall;
use revm::{
    context::{Cfg, ContextError, ContextTr},
    context_interface::local::OutFrame,
    handler::{EthFrame, FrameInitOrResult, FrameResult, FrameTr, ItemOrResult},
    inspector::InspectorFrame,
    interpreter::{
        CallInput, CallInputs, CallScheme, CallValue, InstructionContext, InstructionResult,
        InterpreterAction, InterpreterResult, instructions::contract::load_acc_and_calc_gas,
        interpreter::EthInterpreter, interpreter_action::FrameInit,
    },
};
use tempo_contracts::precompiles::{IFundingSource, ITIP20Funder};

use crate::evm::TempoContext;

/// An EVM frame with an optional native continuation sharing its gas and checkpoint.
#[derive(Debug)]
pub struct TempoFrame {
    pub(crate) eth: EthFrame<EthInterpreter>,
    pub(crate) funding: Option<FundingContinuation>,
}

impl Default for TempoFrame {
    fn default() -> Self {
        Self {
            eth: EthFrame::invalid(),
            funding: None,
        }
    }
}

impl FrameTr for TempoFrame {
    type FrameInit = FrameInit;
    type FrameResult = FrameResult;
}

impl InspectorFrame for TempoFrame {
    type IT = EthInterpreter;

    fn eth_frame(&mut self) -> Option<&mut EthFrame<EthInterpreter>> {
        if self.funding.is_some() {
            None
        } else {
            Some(&mut self.eth)
        }
    }
}

impl TempoFrame {
    pub(crate) fn init<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
        precompiles: &mut PrecompilesMap,
        frame_input: FrameInit,
    ) -> Result<ItemOrResult<(), FrameResult>, ContextError<DB::Error>> {
        // No protocol address enters a funding frame until its authorization and metering are implemented.
        #[cfg(test)]
        let frame_input = tests::admit(self, ctx, frame_input);
        EthFrame::init_with_context(
            OutFrame::new_init(&mut self.eth),
            ctx,
            precompiles,
            frame_input,
        )
        .map(|result| result.map_item(|_| ()))
    }

    pub(crate) fn run_funding<DB: Database>(
        &mut self,
        ctx: &mut TempoContext<DB>,
    ) -> Result<FrameInitOrResult<Self>, ContextError<DB::Error>> {
        let funding = self.funding.as_mut().expect("native funding frame");
        let action = match &funding.stage {
            Stage::Prepare(data) => Some((data.clone(), true)),
            Stage::Fund(plan) => Some((
                IFundingSource::fundCall {
                    account: funding.account,
                    assetOut: funding.asset_out,
                    amountOut: funding.amount_out,
                    data: plan.data.clone(),
                }
                .abi_encode()
                .into(),
                false,
            )),
            Stage::Finished(_, _) => None,
        };
        if let Some((data, is_static)) = action {
            // Charge memory before allocating a child, using the same expansion schedule as CALL.
            let gas_params = ctx.cfg().gas_params();
            let charge = self
                .eth
                .interpreter
                .resize_memory(gas_params, 0, data.len());
            let call = charge.and_then(|()| {
                load_acc_and_calc_gas(
                    &mut InstructionContext {
                        interpreter: &mut self.eth.interpreter,
                        host: ctx,
                    },
                    funding.source,
                    false,
                    !is_static,
                    u64::MAX,
                )
            });
            match call {
                Ok((gas_limit, bytecode, hash, charged_new_account_state_gas)) => {
                    let inputs = CallInputs {
                        input: CallInput::Bytes(data),
                        return_memory_offset: 0..0,
                        gas_limit,
                        reservoir: self.eth.interpreter.gas.reservoir(),
                        bytecode_address: funding.source,
                        known_bytecode: (hash, bytecode),
                        target_address: funding.source,
                        caller: funding.funder,
                        value: CallValue::Transfer(U256::ZERO),
                        scheme: if is_static {
                            CallScheme::StaticCall
                        } else {
                            CallScheme::Call
                        },
                        is_static,
                        charged_new_account_state_gas,
                    };
                    return self.eth.process_next_action(
                        ctx,
                        InterpreterAction::NewFrame(revm::interpreter::FrameInput::Call(Box::new(
                            inputs,
                        ))),
                    );
                }
                Err(error) => funding.stage = Stage::Finished(error, Bytes::new()),
            }
        }
        let Stage::Finished(result, output) = &funding.stage else {
            unreachable!()
        };
        let result = self.eth.process_next_action(
            ctx,
            InterpreterAction::Return(InterpreterResult {
                result: *result,
                output: output.clone(),
                gas: self.eth.interpreter.gas,
            }),
        );
        self.eth.set_finished(true);
        result
    }
}

#[derive(Debug)]
pub(crate) struct FundingContinuation {
    funder: Address,
    source: Address,
    account: Address,
    asset_out: Address,
    amount_out: U256,
    stage: Stage,
}

#[derive(Debug)]
enum Stage {
    #[cfg_attr(not(test), expect(dead_code))]
    Prepare(Bytes),
    Fund(IFundingSource::Plan),
    Finished(InstructionResult, Bytes),
}

impl FundingContinuation {
    pub(crate) fn resume(&mut self, result: &FrameResult) {
        let success = result.instruction_result().is_ok();
        let output = result.interpreter_result().output.clone();
        if !success {
            // A failed source call reverts funding; child halt gas is settled by EthFrame::return_result.
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

#[cfg(test)]
mod tests;
