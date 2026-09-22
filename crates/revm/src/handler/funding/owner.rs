//! Owner-authorized funding before application calls.

use super::*;
use alloy_primitives::keccak256;
use alloy_sol_types::{SolCall, SolEvent};
use tempo_contracts::precompiles::{
    IAccountKeychain, IFundingSource, ITIP20, ITIP20Funder, TIP20FunderError,
};
use tempo_precompiles::{
    storage::ContractStorage,
    tip20_funder::{InputRate, cost_budget},
};

/// Internal execution input. Signed transaction encoding is defined separately.
pub(in crate::handler) struct FundingRequirement {
    pub token: Address,
    pub amount: U256,
    pub slippage_bps: Option<u16>,
    pub sources: Vec<ITIP20Funder::Source>,
}

enum FundingFailure<E> {
    Execution(EVMError<E, TempoInvalidTransaction>),
    Frame(Box<FrameResult>),
}

impl<E> From<EVMError<E, TempoInvalidTransaction>> for FundingFailure<E> {
    fn from(error: EVMError<E, TempoInvalidTransaction>) -> Self {
        Self::Execution(error)
    }
}

fn invalid_context() -> TempoPrecompileError {
    TIP20FunderError::InvalidFundingContext(ITIP20Funder::InvalidFundingContext {}).into()
}

fn invalid_quote(source: Address) -> TempoPrecompileError {
    TIP20FunderError::InvalidFundingQuote(ITIP20Funder::InvalidFundingQuote { source }).into()
}

fn funding_balance(asset: Address, account: Address) -> tempo_precompiles::error::Result<U256> {
    let invalid = || {
        TempoPrecompileError::from(TIP20FunderError::InvalidAsset(ITIP20Funder::InvalidAsset {
            asset,
        }))
    };
    let token = TIP20Token::from_address(asset).map_err(|_| invalid())?;
    if !token.is_initialized()? {
        return Err(invalid());
    }
    token.balance_of(ITIP20::balanceOfCall { account })
}

impl<DB: alloy_evm::Database, I> TempoEvmHandler<DB, I> {
    pub(in crate::handler) fn require_transaction_funds_with<F>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas: &mut GasTracker,
        run_loop: F,
    ) -> Result<Option<FrameResult>, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnMut(
            &mut Self,
            &mut TempoEvm<DB, I>,
            FrameInit,
        ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>,
    {
        let Some(tx) = evm
            .ctx
            .tx
            .tempo_tx_env
            .as_ref()
            .filter(|tx| !tx.require_funds.is_empty())
        else {
            return Ok(None);
        };
        let funder = tempo_contracts::precompiles::TIP20_FUNDER_ADDRESS;
        let requirements = tx
            .require_funds
            .iter()
            .map(|entry| {
                Ok(FundingRequirement {
                    token: entry.token,
                    amount: entry.amount,
                    slippage_bps: entry
                        .slippage_bps
                        .map(u16::try_from)
                        .transpose()
                        .map_err(|_| TempoInvalidTransaction::InvalidFundingSlippage)?,
                    sources: entry
                        .sources
                        .iter()
                        .map(|source| ITIP20Funder::Source {
                            target: source.target,
                            data: source.data.clone(),
                        })
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, TempoInvalidTransaction>>()?;
        self.require_owner_funds_with(evm, gas, funder, &requirements, run_loop)
    }

    /// Runs native accounting under the same gas budget as the source callbacks.
    fn funding_storage<T>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas: &mut GasTracker,
        operation: impl FnOnce() -> tempo_precompiles::error::Result<T>,
    ) -> Result<T, FundingFailure<DB::Error>> {
        let limit = gas.remaining();
        let actions = evm.actions.clone();
        let (result, used) = StorageCtx::enter_ctx_with_gas_limit(
            evm.ctx_mut(),
            limit,
            gas.reservoir(),
            actions,
            operation,
        );
        match result {
            Ok(value) => {
                assert!(gas.record_regular_cost(used));
                Ok(value)
            }
            Err(error) => {
                let output = error
                    .into_precompile_result(used, gas.reservoir())
                    .map_err(|error| EVMError::Custom(error.to_string()))?;
                let mut result = FrameResult::Call(CallOutcome::new(
                    precompile_output_to_interpreter_result(output, limit),
                    0..0,
                ));
                self.last_frame_result(evm, &mut result, gas)?;
                Err(FundingFailure::Frame(Box::new(result)))
            }
        }
    }

    /// Called only by the transaction handler inside the application's batch checkpoint.
    pub(in crate::handler) fn require_owner_funds_with<F>(
        &mut self,
        evm: &mut TempoEvm<DB, I>,
        gas: &mut GasTracker,
        funder: Address,
        requirements: &[FundingRequirement],
        mut run_loop: F,
    ) -> Result<Option<FrameResult>, EVMError<DB::Error, TempoInvalidTransaction>>
    where
        F: FnMut(
            &mut Self,
            &mut TempoEvm<DB, I>,
            FrameInit,
        ) -> Result<FrameResult, EVMError<DB::Error, TempoInvalidTransaction>>,
    {
        let account = evm.ctx().tx().caller();
        let nested = evm.frame_stack().index().is_some();
        let result = (|| -> Result<(), FundingFailure<DB::Error>> {
            let (key, policy) = self.funding_storage(evm, gas, || {
                if nested || funder.is_zero() || account.is_zero() {
                    return Err(invalid_context());
                }
                let keychain = AccountKeychain::new();
                let key = keychain
                    .get_transaction_key(IAccountKeychain::getTransactionKeyCall {}, account)?;
                if key.is_zero() {
                    return Ok((key, None));
                }
                if !StorageCtx.spec().is_t13() {
                    return Err(invalid_context());
                }
                keychain.validate_funding_key(account)?;
                let id = keychain.get_funding_policy_id(account, key)?;
                let policy = tempo_precompiles::funding_policy::FundingPolicy::new(
                    tempo_contracts::precompiles::FUNDING_POLICY_ADDRESS,
                )
                .get_policy(id)?;
                Ok((key, Some(policy)))
            })?;
            for requirement in requirements {
                let (slippage, rules) = self.funding_storage(evm, gas, || {
                    let Some(policy) = &policy else {
                        return Ok((
                            requirement.slippage_bps.unwrap_or_default(),
                            vec![Bytes::new(); requirement.sources.len()],
                        ));
                    };
                    if requirement
                        .slippage_bps
                        .is_some_and(|bps| bps != policy.slippageBps)
                    {
                        return Err(invalid_context());
                    }
                    StorageCtx.deduct_gas((policy.routes.len() as u64).saturating_mul(3))?;
                    let route = policy
                        .routes
                        .iter()
                        .find(|route| route.token == requirement.token)
                        .ok_or(TIP20FunderError::TokenNotAllowed(
                            ITIP20Funder::TokenNotAllowed {
                                token: requirement.token,
                            },
                        ))?;
                    let mut previous = 0;
                    let mut rules = Vec::with_capacity(requirement.sources.len());
                    for request in &requirement.sources {
                        StorageCtx.deduct_gas((route.sources.len() as u64).saturating_mul(3))?;
                        let position = route
                            .sources
                            .iter()
                            .position(|source| source.target == request.target)
                            .ok_or(TIP20FunderError::FundingNotAuthorized(
                                ITIP20Funder::FundingNotAuthorized {
                                    source: request.target,
                                },
                            ))?;
                        if position < previous {
                            return Err(TIP20FunderError::InvalidSourceOrder(
                                ITIP20Funder::InvalidSourceOrder {},
                            )
                            .into());
                        }
                        previous = position;
                        rules.push(route.sources[position].data.clone());
                    }
                    Ok((policy.slippageBps, rules))
                })?;
                let mut balance = self.funding_storage(evm, gas, || {
                    // Context and argument validation precede the existing-balance shortcut.
                    if slippage > 10_000
                        || requirement
                            .sources
                            .iter()
                            .any(|source| source.target.is_zero() || source.data.is_empty())
                    {
                        return Err(invalid_context());
                    }
                    funding_balance(requirement.token, account)
                })?;
                let initial_balance = balance;
                let mut remaining_cost = self.funding_storage(evm, gas, || {
                    cost_budget(requirement.amount.saturating_sub(balance), slippage)
                        .map_err(|_| invalid_context())
                })?;
                if balance < requirement.amount && !key.is_zero() {
                    self.funding_storage(evm, gas, || {
                        AccountKeychain::new().verify_and_update_spending(
                            account,
                            key,
                            requirement.token,
                            requirement.amount - balance,
                        )
                    })?;
                }
                for (request, policy_data) in requirement.sources.iter().zip(rules) {
                    if balance >= requirement.amount {
                        break;
                    }
                    let result = self.execute_funding_call_with(
                        evm,
                        gas,
                        FundingCall {
                            caller: funder,
                            source: request.target,
                            is_static: true,
                            permission: None,
                            data: IFundingSource::quoteCall {
                                account,
                                amountOut: requirement.amount - balance,
                                assetOut: requirement.token,
                                maxCost: remaining_cost,
                                requestData: request.data.clone(),
                                policyData: policy_data,
                                ownerAuthorized: key.is_zero(),
                            }
                            .abi_encode()
                            .into(),
                        },
                        &mut run_loop,
                    )?;
                    if !result.instruction_result().is_ok() {
                        return Err(FundingFailure::Frame(Box::new(result)));
                    }
                    let (plan, permission) = self.funding_storage(evm, gas, || {
                        let plan = IFundingSource::quoteCall::abi_decode_returns_validate(
                            result.output().data(),
                        )
                        .map_err(|_| invalid_quote(request.target))?;
                        if plan.requestData.is_empty()
                            || plan.amountOut > requirement.amount - balance
                        {
                            return Err(invalid_quote(request.target));
                        }
                        let permission = FundingPermission::new(
                            funder,
                            account,
                            request.target,
                            &plan,
                            remaining_cost,
                        )?;
                        if !plan.assetIn.is_zero() {
                            let rate = InputRate::new(plan.rate)
                                .map_err(|_| invalid_quote(request.target))?;
                            if plan.maxAmountIn > rate.input_capacity(remaining_cost) {
                                return Err(invalid_quote(request.target));
                            }
                        }
                        Ok((plan, permission))
                    })?;
                    let maximum = requirement.amount - balance;
                    let result = self.execute_funding_call_with(
                        evm,
                        gas,
                        FundingCall {
                            caller: funder,
                            source: request.target,
                            is_static: false,
                            permission: Some(&permission),
                            data: IFundingSource::fundCall {
                                account,
                                assetOut: requirement.token,
                                amountOut: maximum,
                                requestData: plan.requestData,
                            }
                            .abi_encode()
                            .into(),
                        },
                        &mut run_loop,
                    )?;
                    if !result.instruction_result().is_ok() {
                        return Err(FundingFailure::Frame(Box::new(result)));
                    }
                    let (new_balance, cost) = self.funding_storage(evm, gas, || {
                        let usage = permission.usage()?;
                        let new_balance = funding_balance(requirement.token, account)?;
                        let received = new_balance.checked_sub(balance);
                        if received.is_none_or(|amount| {
                            amount > maximum || (amount.is_zero() && !usage.amount_in.is_zero())
                        }) {
                            return Err(TIP20FunderError::UnexpectedFundingAmount(
                                ITIP20Funder::UnexpectedFundingAmount {
                                    source: request.target,
                                    maximum,
                                    received: received.unwrap_or_default(),
                                },
                            )
                            .into());
                        }
                        let received = received.unwrap();
                        if !received.is_zero() {
                            AccountKeychain::new().add_funding_credit(
                                account,
                                requirement.token,
                                received,
                            )?;
                            StorageCtx.emit_event(
                                funder,
                                ITIP20Funder::SourceFunded {
                                    account,
                                    assetOut: requirement.token,
                                    source: request.target,
                                    requestHash: keccak256(&request.data),
                                    assetIn: plan.assetIn,
                                    amountIn: usage.amount_in,
                                    amountOut: received,
                                }
                                .encode_log_data(),
                            )?;
                        }
                        Ok((new_balance, usage.input_cost))
                    })?;
                    remaining_cost = self.funding_storage(evm, gas, || {
                        remaining_cost.checked_sub(cost).ok_or_else(invalid_context)
                    })?;
                    balance = new_balance;
                }
                self.funding_storage(evm, gas, || {
                    if balance < requirement.amount {
                        return Err(TIP20FunderError::InsufficientFunding(
                            ITIP20Funder::InsufficientFunding {
                                required: requirement.amount,
                                available: balance,
                            },
                        )
                        .into());
                    }
                    StorageCtx.emit_event(
                        funder,
                        ITIP20Funder::FundsRequired {
                            account,
                            key,
                            asset: requirement.token,
                            requiredAmount: requirement.amount,
                            fundedAmount: balance - initial_balance,
                        }
                        .encode_log_data(),
                    )
                })?;
            }
            // A later requirement may consume an earlier requirement's output.
            for requirement in requirements {
                self.funding_storage(evm, gas, || {
                    let balance = funding_balance(requirement.token, account)?;
                    if balance < requirement.amount {
                        return Err(TIP20FunderError::InsufficientFunding(
                            ITIP20Funder::InsufficientFunding {
                                required: requirement.amount,
                                available: balance,
                            },
                        )
                        .into());
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(None),
            Err(FundingFailure::Frame(result)) => Ok(Some(*result)),
            Err(FundingFailure::Execution(error)) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
