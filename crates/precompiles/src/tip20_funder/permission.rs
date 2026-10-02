//! Native-only input authority; consumption follows the EVM transient-storage journal.

use alloy_primitives::{Address, U256};
use scoped_tls::scoped_thread_local;
use tempo_contracts::precompiles::{IAccountKeychain, TIP20FunderError};

use super::{IFundingSource, ITIP20Funder, InputRate};
use crate::{account_keychain::AccountKeychain, error::Result, storage::StorageCtx};

scoped_thread_local!(static ACTIVE: FundingPermission);
const AMOUNT_IN_SLOT: U256 = U256::ZERO;

/// Validated authority installed only by the transaction handler around one funding callback.
#[derive(Debug)]
pub struct FundingPermission {
    funder: Address,
    account: Address,
    source: Address,
    asset_in: Address,
    rate: Option<InputRate>,
    max_amount_in: U256,
    max_cost: U256,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FundingUsage {
    pub amount_in: U256,
    pub input_cost: U256,
}

fn invalid_context() -> crate::error::TempoPrecompileError {
    TIP20FunderError::InvalidFundingContext(ITIP20Funder::InvalidFundingContext {}).into()
}

impl FundingPermission {
    /// The funder address is supplied internally until protocol activation assigns its final address.
    pub fn new(
        funder: Address,
        account: Address,
        source: Address,
        plan: &IFundingSource::Quote,
        max_cost: U256,
    ) -> Result<Self> {
        let invalid = || {
            crate::error::TempoPrecompileError::from(TIP20FunderError::InvalidFundingQuote(
                ITIP20Funder::InvalidFundingQuote { source },
            ))
        };
        if funder.is_zero() || account.is_zero() || source.is_zero() {
            return Err(invalid_context());
        }
        let rate = if plan.assetIn.is_zero() {
            if !plan.rate.is_zero() || !plan.maxAmountIn.is_zero() {
                return Err(invalid());
            }
            None
        } else {
            Some(InputRate::new(plan.rate).map_err(|_| invalid())?)
        };
        Ok(Self {
            funder,
            account,
            source,
            asset_in: plan.assetIn,
            rate,
            max_amount_in: plan.maxAmountIn,
            max_cost,
        })
    }

    pub fn matches(&self, funder: Address, account: Address, source: Address) -> bool {
        (self.funder, self.account, self.source) == (funder, account, source)
    }

    /// Starts fresh counters. Access keys remain disabled until delegated accounting is implemented.
    pub fn initialize(&self) -> Result<()> {
        if ACTIVE.is_set()
            || !AccountKeychain::new()
                .get_transaction_key(IAccountKeychain::getTransactionKeyCall {}, self.account)?
                .is_zero()
        {
            return Err(invalid_context());
        }
        StorageCtx.tstore(self.funder, AMOUNT_IN_SLOT, U256::ZERO)
    }

    /// The synchronous callback and descendants are the entire lifetime of this authority.
    pub fn enter<T>(&self, f: impl FnOnce() -> T) -> Result<T> {
        if ACTIVE.is_set() {
            return Err(invalid_context());
        }
        Ok(ACTIVE.set(self, f))
    }

    /// Read before initializing the next invocation; closing native scope removes authority, not these counters.
    pub fn usage(&self) -> Result<FundingUsage> {
        let amount_in = StorageCtx.tload(self.funder, AMOUNT_IN_SLOT)?;
        let input_cost = match self.rate {
            Some(rate) => rate.input_cost(amount_in).map_err(|_| invalid_context())?,
            None => U256::ZERO,
        };
        Ok(FundingUsage {
            amount_in,
            input_cost,
        })
    }
}

/// Rejects source execution outside the protocol's matching input permission.
pub(crate) fn require_active(funder: Address, account: Address, source: Address) -> Result<()> {
    if !ACTIVE.is_set() || !ACTIVE.with(|permission| permission.matches(funder, account, source)) {
        return Err(invalid_context());
    }
    Ok(())
}

/// Returns false outside funding or for another owner's funds, preserving ordinary authorization.
pub(crate) fn meter_input(owner: Address, asset: Address, amount: U256) -> Result<bool> {
    input_permission(owner, asset, amount, true)
}

/// Checks bounded authority before allowance validation without charging a debit twice.
pub(crate) fn authorize_input(owner: Address, asset: Address, amount: U256) -> Result<bool> {
    input_permission(owner, asset, amount, false)
}

fn input_permission(owner: Address, asset: Address, amount: U256, consume: bool) -> Result<bool> {
    if !ACTIVE.is_set() {
        return Ok(false);
    }
    ACTIVE.with(|permission| {
        if owner != permission.account {
            return Ok(false);
        }
        if asset != permission.asset_in || permission.rate.is_none() {
            return Err(TIP20FunderError::FundingNotAuthorized(
                ITIP20Funder::FundingNotAuthorized {
                    source: permission.source,
                },
            )
            .into());
        }
        let used = StorageCtx.tload(permission.funder, AMOUNT_IN_SLOT)?;
        let limit = permission
            .max_amount_in
            .min(permission.rate.unwrap().input_capacity(permission.max_cost));
        let next = used.checked_add(amount);
        if next.is_none_or(|next| next > limit) {
            return Err(
                TIP20FunderError::InputLimitExceeded(ITIP20Funder::InputLimitExceeded {
                    source: permission.source,
                    limit,
                    attempted: next.unwrap_or(U256::MAX),
                })
                .into(),
            );
        }
        if consume {
            StorageCtx.tstore(permission.funder, AMOUNT_IN_SLOT, next.unwrap())?;
        }
        Ok(true)
    })
}

#[cfg(test)]
mod tests;
