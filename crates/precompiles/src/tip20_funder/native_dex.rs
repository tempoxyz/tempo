//! Native DEX funding hooks. No address is registered until funding activation.

use super::{RATE_SCALE, permission::require_active};
use crate::{
    Precompile, charge_input_cost, dispatch,
    error::{Result, TempoPrecompileError},
    mutate_void, preserve_storage_credits,
    stablecoin_dex::{StablecoinDEX, StablecoinDEXError},
    storage::{ContractStorage, StorageCtx},
    tip20::TIP20Token,
    view,
};
use alloy::sol_types::SolValue;
use alloy_primitives::{Address, U256};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{IFundingSource, ITIP20, ITIP20Funder, TIP20FunderError};

/// Explicitly configured parity assets, not inferred from token names or currency metadata.
#[derive(Clone)]
pub struct NativeDexFundingSource {
    address: Address,
    funder: Address,
    parity_assets: Vec<Address>,
}

impl NativeDexFundingSource {
    pub fn new(address: Address, funder: Address, parity_assets: Vec<Address>) -> Self {
        Self {
            address,
            funder,
            parity_assets,
        }
    }

    fn validate_caller(&self, caller: Address) -> Result<()> {
        // Exact per-order quotes and execution use the same rounding starting at T12.
        if caller != self.funder
            || caller.is_zero()
            || self.address.is_zero()
            || !StorageCtx.spec().is_t12()
        {
            return Err(TIP20FunderError::InvalidFundingContext(
                ITIP20Funder::InvalidFundingContext {},
            )
            .into());
        }
        Ok(())
    }

    fn validate_asset(&self, asset: Address) -> Result<()> {
        let invalid = || {
            TempoPrecompileError::from(TIP20FunderError::InvalidAsset(ITIP20Funder::InvalidAsset {
                asset,
            }))
        };
        if !self.parity_assets.contains(&asset) {
            return Err(invalid());
        }
        let token = TIP20Token::from_address(asset).map_err(|_| invalid())?;
        if !token.is_initialized()? {
            return Err(invalid());
        }
        token.check_not_paused()
    }

    fn validate_route(&self, asset_in: Address, asset_out: Address) -> Result<()> {
        self.validate_asset(asset_in)?;
        self.validate_asset(asset_out)?;
        let dex = StablecoinDEX::new();
        for (key, _) in dex.find_trade_path(asset_in, asset_out)? {
            let book = dex.books(key)?;
            self.validate_asset(book.base)?;
            self.validate_asset(book.quote)?;
        }
        Ok(())
    }

    fn decode(&self, data: &[u8]) -> Result<(Address, U256)> {
        <(Address, U256)>::abi_decode_validate(data).map_err(|_| {
            TIP20FunderError::InvalidFundingPlan(ITIP20Funder::InvalidFundingPlan {
                source: self.address,
            })
            .into()
        })
    }

    /// Data is ABI `(address assetIn, uint256 maxAmountIn)`; omitted caps encode as `uint256.max`.
    pub fn prepare(
        &self,
        caller: Address,
        call: IFundingSource::prepareCall,
    ) -> Result<IFundingSource::Plan> {
        self.validate_caller(caller)?;
        if !call.ownerAuthorized || !call.policyData.is_empty() {
            return Err(TIP20FunderError::FundingNotAuthorized(
                ITIP20Funder::FundingNotAuthorized {
                    source: self.address,
                },
            )
            .into());
        }
        let (asset_in, cap) = self.decode(&call.data)?;
        self.validate_route(asset_in, call.assetOut)?;
        // All native TIP-20 tokens have six decimals; approved parity therefore uses rate 1e18.
        let cap = cap.min(call.maxCost).min(U256::from(u128::MAX));
        Ok(IFundingSource::Plan {
            assetIn: asset_in,
            rate: RATE_SCALE,
            maxAmountIn: cap,
            data: (asset_in, cap).abi_encode().into(),
        })
    }

    pub fn fund(&self, caller: Address, call: IFundingSource::fundCall) -> Result<()> {
        self.validate_caller(caller)?;
        require_active(self.funder, call.account, self.address)?;
        let (asset_in, cap) = self.decode(&call.data)?;
        self.validate_route(asset_in, call.assetOut)?;
        let mut dex = StablecoinDEX::new();
        let wallet = TIP20Token::from_address(asset_in)?.balance_of(ITIP20::balanceOfCall {
            account: call.account,
        })?;
        let internal = U256::from(dex.balance_of(call.account, asset_in)?);
        let available = wallet
            .saturating_add(internal)
            .min(cap)
            .min(U256::from(u128::MAX))
            .to::<u128>();
        let requested = call.amountOut.min(U256::from(u128::MAX)).to::<u128>();
        if available == 0 || requested == 0 {
            return Ok(());
        }
        let contribution = executable_output(&dex, asset_in, call.assetOut, requested, available)?;
        if contribution == 0 {
            return Ok(());
        }
        preserve_storage_credits(dex.address())?;
        dex.swap_exact_amount_out(
            call.account,
            asset_in,
            call.assetOut,
            contribution,
            available,
        )?;
        Ok(())
    }
}

/// Quotes are monotonic; at most 129 metered probes find the largest affordable, liquid output.
fn executable_output(
    dex: &StablecoinDEX,
    asset_in: Address,
    asset_out: Address,
    requested: u128,
    cap: u128,
) -> Result<u128> {
    let affordable = |output| -> Result<bool> {
        match dex.quote_swap_exact_amount_out(asset_in, asset_out, output) {
            Ok(input) => Ok(input <= cap),
            Err(TempoPrecompileError::StablecoinDEX(
                StablecoinDEXError::InsufficientLiquidity(_),
            )) => Ok(false),
            Err(error) => Err(error),
        }
    };
    if affordable(requested)? {
        return Ok(requested);
    }
    let (mut low, mut high) = (0, requested - 1);
    while low < high {
        let distance = high - low;
        let mid = low + distance / 2 + distance % 2;
        if affordable(mid)? {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(low)
}

impl Precompile for NativeDexFundingSource {
    fn call(&mut self, calldata: &[u8], caller: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut StorageCtx, calldata) {
            return error;
        }
        dispatch!(calldata, |call| match call {
            IFundingSource::IFundingSourceCalls {
                prepare(call) => view(call, |call| self.prepare(caller, call)),
                fund(call) => mutate_void(call, caller, |caller, call| self.fund(caller, call)),
            }
        })
    }
}

#[cfg(test)]
mod tests;
