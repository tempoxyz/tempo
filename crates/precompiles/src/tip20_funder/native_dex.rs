//! Native DEX funding hooks, activated at T13.

use super::{RATE_SCALE, permission::require_active};
use crate::{
    Precompile, charge_input_cost, dispatch,
    error::{Result, TempoPrecompileError},
    mutate_void, preserve_storage_credits,
    stablecoin_dex::{StablecoinDEX, StablecoinDEXError},
    storage::{ContractStorage, StorageCtx},
    tip20::{TIP20Error, TIP20Token},
    view,
};
use alloy::sol_types::SolValue;
use alloy_primitives::{Address, U256};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{IFundingSource, ITIP20, ITIP20Funder, TIP20FunderError};

/// Funding through initialized, unpaused tokens with matching currency metadata.
#[derive(Clone)]
pub struct DexFundingSource {
    address: Address,
    funder: Address,
}

impl DexFundingSource {
    pub fn new(address: Address, funder: Address) -> Self {
        Self { address, funder }
    }

    fn validate_context(&self) -> Result<()> {
        // Exact per-order quotes and execution use the same rounding starting at T12.
        if self.funder.is_zero() || self.address.is_zero() || !StorageCtx.spec().is_t13() {
            return Err(TIP20FunderError::InvalidFundingContext(
                ITIP20Funder::InvalidFundingContext {},
            )
            .into());
        }
        Ok(())
    }

    fn validate_asset(&self, asset: Address, currency: &str) -> Result<()> {
        let invalid = || {
            TempoPrecompileError::from(TIP20FunderError::InvalidAsset(ITIP20Funder::InvalidAsset {
                asset,
            }))
        };
        let token = TIP20Token::from_address(asset).map_err(|_| invalid())?;
        if !token.is_initialized()? || token.currency()? != currency {
            return Err(invalid());
        }
        token.check_not_paused()
    }

    fn validate_route(&self, asset_in: Address, asset_out: Address) -> Result<()> {
        let currency = TIP20Token::from_address(asset_out)?.currency()?;
        self.validate_asset(asset_in, &currency)?;
        self.validate_asset(asset_out, &currency)?;
        let dex = StablecoinDEX::new();
        for (key, _) in dex.find_trade_path(asset_in, asset_out)? {
            let book = dex.books(key)?;
            self.validate_asset(book.base, &currency)?;
            self.validate_asset(book.quote, &currency)?;
        }
        Ok(())
    }

    fn decode(&self, data: &[u8]) -> Result<(Address, U256)> {
        <(Address, U256)>::abi_decode_validate(data).map_err(|_| {
            TIP20FunderError::InvalidFundingQuote(ITIP20Funder::InvalidFundingQuote {
                source: self.address,
            })
            .into()
        })
    }

    /// Compares input and cap without reading balances, liquidity, or mutable state.
    pub fn verify(&self, call: IFundingSource::verifyCall) -> Result<bool> {
        let (input, cap) = self.decode(&call.executionData)?;
        let (allowed_input, allowed_cap) = self.decode(&call.configData)?;
        Ok(input == allowed_input && cap <= allowed_cap)
    }

    /// Checks configured routes without reading account balances or orderbook liquidity.
    pub fn supports_token(&self, call: IFundingSource::supportsTokenCall) -> Result<bool> {
        self.validate_context()?;
        let (input, _) = self.decode(&call.configData)?;
        match self.validate_route(input, call.token) {
            Ok(()) => Ok(true),
            Err(TempoPrecompileError::TIP20Funder(TIP20FunderError::InvalidAsset(_)))
            | Err(TempoPrecompileError::TIP20(
                TIP20Error::InvalidToken(_) | TIP20Error::ContractPaused(_),
            ))
            | Err(TempoPrecompileError::StablecoinDEX(
                StablecoinDEXError::IdenticalTokens(_)
                | StablecoinDEXError::InvalidToken(_)
                | StablecoinDEXError::PairDoesNotExist(_),
            )) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Policy data is ABI `(address tokenIn, uint256 maxAmountIn)`.
    pub fn discover(
        &self,
        call: IFundingSource::discoverCall,
    ) -> Result<Vec<IFundingSource::Candidate>> {
        self.validate_context()?;
        let currency = TIP20Token::from_address(call.assetOut)?.currency()?;
        self.validate_asset(call.assetOut, &currency)?;
        let (asset_in, cap) = self.decode(&call.configData)?;
        let mut candidates = Vec::new();
        if asset_in == call.assetOut {
            return Ok(candidates);
        }
        let quote = self.quote_input(
            call.account,
            call.assetOut,
            call.amountOut,
            call.maxCost,
            asset_in,
            cap,
        )?;
        if !quote.amountOut.is_zero() {
            candidates.push(IFundingSource::Candidate {
                executionData: quote.executionData,
                availableAmount: quote.amountOut,
            });
        }
        Ok(candidates)
    }

    /// Data is ABI `(address assetIn, uint256 maxAmountIn)`; omitted caps encode as `uint256.max`.
    pub fn quote(&self, call: IFundingSource::quoteCall) -> Result<IFundingSource::Quote> {
        self.validate_context()?;
        let (asset_in, cap) = self.decode(&call.executionData)?;
        let authorized = if call.ownerAuthorized {
            call.configData.is_empty()
        } else {
            self.verify(IFundingSource::verifyCall {
                executionData: call.executionData.clone(),
                configData: call.configData.clone(),
            })?
        };
        if !authorized {
            return Err(TIP20FunderError::FundingNotAuthorized(
                ITIP20Funder::FundingNotAuthorized {
                    source: self.address,
                },
            )
            .into());
        }
        self.quote_input(
            call.account,
            call.assetOut,
            call.amountOut,
            call.maxCost,
            asset_in,
            cap,
        )
    }

    fn quote_input(
        &self,
        account: Address,
        asset_out: Address,
        amount_out: U256,
        max_cost: U256,
        asset_in: Address,
        cap: U256,
    ) -> Result<IFundingSource::Quote> {
        self.validate_route(asset_in, asset_out)?;
        // All native TIP-20 tokens have six decimals; approved parity therefore uses rate 1e18.
        let cap = cap.min(max_cost).min(U256::from(u128::MAX));
        Ok(IFundingSource::Quote {
            assetIn: asset_in,
            rate: RATE_SCALE,
            maxAmountIn: cap,
            amountOut: U256::from(
                self.available_output(account, asset_in, asset_out, amount_out, cap)?,
            ),
            executionData: (asset_in, cap).abi_encode().into(),
        })
    }

    pub fn fund(&self, caller: Address, call: IFundingSource::fundCall) -> Result<()> {
        self.validate_context()?;
        if caller != self.funder {
            return Err(TIP20FunderError::InvalidFundingContext(
                ITIP20Funder::InvalidFundingContext {},
            )
            .into());
        }
        require_active(self.funder, call.account, self.address)?;
        let (asset_in, cap) = self.decode(&call.executionData)?;
        self.validate_route(asset_in, call.assetOut)?;
        let contribution =
            self.available_output(call.account, asset_in, call.assetOut, call.amountOut, cap)?;
        if contribution == 0 {
            return Ok(());
        }
        let mut dex = StablecoinDEX::new();
        preserve_storage_credits(dex.address())?;
        dex.swap_exact_amount_out(
            call.account,
            asset_in,
            call.assetOut,
            contribution,
            cap.min(U256::from(u128::MAX)).to::<u128>(),
        )?;
        Ok(())
    }
    fn available_output(
        &self,
        account: Address,
        asset_in: Address,
        asset_out: Address,
        amount_out: U256,
        cap: U256,
    ) -> Result<u128> {
        let dex = StablecoinDEX::new();
        let wallet =
            TIP20Token::from_address(asset_in)?.balance_of(ITIP20::balanceOfCall { account })?;
        let internal = U256::from(dex.balance_of(account, asset_in)?);
        let available = wallet
            .saturating_add(internal)
            .min(cap)
            .min(U256::from(u128::MAX))
            .to::<u128>();
        let requested = amount_out.min(U256::from(u128::MAX)).to::<u128>();
        if available == 0 || requested == 0 {
            return Ok(0);
        }
        executable_output(&dex, asset_in, asset_out, requested, available)
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

impl Precompile for DexFundingSource {
    fn call(&mut self, calldata: &[u8], caller: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut StorageCtx, calldata) {
            return error;
        }
        dispatch!(calldata, |call| match call {
            IFundingSource::IFundingSourceCalls {
                verify(call) => view(call, |call| self.verify(call)),
                supportsToken(call) => view(call, |call| self.supports_token(call)),
                discover(call) => view(call, |call| self.discover(call)),
                quote(call) => view(call, |call| self.quote(call)),
                fund(call) => mutate_void(call, caller, |caller, call| self.fund(caller, call)),
            }
        })
    }
}

#[cfg(test)]
mod tests;
