use crate::{
    error::{Result, TempoPrecompileError},
    storage::{
        ContractStorage, Handler, StorageAction, StorageCtx, StorageKey, packing::insert_into_word,
    },
    tip_fee_manager::{ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent, TipFeeManager},
    tip20::{ITIP20, TIP20Token, validate_usd_currency},
    tip403_registry::AuthRole,
};
use alloy::{
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use tempo_precompiles_macros::Storable;

/// Fee multiplier for fee swaps: 0.9970 scaled by 10000 (30 bps fee).
pub const M: U256 = uint!(9970_U256);
/// Fee multiplier for rebalance swaps: 0.9985 scaled by 10000.
pub const N: U256 = uint!(9985_U256);
/// Scale factor for fixed-point AMM arithmetic (10000).
pub const SCALE: U256 = uint!(10000_U256);
/// Minimum liquidity locked permanently when initializing a pool.
pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);

/// Computes the output amount for a fee swap: `amount_in * M / SCALE`.
///
/// # Errors
/// - `UnderOverflow` — multiplication of `amount_in * M` overflows
#[inline]
pub fn compute_amount_out(amount_in: U256) -> Result<U256> {
    amount_in
        .checked_mul(M)
        .map(|product| product / SCALE)
        .ok_or(TempoPrecompileError::under_overflow())
}

/// AMM pool reserves for a user-token / validator-token pair.
#[derive(Debug, Clone, Default, Storable)]
pub struct Pool {
    /// Reserve of the user's fee token.
    pub reserve_user_token: u128,
    /// Reserve of the validator's fee token.
    pub reserve_validator_token: u128,
}

impl From<Pool> for ITIPFeeAMM::Pool {
    fn from(value: Pool) -> Self {
        Self {
            reserveUserToken: value.reserve_user_token,
            reserveValidatorToken: value.reserve_validator_token,
        }
    }
}

/// Identifies a directional token pair in the fee AMM.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Storable)]
pub struct PoolKey {
    /// The fee token chosen by the user (transaction sender).
    pub user_token: Address,
    /// The fee token chosen by the validator (block producer).
    pub validator_token: Address,
}

impl Pool {
    /// Decodes a [`Pool`] from a raw EVM storage slot value (needed from changeset diffs).
    pub fn decode_from_slot(slot_value: U256) -> Self {
        use crate::storage::{LayoutCtx, Storable, packing::PackedSlot};

        // NOTE: fine to expect, as `StorageOps` on `PackedSlot` are infallible
        Self::load(&PackedSlot(slot_value), U256::ZERO, LayoutCtx::FULL)
            .expect("unable to decode Pool from slot")
    }

    /// Encodes a [`Pool`] into the raw EVM storage slot value.
    pub fn encode_to_slot(&self) -> Result<U256> {
        let slot = insert_into_word(
            U256::ZERO,
            &self.reserve_user_token,
            __packing_pool::RESERVE_USER_TOKEN_LOC.offset_bytes,
            __packing_pool::RESERVE_USER_TOKEN_LOC.size,
        )?;
        let slot = insert_into_word(
            slot,
            &self.reserve_validator_token,
            __packing_pool::RESERVE_VALIDATOR_TOKEN_LOC.offset_bytes,
            __packing_pool::RESERVE_VALIDATOR_TOKEN_LOC.size,
        )?;
        Ok(slot)
    }

    /// Applies a fee swap to the pool.
    ///
    /// Checks `amount_out <= self.reserve_validator_token`, increments `self.reserve_user_token` by `amount_in`,
    /// and decrements `self.reserve_validator_token` by `amount_out`.
    pub fn apply_swap(&mut self, amount_in: U256, amount_out: U256) -> Result<()> {
        // Check if there's enough validatorToken available
        if amount_out > U256::from(self.reserve_validator_token) {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        let amount_in: u128 = amount_in
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?;
        let amount_out: u128 = amount_out
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?;

        // Update reserves
        self.reserve_user_token = self
            .reserve_user_token
            .checked_add(amount_in)
            .ok_or_else(TempoPrecompileError::under_overflow)?;
        self.reserve_validator_token = self
            .reserve_validator_token
            .checked_sub(amount_out)
            .ok_or_else(TempoPrecompileError::under_overflow)?;

        Ok(())
    }

    /// Returns whether the pool has enough reserve validator token to cover the given amount.
    pub fn has_enough_reserve_validator_token(&self, amount: U256) -> bool {
        // Reject empty pools, even for zero-output swaps, so no input lands in an LP-less pool.
        self.reserve_validator_token != 0 && U256::from(self.reserve_validator_token) >= amount
    }
}

impl PoolKey {
    /// Creates a new pool key from user and validator token addresses.
    /// This key uniquely identifies a trading pair in the AMM.
    pub fn new(user_token: Address, validator_token: Address) -> Self {
        Self {
            user_token,
            validator_token,
        }
    }

    /// Generates a unique pool ID by hashing the token pair addresses.
    /// Uses keccak256 to create a deterministic identifier for this pool.
    pub fn get_id(&self) -> B256 {
        keccak256((self.user_token, self.validator_token).abi_encode())
    }
}

/// AMM path [`TipFeeManager`] will take to swap `user_token` into `validator_token` for fee collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeRoute {
    /// User and validator share the same fee token; no swap is performed.
    SameToken,
    /// Direct pool `(user_token, validator_token)` swap.
    Direct,
    /// Two-hop swap (T5+): routes through `intermediate = userToken.quoteToken()`.
    /// Each hop applies the standard `M = 9970/10000` rate sequentially.
    TwoHop(Address),
}

/// Pools read during planning, paired with their observed validator-token reserve.
pub type PoolData = ((Address, Address), u128);

impl TipFeeManager {
    /// Returns the deterministic pool ID for a directional token pair. Note that the pool id is
    /// order-dependent: `(A, B)` produces a different ID than `(B, A)`.
    pub fn pool_id(&self, user_token: Address, validator_token: Address) -> B256 {
        PoolKey::new(user_token, validator_token).get_id()
    }

    /// Returns the [`Pool`] reserves for the given user/validator token pair.
    pub fn get_pool(&self, call: ITIPFeeAMM::getPoolCall) -> Result<Pool> {
        let pool_id = self.pool_id(call.userToken, call.validatorToken);
        self.pools[pool_id].read()
    }

    /// Reserves pool liquidity in transient storage for a pending fee swap.
    #[inline]
    pub fn reserve_pool_liquidity(&mut self, pool_id: B256, amount: u128) -> Result<()> {
        self.pending_fee_swap_reservation[pool_id].t_write(amount)
    }

    /// Executes a rebalance swap: sells `amount_out` of user-token from the pool in exchange for
    /// validator-token at the rebalance rate (`N / SCALE`). Used by arbitrageurs to rebalance reserves.
    ///
    /// # Errors
    /// - `InvalidAmount` — `amount_out` is zero or exceeds `u128`
    /// - `InsufficientReserves` — adding `amount_in` overflows the validator reserve
    /// - `InsufficientLiquidity` — remaining reserve would violate the pending reservation (T1C+)
    /// - `UnderOverflow` — arithmetic overflow computing `amount_in`
    /// - `PolicyForbids` — `to`'s receive policy would divert the payout into a receipt only the
    ///   FeeManager could claim (T15+)
    pub fn rebalance_swap(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_out: U256,
        to: Address,
    ) -> Result<U256> {
        if amount_out.is_zero() {
            return Err(TIPFeeAMMError::invalid_amount().into());
        }

        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools[pool_id].read()?;

        // Rebalancing swaps are always from validatorToken to userToken
        // Calculate input and update reserves
        let amount_in = amount_out
            .checked_mul(N)
            .and_then(|product| product.checked_div(SCALE))
            .and_then(|result| result.checked_add(U256::ONE))
            .ok_or(TempoPrecompileError::under_overflow())?;

        let amount_in: u128 = amount_in
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let amount_out: u128 = amount_out
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(amount_in)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_sub(amount_out)
            .ok_or(TIPFeeAMMError::invalid_amount())?;

        if self.storage.spec().is_t1c() {
            let reserved = self.pending_fee_swap_reservation[pool_id].t_read()?;
            if pool.reserve_validator_token < reserved {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }
        }

        self.ensure_payout_claimable(user_token, to)?;

        self.pools[pool_id].write(pool)?;

        let amount_in = U256::from(amount_in);
        let amount_out = U256::from(amount_out);
        let mut validator_token = TIP20Token::from_address(validator_token)?;
        validator_token.system_transfer_from(self.address, msg_sender, amount_in)?;

        // collect_fee_pre_tx creates FeeManager balance slots for free; do not convert them into storage credits.
        StorageCtx.set_tip1060_storage_credit_minting(false);
        let mut user_token = TIP20Token::from_address(user_token)?;
        user_token.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_out,
            },
        )?;

        self.emit_event(TIPFeeAMMEvent::rebalance_swap(
            user_token.address(),
            validator_token.address(),
            msg_sender,
            amount_in,
            amount_out,
        ))?;

        Ok(amount_in)
    }

    /// Mints LP tokens by depositing validator-token into a pool.
    ///
    /// On first deposit the pool is initialized with equal reserves and [`MIN_LIQUIDITY`] is
    /// permanently locked. Subsequent deposits mint pro-rata to existing supply. Both tokens
    /// must be distinct, USD-denominated TIP-20s.
    ///
    /// NOTE: Validators who also provide liquidity have an information advantage over non-validator
    /// LPs. Because validators choose their preferred fee token and control transaction inclusion
    /// order as block producers, a validator-LP can predict which pool will receive fee-swap
    /// revenue and position liquidity accordingly.
    ///
    /// # Errors
    /// - `IdenticalAddresses` — `user_token` equals `validator_token`
    /// - `InvalidAmount` — `amount_validator_token` is zero or exceeds `u128`
    /// - `InvalidCurrency` — either token is not USD-denominated
    /// - `InsufficientLiquidity` — initial deposit ≤ `MIN_LIQUIDITY`, or zero liquidity minted
    /// - `InvalidSwapCalculation` — pro-rata arithmetic fails
    /// - `UnderOverflow` — supply or balance overflow
    pub fn mint(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_validator_token: U256,
        to: Address,
    ) -> Result<U256> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses().into());
        }

        if amount_validator_token.is_zero() {
            return Err(TIPFeeAMMError::invalid_amount().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token)?;
        validate_usd_currency(validator_token)?;

        let user_token = TIP20Token::from_address(user_token)?;
        let mut validator_token = TIP20Token::from_address(validator_token)?;
        if self.storage.spec().is_t8() {
            user_token.ensure_authorized_as(&[
                (msg_sender, AuthRole::sender()),
                (self.address, AuthRole::recipient()),
                (to, AuthRole::recipient()),
            ])?;
            validator_token.ensure_authorized_as(&[(to, AuthRole::recipient())])?;
        }

        let pool_id = self.pool_id(user_token.address(), validator_token.address());
        let mut pool = self.pools[pool_id].read()?;
        let mut total_supply = self.get_total_supply(pool_id)?;

        let liquidity = if pool.reserve_user_token == 0 && pool.reserve_validator_token == 0 {
            let half_amount = amount_validator_token
                .checked_div(uint!(2_U256))
                .ok_or(TempoPrecompileError::under_overflow())?;

            if half_amount <= MIN_LIQUIDITY {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }

            total_supply = total_supply
                .checked_add(MIN_LIQUIDITY)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_total_supply(pool_id, total_supply)?;

            half_amount
                .checked_sub(MIN_LIQUIDITY)
                .ok_or(TIPFeeAMMError::insufficient_liquidity())?
        } else {
            // Subsequent deposits: mint as if user called rebalanceSwap then minted with both
            // liquidity = amountValidatorToken * _totalSupply / (V + n * U), with n = N / SCALE
            let product = N
                .checked_mul(U256::from(pool.reserve_user_token))
                .and_then(|product| product.checked_div(SCALE))
                .ok_or(TIPFeeAMMError::invalid_swap_calculation())?;

            let denom = U256::from(pool.reserve_validator_token)
                .checked_add(product)
                .ok_or(TIPFeeAMMError::invalid_amount())?;

            if denom.is_zero() {
                return Err(TIPFeeAMMError::division_by_zero().into());
            }

            amount_validator_token
                .checked_mul(total_supply)
                .and_then(|numerator| numerator.checked_div(denom))
                .ok_or(TIPFeeAMMError::invalid_swap_calculation())?
        };

        if liquidity.is_zero() {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        // Transfer validator tokens from user
        let _ = validator_token.system_transfer_from(
            self.address,
            msg_sender,
            amount_validator_token,
        )?;

        // Update reserves
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(validator_amount)
            .ok_or(TIPFeeAMMError::invalid_amount())?;

        self.pools[pool_id].write(pool)?;

        // Mint LP tokens
        self.set_total_supply(
            pool_id,
            total_supply
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        let balance = self.get_liquidity_balances(pool_id, to)?;
        self.set_liquidity_balances(
            pool_id,
            to,
            balance
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Emit Mint event
        self.emit_event(TIPFeeAMMEvent::mint(
            msg_sender,
            to,
            user_token.address(),
            validator_token.address(),
            amount_validator_token,
            liquidity,
        ))?;

        Ok(liquidity)
    }

    /// Burns LP tokens and returns the pro-rata share of both pool tokens to `to`.
    ///
    /// On T1C+ the burn is rejected if the remaining validator-token reserve would fall below
    /// the pending fee-swap reservation set by [`TipFeeManager::reserve_pool_liquidity`].
    ///
    /// # Errors
    /// - `IdenticalAddresses` — `user_token` equals `validator_token`
    /// - `InvalidAmount` — `liquidity` is zero or amounts exceed `u128`
    /// - `InvalidCurrency` — either token is not USD-denominated
    /// - `InsufficientLiquidity` — caller's balance < `liquidity`, or remaining reserve would
    ///   violate the pending reservation (T1C+)
    /// - `InsufficientReserves` — pool reserves underflow after withdrawal
    /// - `PolicyForbids` — `to`'s receive policy would divert either payout into a receipt only the
    ///   FeeManager could claim (T15+)
    /// - `UnderOverflow` — supply or balance arithmetic overflows
    pub fn burn(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        liquidity: U256,
        to: Address,
    ) -> Result<(U256, U256)> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses().into());
        }

        if liquidity.is_zero() {
            return Err(TIPFeeAMMError::invalid_amount().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token)?;
        validate_usd_currency(validator_token)?;

        let mut user_token = TIP20Token::from_address(user_token)?;
        let mut validator_token = TIP20Token::from_address(validator_token)?;
        if self.storage.spec().is_t8() {
            user_token.ensure_authorized_as(&[(msg_sender, AuthRole::sender())])?;
            validator_token.ensure_authorized_as(&[(msg_sender, AuthRole::sender())])?;
        }

        let pool_id = self.pool_id(user_token.address(), validator_token.address());
        // Check user has sufficient liquidity
        let balance = self.get_liquidity_balances(pool_id, msg_sender)?;
        if balance < liquidity {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        let mut pool = self.pools[pool_id].read()?;
        // Calculate amounts to return
        let (amount_user_token, amount_validator_token) =
            self.calculate_burn_amounts(&pool, pool_id, liquidity)?;

        // T1C+: Check that burn leaves enough liquidity for pending fee swaps
        // Reservation is set by reserve_pool_liquidity() in collect_fee_pre_tx
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let available_after_burn = pool
            .reserve_validator_token
            .checked_sub(validator_amount)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;
        if self.storage.spec().is_t1c() {
            let reserved = self.pending_fee_swap_reservation[pool_id].t_read()?;
            if available_after_burn < reserved {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }
        }

        if !amount_user_token.is_zero() {
            self.ensure_payout_claimable(user_token.address(), to)?;
        }
        if !amount_validator_token.is_zero() {
            self.ensure_payout_claimable(validator_token.address(), to)?;
        }

        // Burn LP tokens
        self.set_liquidity_balances(
            pool_id,
            msg_sender,
            balance
                .checked_sub(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        let total_supply = self.get_total_supply(pool_id)?;
        #[cfg(feature = "fuzz")]
        antithesis_sdk::assert_always_or_unreachable!(
            liquidity <= total_supply,
            "Fee AMM LP burn stays within the pool's LP total supply",
            &serde_json::json!({
                "pool_id": pool_id.to_string(),
                "liquidity": liquidity.to_string(),
                "total_supply": total_supply.to_string(),
            })
        );
        self.set_total_supply(
            pool_id,
            total_supply
                .checked_sub(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Update reserves with underflow checks
        let user_amount: u128 = amount_user_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_sub(user_amount)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;
        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_sub(validator_amount)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;
        self.pools[pool_id].write(pool)?;

        // Transfer tokens to user
        let _ = user_token.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_user_token,
            },
        )?;

        let _ = validator_token.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_validator_token,
            },
        )?;

        // Emit Burn event
        self.emit_event(TIPFeeAMMEvent::burn(
            msg_sender,
            user_token.address(),
            validator_token.address(),
            amount_user_token,
            amount_validator_token,
            liquidity,
            to,
        ))?;

        Ok((amount_user_token, amount_validator_token))
    }

    /// Calculate burn amounts for liquidity withdrawal
    fn calculate_burn_amounts(
        &self,
        pool: &Pool,
        pool_id: B256,
        liquidity: U256,
    ) -> Result<(U256, U256)> {
        let total_supply = self.get_total_supply(pool_id)?;
        let amount_user_token = liquidity
            .checked_mul(U256::from(pool.reserve_user_token))
            .and_then(|product| product.checked_div(total_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;
        let amount_validator_token = liquidity
            .checked_mul(U256::from(pool.reserve_validator_token))
            .and_then(|product| product.checked_div(total_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;

        Ok((amount_user_token, amount_validator_token))
    }

    /// Plans the AMM path needed to swap `max_amount` of `user_token` into `validator_token`
    /// under the active hardfork. Read-only; does not reserve.
    ///
    /// On T5+ falls back to a two-hop path through `userToken.quoteToken()` as per [TIP-1033].
    /// Returns `(route, queried_intermediate, pools)`:
    /// - `route` is `None` when no path has sufficient liquidity.
    /// - `queried_intermediate` is `Some(addr)` whenever `userToken.quoteToken()` was read,
    ///   regardless of whether the value is usable. Callers can cache it to skip the cold
    ///   storage read on subsequent admissions.
    /// - `pools` lists every pool slot read during planning, paired with its observed reserve.
    ///
    /// # Errors
    /// - `InvalidToken` — `user_token` does not have a valid TIP-20 prefix
    /// - `UnderOverflow` — fee-amount arithmetic overflows
    ///
    /// [TIP-1033]: <https://docs.tempo.xyz/protocol/tips/tip-1033>
    pub fn plan_fee_route(
        &self,
        user_token: Address,
        validator_token: Address,
        max_amount: U256,
    ) -> Result<(Option<FeeRoute>, Option<Address>, Vec<PoolData>)> {
        let mut data = Vec::new();

        if user_token == validator_token {
            return Ok((Some(FeeRoute::SameToken), None, data));
        }

        let actions = self.storage.actions();

        actions.unrecorded(|| {
            let amount_out = compute_amount_out(max_amount)?;

            // Direct (single-hop) path — always checked.
            let direct_slot = &self.pools[self.pool_id(user_token, validator_token)];
            let direct = direct_slot.read()?;
            data.push((
                (user_token, validator_token),
                direct.reserve_validator_token,
            ));
            let has_enough_liquidity = direct.has_enough_reserve_validator_token(amount_out);
            actions.record_always(StorageAction::FeeAmmLiquidityCheck(
                direct_slot.as_slot().slot(),
                direct.encode_to_slot()?,
                amount_out,
                has_enough_liquidity,
            ));
            if has_enough_liquidity {
                return Ok((Some(FeeRoute::Direct), None, data));
            }

            // T5+: two-hop fallback through `userToken.quoteToken()`.
            if !self.storage.spec().is_t5() {
                return Ok((None, None, data));
            }

            // TIP-20 token graph forbids self-quoting, so `intermediate == user_token` is unreachable.
            let mid_token =
                actions.recorded(|| TIP20Token::from_address(user_token)?.quote_token())?;
            if mid_token.is_zero() || mid_token == validator_token {
                return Ok((None, Some(mid_token), data));
            }

            // First leg: user_token -> intermediate.
            let leg1_slot = &self.pools[self.pool_id(user_token, mid_token)];
            let leg1 = leg1_slot.read()?;
            data.push(((user_token, mid_token), leg1.reserve_validator_token));
            let has_enough_liquidity = leg1.has_enough_reserve_validator_token(amount_out);
            actions.record_always(StorageAction::FeeAmmLiquidityCheck(
                leg1_slot.as_slot().slot(),
                leg1.encode_to_slot()?,
                amount_out,
                has_enough_liquidity,
            ));
            if !has_enough_liquidity {
                return Ok((None, Some(mid_token), data));
            }

            // Second leg: intermediate -> validator_token.
            let amount_out2 = compute_amount_out(amount_out)?;
            let leg2_slot = &self.pools[self.pool_id(mid_token, validator_token)];
            let leg2 = leg2_slot.read()?;
            data.push(((mid_token, validator_token), leg2.reserve_validator_token));
            let has_enough_liquidity = leg2.has_enough_reserve_validator_token(amount_out2);
            actions.record_always(StorageAction::FeeAmmLiquidityCheck(
                leg2_slot.as_slot().slot(),
                leg2.encode_to_slot()?,
                amount_out2,
                has_enough_liquidity,
            ));
            if !has_enough_liquidity {
                return Ok((None, Some(mid_token), data));
            }

            Ok((Some(FeeRoute::TwoHop(mid_token)), Some(mid_token), data))
        })
    }

    /// Executes a fee swap, converting `user_token` to `validator_token` at a fixed rate m = 0.997
    /// Called internally by [`TipFeeManager::collect_fee_post_tx`] during post-tx fee collection.
    ///
    /// # Errors
    /// - `InsufficientLiquidity` — pool validator-token reserve is below the required output
    /// - `UnderOverflow` — reserve arithmetic overflows or amounts exceed `u128`
    pub fn execute_fee_swap(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
    ) -> Result<U256> {
        let actions = self.storage.actions();
        // We suppress the actions recording to instead emit a single `FeeAmmSwap` action
        actions.unrecorded(|| {
            // Calculate output at fixed price m = 0.9970
            let amount_out = compute_amount_out(amount_in)?;

            let pool_id = self.pool_id(user_token, validator_token);
            let mut pool = self.pools[pool_id].read()?;
            let pool_slot = pool.encode_to_slot()?;
            pool.apply_swap(amount_in, amount_out)?;
            self.pools[pool_id].write(pool)?;

            actions.record_always(StorageAction::FeeAmmSwap(
                pool_id.mapping_slot(self.pools.slot()),
                pool_slot,
                amount_in,
            ));

            Ok(amount_out)
        })
    }

    /// Returns the total supply of LP tokens for the given pool.
    pub fn get_total_supply(&self, pool_id: B256) -> Result<U256> {
        self.total_supply[pool_id].read()
    }

    /// Set total supply of LP tokens for a pool
    fn set_total_supply(&mut self, pool_id: B256, total_supply: U256) -> Result<()> {
        self.total_supply[pool_id].write(total_supply)
    }

    /// Returns the LP token balance for `user` in the given pool.
    pub fn get_liquidity_balances(&self, pool_id: B256, user: Address) -> Result<U256> {
        self.liquidity_balances[pool_id][user].read()
    }

    /// Set user's LP token balance
    fn set_liquidity_balances(
        &mut self,
        pool_id: B256,
        user: Address,
        balance: U256,
    ) -> Result<()> {
        self.liquidity_balances[pool_id][user].write(balance)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;
    use tempo_chainspec::hardfork::TempoHardfork;

    use super::*;
    use crate::{
        RECEIVE_POLICY_GUARD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        address_registry::AddressRegistry,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{
            TIP20Setup, TIP403Setup, VIRTUAL_MASTER, register_virtual_master, reject_all_senders,
            with_storage,
        },
        tip_fee_manager::TIPFeeAMMError,
        tip20::TIP20Error,
        tip403_registry::{
            ALLOW_ALL_POLICY_ID, ITIP403Registry, REJECT_ALL_POLICY_ID, TIP403Registry,
        },
    };
    use tempo_primitives::test_utils::actors;

    /// Creates a USD user token and validator token owned by `admin`, applying `mints` to both.
    fn create_token_pair(admin: Address, mints: &[(Address, U256)]) -> Result<(Address, Address)> {
        let create = |name, symbol| {
            mints
                .iter()
                .fold(
                    TIP20Setup::create(name, symbol, admin),
                    |setup, &(to, amount)| setup.with_mint(to, amount),
                )
                .apply()
                .map(|token| token.address())
        };
        Ok((
            create("UserToken", "UTK")?,
            create("ValidatorToken", "VTK")?,
        ))
    }

    /// Writes a pool with `liquidity` of each token and a matching LP total supply.
    fn setup_pool_with_liquidity(
        amm: &mut TipFeeManager,
        user_token: Address,
        validator_token: Address,
        liquidity: U256,
    ) -> Result<B256> {
        let pool_id = amm.pool_id(user_token, validator_token);
        let reserve: u128 = liquidity.try_into().unwrap();
        amm.pools[pool_id].write(Pool {
            reserve_user_token: reserve,
            reserve_validator_token: reserve,
        })?;
        // sqrt(liquidity * liquidity)
        amm.total_supply[pool_id].write(liquidity)?;
        Ok(pool_id)
    }

    #[test]
    fn test_mint_burn_identical_addresses() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?.address();
            let mut amm = TipFeeManager::new();
            assert_eq!(
                amm.mint(admin, token, token, U256::from(1000), admin),
                Err(TIPFeeAMMError::identical_addresses().into())
            );
            assert_eq!(
                amm.burn(admin, token, token, U256::from(1000), admin),
                Err(TIPFeeAMMError::identical_addresses().into())
            );
            Ok(())
        })
    }

    #[test]
    fn test_rebalance_swap_insufficient_funds() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, to] = actors();
        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) = create_token_pair(admin, &[])?;
            let mut amm = TipFeeManager::new();
            let amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
            setup_pool_with_liquidity(&mut amm, user_token, validator_token, amount)?;

            let result =
                amm.rebalance_swap(admin, user_token, validator_token, amount + U256::ONE, to);
            assert_eq!(result, Err(TIPFeeAMMError::invalid_amount().into()));
            Ok(())
        })
    }

    #[test]
    fn test_mint_burn_reject_non_usd_tokens() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let eur = TIP20Setup::create("EuroToken", "EUR", admin)
                .currency("EUR")
                .apply()?
                .address();
            let usd = TIP20Setup::create("USDToken", "USD", admin)
                .apply()?
                .address();
            let mut amm = TipFeeManager::new();

            for (user_token, validator_token) in [(eur, usd), (usd, eur)] {
                assert_eq!(
                    amm.mint(admin, user_token, validator_token, U256::from(1000), admin),
                    Err(TIP20Error::invalid_currency().into())
                );
                assert_eq!(
                    amm.burn(admin, user_token, validator_token, U256::from(1000), admin),
                    Err(TIP20Error::invalid_currency().into())
                );
            }
            Ok(())
        })
    }

    #[test]
    fn test_mint_requires_policy_authorization() -> eyre::Result<()> {
        let [admin, caller, to] = actors();
        let fee_manager = TIP_FEE_MANAGER_ADDRESS;
        // (user token whitelist, validator token whitelist, sender, recipient): each case lacks
        // one authorization: fee manager as user token recipient, sender on the user token,
        // `to` on the user token, `to` on the validator token.
        for (user_members, validator_members, sender, recipient) in [
            (vec![admin], None, admin, admin),
            (vec![admin, fee_manager], None, caller, admin),
            (vec![admin, fee_manager], None, admin, to),
            (
                vec![admin, fee_manager, to],
                Some([admin, fee_manager]),
                admin,
                to,
            ),
        ] {
            with_storage(TempoHardfork::T8, || {
                let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                    .with_transfer_policy(TIP403Setup::whitelist(admin).with_members(user_members))
                    .apply()?
                    .address();
                let mut validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                    .with_mint(sender, U256::from(10000));
                if let Some(members) = validator_members {
                    validator_token = validator_token
                        .with_transfer_policy(TIP403Setup::whitelist(admin).with_members(members));
                }
                let validator_token = validator_token.apply()?.address();

                let result = TipFeeManager::new().mint(
                    sender,
                    user_token,
                    validator_token,
                    U256::from(10000),
                    recipient,
                );
                assert_eq!(result, Err(TIP20Error::policy_forbids().into()));
                Ok::<_, eyre::Report>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_burn_requires_lp_sender_authorization() -> eyre::Result<()> {
        let [admin, lp, to] = actors();
        let with_lp = [lp, TIP_FEE_MANAGER_ADDRESS, to];
        let without_lp = [TIP_FEE_MANAGER_ADDRESS, to];
        // (user token whitelist, validator token whitelist)
        for (user_members, validator_members) in [
            (&without_lp[..], &with_lp[..]),
            (&with_lp[..], &without_lp[..]),
        ] {
            with_storage(TempoHardfork::T8, || {
                let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                    .with_transfer_policy(
                        TIP403Setup::whitelist(admin).with_members(user_members.iter().copied()),
                    )
                    .apply()?
                    .address();
                let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                    .with_transfer_policy(
                        TIP403Setup::whitelist(admin)
                            .with_members(validator_members.iter().copied()),
                    )
                    .apply()?
                    .address();

                let mut amm = TipFeeManager::new();
                let pool_id = setup_pool_with_liquidity(
                    &mut amm,
                    user_token,
                    validator_token,
                    U256::from(10000),
                )?;
                amm.set_liquidity_balances(pool_id, lp, U256::from(10000))?;

                let result = amm.burn(lp, user_token, validator_token, U256::from(1000), to);
                assert_eq!(result, Err(TIP20Error::policy_forbids().into()));
                Ok::<_, eyre::Report>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_mint_insufficient_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) = create_token_pair(admin, &[])?;

            // MIN_LIQUIDITY = 1000, amount/2 must be > 1000, so 2000 should fail
            let result = TipFeeManager::new().mint(
                admin,
                user_token,
                validator_token,
                uint!(2000_U256),
                admin,
            );
            assert_eq!(result, Err(TIPFeeAMMError::insufficient_liquidity().into()));
            Ok(())
        })
    }

    #[test]
    fn test_add_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let (token1, token2) = create_token_pair(admin, &[(admin, uint!(10000000_U256))])?;

            let amount = uint!(10000_U256);
            let result = TipFeeManager::new().mint(admin, token1, token2, amount, admin)?;
            assert_eq!(result, amount / uint!(2_U256) - MIN_LIQUIDITY);

            Ok(())
        })
    }

    #[test]
    fn test_calculate_burn_amounts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();

            let pool = Pool {
                reserve_user_token: 1000,
                reserve_validator_token: 1000,
            };
            amm.set_total_supply(B256::ZERO, uint!(1000000000000000_U256))?;

            let (amount_user, amount_validator) =
                amm.calculate_burn_amounts(&pool, B256::ZERO, uint!(1_U256))?;
            assert_eq!(amount_user, U256::ZERO);
            assert_eq!(amount_validator, U256::ZERO);

            Ok(())
        })
    }

    /// Test execute_fee_swap executes swap immediately, updates reserves and rounds consistently
    #[test]
    fn test_execute_fee_swap() -> eyre::Result<()> {
        let admin = Address::random();
        let unit = uint!(10_U256).pow(U256::from(6));
        // (pool liquidity, amount in)
        for (liquidity, amount_in) in [
            (uint!(1000_U256), uint!(100_U256)),
            (uint!(100000_U256) * unit, uint!(10000_U256) * unit),
        ] {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let (user_token, validator_token) = create_token_pair(admin, &[])?;
                let mut amm = TipFeeManager::new();
                let pool_id =
                    setup_pool_with_liquidity(&mut amm, user_token, validator_token, liquidity)?;

                // e.g. 100 * 9970 / 10000 = 99
                let expected_out = (amount_in * M) / SCALE;
                let amount_out = amm.execute_fee_swap(user_token, validator_token, amount_in)?;
                assert_eq!(amount_out, expected_out);

                let pool = amm.pools[pool_id].read()?;
                assert_eq!(U256::from(pool.reserve_user_token), liquidity + amount_in);
                assert_eq!(
                    U256::from(pool.reserve_validator_token),
                    liquidity - expected_out
                );
                Ok::<_, eyre::Report>(())
            })?;
        }
        Ok(())
    }

    /// Test execute_fee_swap fails with insufficient liquidity
    #[test]
    fn test_execute_fee_swap_insufficient_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) = create_token_pair(admin, &[])?;
            let mut amm = TipFeeManager::new();
            setup_pool_with_liquidity(&mut amm, user_token, validator_token, uint!(100_U256))?;

            // Try to swap 200 tokens (would need ~199 output, but only 100 available)
            let result = amm.execute_fee_swap(user_token, validator_token, uint!(200_U256));
            assert_eq!(result, Err(TIPFeeAMMError::insufficient_liquidity().into()));

            Ok(())
        })
    }

    /// Test multiple consecutive fee swaps update reserves correctly
    #[test]
    fn test_multiple_consecutive_fee_swaps() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) = create_token_pair(admin, &[])?;
            let mut amm = TipFeeManager::new();
            let unit = uint!(10_U256).pow(U256::from(6));
            let initial = uint!(100000_U256) * unit;
            let pool_id =
                setup_pool_with_liquidity(&mut amm, user_token, validator_token, initial)?;

            let (mut total_in, mut total_out) = (U256::ZERO, U256::ZERO);
            for swap in [uint!(1000_U256), uint!(2000_U256), uint!(3000_U256)] {
                let amount_in = swap * unit;
                let out = amm.execute_fee_swap(user_token, validator_token, amount_in)?;
                // Each swap output should be amount_in * M / SCALE
                assert_eq!(out, (amount_in * M) / SCALE);
                total_in += amount_in;
                total_out += out;
            }

            let pool = amm.pools[pool_id].read()?;
            assert_eq!(U256::from(pool.reserve_user_token), initial + total_in);
            assert_eq!(
                U256::from(pool.reserve_validator_token),
                initial - total_out
            );

            Ok(())
        })
    }

    /// Test pool boundary condition
    #[test]
    fn test_pool_liquidity_boundary() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) = create_token_pair(admin, &[])?;
            let mut amm = TipFeeManager::new();
            let unit = uint!(10_U256).pow(U256::from(6));
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                uint!(100_U256) * unit,
            )?;

            let reserve = U256::from(amm.pools[pool_id].read()?.reserve_validator_token);

            // Exactly at boundary should succeed (100 * 0.997 = 99.7, which is < 100)
            assert!(reserve >= compute_amount_out(uint!(100_U256) * unit)?);

            // Just over boundary should fail (101 * 0.997 = 100.697, which is > 100)
            assert!(reserve < compute_amount_out(uint!(101_U256) * unit)?);

            Ok(())
        })
    }

    /// Test zero amounts are rejected by burn, mint and rebalance swap
    #[test]
    fn test_zero_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, to] = actors();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) = create_token_pair(admin, &[])?;
            let mut amm = TipFeeManager::new();

            for result in [
                amm.burn(admin, user_token, validator_token, U256::ZERO, admin)
                    .map(|_| ()),
                amm.mint(admin, user_token, validator_token, U256::ZERO, admin)
                    .map(|_| ()),
                amm.rebalance_swap(admin, user_token, validator_token, U256::ZERO, to)
                    .map(|_| ()),
            ] {
                assert_eq!(result, Err(TIPFeeAMMError::invalid_amount().into()));
            }

            Ok(())
        })
    }

    #[test]
    fn test_rebalance_swap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, recipient] = actors();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(10000000_U256);
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, mint_amount), (amm.address, mint_amount)])?;

            let liquidity = uint!(100000_U256);
            let pool_id =
                setup_pool_with_liquidity(&mut amm, user_token, validator_token, liquidity)?;

            let amount_out = uint!(1000_U256);
            let amount_in =
                amm.rebalance_swap(admin, user_token, validator_token, amount_out, recipient)?;
            assert_eq!(amount_in, (amount_out * N) / SCALE + U256::ONE);

            let pool = amm.pools[pool_id].read()?;
            assert_eq!(U256::from(pool.reserve_user_token), liquidity - amount_out);
            assert_eq!(
                U256::from(pool.reserve_validator_token),
                liquidity + amount_in
            );

            Ok(())
        })
    }

    #[test]
    fn test_mint_subsequent_deposit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, second_user] = actors();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, mint_amount), (second_user, mint_amount)])?;

            let mut amm = TipFeeManager::new();

            let initial_amount = uint!(100000_U256);
            let first_liquidity =
                amm.mint(admin, user_token, validator_token, initial_amount, admin)?;
            assert_eq!(
                first_liquidity,
                initial_amount / uint!(2_U256) - MIN_LIQUIDITY
            );

            let pool_id = amm.pool_id(user_token, validator_token);
            let total_supply_after_first = amm.get_total_supply(pool_id)?;
            assert_eq!(total_supply_after_first, first_liquidity + MIN_LIQUIDITY);

            let reserve_val = U256::from(amm.pools[pool_id].read()?.reserve_validator_token);

            let second_amount = uint!(50000_U256);
            let second_liquidity = amm.mint(
                second_user,
                user_token,
                validator_token,
                second_amount,
                second_user,
            )?;
            assert_eq!(
                second_liquidity,
                second_amount * total_supply_after_first / reserve_val
            );

            assert_eq!(
                amm.get_total_supply(pool_id)?,
                total_supply_after_first + second_liquidity
            );
            assert_eq!(amm.get_liquidity_balances(pool_id, admin)?, first_liquidity);
            assert_eq!(
                amm.get_liquidity_balances(pool_id, second_user)?,
                second_liquidity
            );

            Ok(())
        })
    }

    #[test]
    fn test_burn() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, recipient] = actors();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, uint!(100000000_U256))])?;

            let mut amm = TipFeeManager::new();

            let deposit_amount = uint!(100000_U256);
            let liquidity = amm.mint(admin, user_token, validator_token, deposit_amount, admin)?;
            assert_eq!(liquidity, deposit_amount / uint!(2_U256) - MIN_LIQUIDITY);

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool_before = amm.pools[pool_id].read()?;
            let total_supply_before = amm.get_total_supply(pool_id)?;

            let burn_amount = liquidity / uint!(2_U256);
            let (amount_user, amount_validator) =
                amm.burn(admin, user_token, validator_token, burn_amount, recipient)?;

            assert_eq!(
                amount_user,
                burn_amount * U256::from(pool_before.reserve_user_token) / total_supply_before
            );
            assert_eq!(
                amount_validator,
                burn_amount * U256::from(pool_before.reserve_validator_token) / total_supply_before
            );

            assert_eq!(
                amm.get_total_supply(pool_id)?,
                total_supply_before - burn_amount
            );
            assert_eq!(
                amm.get_liquidity_balances(pool_id, admin)?,
                liquidity - burn_amount
            );

            let pool_after = amm.pools[pool_id].read()?;
            assert_eq!(
                U256::from(pool_after.reserve_user_token),
                U256::from(pool_before.reserve_user_token) - amount_user
            );
            assert_eq!(
                U256::from(pool_after.reserve_validator_token),
                U256::from(pool_before.reserve_validator_token) - amount_validator
            );

            Ok(())
        })
    }

    #[test]
    fn test_burn_insufficient_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, other_user] = actors();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, uint!(100000000_U256))])?;

            let mut amm = TipFeeManager::new();
            let liquidity = amm.mint(
                admin,
                user_token,
                validator_token,
                uint!(100000_U256),
                admin,
            )?;

            let result = amm.burn(
                other_user,
                user_token,
                validator_token,
                liquidity,
                other_user,
            );
            assert_eq!(result, Err(TIPFeeAMMError::insufficient_liquidity().into()));

            Ok(())
        })
    }

    #[test]
    fn test_t1c_reserve_pool_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, uint!(10000000_U256))])?;

            let mut amm = TipFeeManager::new();
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                uint!(100000_U256),
            )?;

            let amount_out: u128 = compute_amount_out(uint!(10000_U256))?.try_into().unwrap();
            amm.reserve_pool_liquidity(pool_id, amount_out)?;

            assert_eq!(
                amm.pending_fee_swap_reservation[pool_id].t_read()?,
                amount_out
            );

            Ok(())
        })
    }

    #[test]
    fn test_t1c_burn_respects_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let [admin, recipient] = actors();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, uint!(100000000_U256))])?;

            let mut amm = TipFeeManager::new();
            let liquidity = amm.mint(
                admin,
                user_token,
                validator_token,
                uint!(100000_U256),
                admin,
            )?;

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool = amm.pools[pool_id].read()?;

            // Reserve most of the validator token liquidity
            let reserve_amount = U256::from(pool.reserve_validator_token) - uint!(100_U256);
            let amount_out: u128 = compute_amount_out(reserve_amount)?.try_into().unwrap();
            amm.reserve_pool_liquidity(pool_id, amount_out)?;

            let result = amm.burn(admin, user_token, validator_token, liquidity, recipient);
            assert_eq!(result, Err(TIPFeeAMMError::insufficient_liquidity().into()));

            Ok(())
        })
    }

    #[test]
    fn test_t1c_partial_burn_with_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let [admin, recipient] = actors();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, uint!(100000000_U256))])?;

            let mut amm = TipFeeManager::new();
            let liquidity = amm.mint(
                admin,
                user_token,
                validator_token,
                uint!(100000_U256),
                admin,
            )?;

            let pool_id = amm.pool_id(user_token, validator_token);
            let amount_out: u128 = compute_amount_out(uint!(1000_U256))?.try_into().unwrap();
            amm.reserve_pool_liquidity(pool_id, amount_out)?;

            let small_burn = liquidity / uint!(10_U256);
            assert!(
                amm.burn(admin, user_token, validator_token, small_burn, recipient)
                    .is_ok()
            );

            Ok(())
        })
    }

    #[test]
    fn test_t1c_rebalance_swap_respects_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let [admin, to] = actors();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, mint_amount), (amm.address, mint_amount)])?;

            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                uint!(100000_U256),
            )?;

            let amount_out: u128 = compute_amount_out(uint!(50000_U256))?.try_into().unwrap();
            amm.reserve_pool_liquidity(pool_id, amount_out)?;

            amm.rebalance_swap(admin, user_token, validator_token, uint!(5000_U256), to)?;
            let pool = amm.pools[pool_id].read()?;
            let reserved = amm.pending_fee_swap_reservation[pool_id].t_read()?;
            assert!(pool.reserve_validator_token >= reserved);

            Ok(())
        })
    }

    #[test]
    fn test_pre_t1c_rebalance_swap_skips_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1B);
        let [admin, to] = actors();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, mint_amount), (amm.address, mint_amount)])?;

            setup_pool_with_liquidity(&mut amm, user_token, validator_token, uint!(100000_U256))?;
            assert!(
                amm.rebalance_swap(admin, user_token, validator_token, uint!(5000_U256), to)
                    .is_ok()
            );

            Ok(())
        })
    }

    #[test]
    fn test_pre_t1c_no_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1B);
        let [admin, recipient] = actors();

        StorageCtx::enter(&mut storage, || {
            let (user_token, validator_token) =
                create_token_pair(admin, &[(admin, uint!(100000000_U256))])?;

            let mut amm = TipFeeManager::new();
            let liquidity = amm.mint(
                admin,
                user_token,
                validator_token,
                uint!(100000_U256),
                admin,
            )?;

            assert!(
                amm.burn(admin, user_token, validator_token, liquidity, recipient)
                    .is_ok()
            );

            Ok(())
        })
    }

    /// Creates both tokens and mints `admin` liquidity into their pool. Returns
    /// `(user_token, validator_token, liquidity)`.
    fn setup_minted_pool(
        amm: &mut TipFeeManager,
        admin: Address,
    ) -> Result<(Address, Address, U256)> {
        let mint_amount = uint!(100000000_U256);
        let user_token = TIP20Setup::create("UserToken", "UTK", admin)
            .with_issuer(admin)
            .with_mint(admin, mint_amount)
            .apply()?
            .address();
        let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
            .with_issuer(admin)
            .with_mint(admin, mint_amount)
            .apply()?
            .address();
        let liquidity = amm.mint(
            admin,
            user_token,
            validator_token,
            uint!(100000_U256),
            admin,
        )?;
        Ok((user_token, validator_token, liquidity))
    }

    /// Creates both tokens and a pool funded for a rebalance swap. Returns
    /// `(user_token, validator_token)`.
    fn setup_rebalance_pool(amm: &mut TipFeeManager, admin: Address) -> Result<(Address, Address)> {
        let mint_amount = uint!(10000000_U256);
        let user_token = TIP20Setup::create("UserToken", "UTK", admin)
            .with_issuer(admin)
            .with_mint(amm.address, mint_amount)
            .apply()?
            .address();
        let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
            .with_issuer(admin)
            .with_mint(admin, mint_amount)
            .apply()?
            .address();
        let liquidity = uint!(100000_U256);
        setup_pool_with_liquidity(amm, user_token, validator_token, liquidity)?;
        Ok((user_token, validator_token))
    }

    fn balance(token: Address, account: Address) -> Result<U256> {
        TIP20Token::from_address(token)?.balance_of(ITIP20::balanceOfCall { account })
    }

    #[test]
    fn test_burn_to_receive_blocked_recipient_reverts_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token, liquidity) = setup_minted_pool(&mut amm, admin)?;
            reject_all_senders(recipient, Address::ZERO)?;

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool_before = amm.pools[pool_id].read()?;
            let result = amm.burn(
                admin,
                user_token,
                validator_token,
                liquidity / uint!(2_U256),
                recipient,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(_)))
            ));

            assert_eq!(amm.get_liquidity_balances(pool_id, admin)?, liquidity);
            let pool_after = amm.pools[pool_id].read()?;
            assert_eq!(
                pool_after.reserve_user_token,
                pool_before.reserve_user_token
            );
            assert_eq!(
                pool_after.reserve_validator_token,
                pool_before.reserve_validator_token
            );
            for token in [user_token, validator_token] {
                assert_eq!(balance(token, RECEIVE_POLICY_GUARD_ADDRESS)?, U256::ZERO);
            }

            Ok(())
        })
    }

    #[test]
    fn test_burn_to_receive_blocked_virtual_recipient_reverts_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let (_, virtual_addr) = register_virtual_master(&mut AddressRegistry::new())?;
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token, liquidity) = setup_minted_pool(&mut amm, admin)?;
            reject_all_senders(VIRTUAL_MASTER, Address::ZERO)?;

            let result = amm.burn(
                admin,
                user_token,
                validator_token,
                liquidity / uint!(2_U256),
                virtual_addr,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(_)))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_burn_to_receive_blocked_recipient_diverts_pre_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token, liquidity) = setup_minted_pool(&mut amm, admin)?;
            reject_all_senders(recipient, Address::ZERO)?;

            let (amount_user, amount_validator) = amm.burn(
                admin,
                user_token,
                validator_token,
                liquidity / uint!(2_U256),
                recipient,
            )?;

            assert_eq!(balance(user_token, recipient)?, U256::ZERO);
            assert_eq!(balance(validator_token, recipient)?, U256::ZERO);
            assert_eq!(
                balance(user_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                amount_user
            );
            assert_eq!(
                balance(validator_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                amount_validator
            );

            Ok(())
        })
    }

    #[test]
    fn test_rebalance_swap_to_receive_blocked_recipient_reverts_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token) = setup_rebalance_pool(&mut amm, admin)?;
            reject_all_senders(recipient, Address::ZERO)?;

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool_before = amm.pools[pool_id].read()?;
            let result = amm.rebalance_swap(
                admin,
                user_token,
                validator_token,
                uint!(1000_U256),
                recipient,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(_)))
            ));

            let pool_after = amm.pools[pool_id].read()?;
            assert_eq!(
                pool_after.reserve_user_token,
                pool_before.reserve_user_token
            );
            assert_eq!(
                pool_after.reserve_validator_token,
                pool_before.reserve_validator_token
            );
            assert_eq!(
                balance(user_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                U256::ZERO
            );

            Ok(())
        })
    }

    #[test]
    fn test_rebalance_swap_to_receive_blocked_recipient_diverts_pre_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token) = setup_rebalance_pool(&mut amm, admin)?;
            reject_all_senders(recipient, Address::ZERO)?;

            let amount_out = uint!(1000_U256);
            amm.rebalance_swap(admin, user_token, validator_token, amount_out, recipient)?;

            assert_eq!(balance(user_token, recipient)?, U256::ZERO);
            assert_eq!(
                balance(user_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                amount_out
            );

            Ok(())
        })
    }

    #[test]
    fn test_burn_to_self_recoverable_recipient_diverts_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token, liquidity) = setup_minted_pool(&mut amm, admin)?;
            reject_all_senders(recipient, recipient)?;

            let burned = liquidity / uint!(2_U256);
            let (amount_user, amount_validator) =
                amm.burn(admin, user_token, validator_token, burned, recipient)?;

            let pool_id = amm.pool_id(user_token, validator_token);
            assert_eq!(
                amm.get_liquidity_balances(pool_id, admin)?,
                liquidity - burned
            );
            assert_eq!(balance(user_token, recipient)?, U256::ZERO);
            assert_eq!(balance(validator_token, recipient)?, U256::ZERO);
            assert_eq!(
                balance(user_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                amount_user
            );
            assert_eq!(
                balance(validator_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                amount_validator
            );

            Ok(())
        })
    }

    #[test]
    fn test_burn_to_third_party_recoverable_recipient_diverts_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token, liquidity) = setup_minted_pool(&mut amm, admin)?;
            reject_all_senders(recipient, Address::random())?;

            let (amount_user, amount_validator) = amm.burn(
                admin,
                user_token,
                validator_token,
                liquidity / uint!(2_U256),
                recipient,
            )?;

            assert_eq!(
                balance(user_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                amount_user
            );
            assert_eq!(
                balance(validator_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                amount_validator
            );

            Ok(())
        })
    }

    #[test]
    fn test_burn_to_token_filtered_recipient_reverts_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token, liquidity) = setup_minted_pool(&mut amm, admin)?;
            TIP403Registry::new().set_receive_policy(
                recipient,
                ITIP403Registry::setReceivePolicyCall {
                    senderPolicyId: ALLOW_ALL_POLICY_ID,
                    tokenFilterId: REJECT_ALL_POLICY_ID,
                    recoveryAuthority: Address::ZERO,
                },
            )?;

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool_before = amm.pools[pool_id].read()?;
            let result = amm.burn(
                admin,
                user_token,
                validator_token,
                liquidity / uint!(2_U256),
                recipient,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(_)))
            ));

            assert_eq!(amm.get_liquidity_balances(pool_id, admin)?, liquidity);
            let pool_after = amm.pools[pool_id].read()?;
            assert_eq!(
                pool_after.reserve_user_token,
                pool_before.reserve_user_token
            );
            assert_eq!(
                pool_after.reserve_validator_token,
                pool_before.reserve_validator_token
            );

            Ok(())
        })
    }

    #[test]
    fn test_rebalance_swap_to_self_recoverable_recipient_diverts_t15() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();
            let (user_token, validator_token) = setup_rebalance_pool(&mut amm, admin)?;
            reject_all_senders(recipient, recipient)?;

            let amount_out = uint!(1000_U256);
            amm.rebalance_swap(admin, user_token, validator_token, amount_out, recipient)?;

            assert_eq!(balance(user_token, recipient)?, U256::ZERO);
            assert_eq!(
                balance(user_token, RECEIVE_POLICY_GUARD_ADDRESS)?,
                amount_out
            );

            Ok(())
        })
    }
}
