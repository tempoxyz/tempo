//! TIP-1120 funding arithmetic and native input permissions. Funding admission remains disabled.

pub mod permission;

use alloy_primitives::{U256, U512, uint};

pub use tempo_contracts::precompiles::{IFundingSource, ITIP20Funder};

/// Scale of an input rate in output base units per input base unit.
pub const RATE_SCALE: U256 = uint!(1_000_000_000_000_000_000_U256);
const BPS_SCALE: u16 = 10_000;

/// Invalid funding arithmetic inputs or an unrepresentable result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FundingMathError {
    #[error("funding rate and reference amounts must be positive")]
    InvalidRate,
    #[error("funding slippage exceeds 10000 basis points")]
    InvalidSlippage,
    #[error("funding arithmetic overflow")]
    Overflow,
}

/// A positive reference rate, independent of execution quotes and losses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputRate(U256);

impl InputRate {
    /// Validates a source's fixed-point rate. No-input plans do not have a rate.
    pub fn new(rate: U256) -> Result<Self, FundingMathError> {
        if rate.is_zero() {
            return Err(FundingMathError::InvalidRate);
        }
        Ok(Self(rate))
    }

    /// Converts approved reference amounts in base units to a rate, rounding up.
    pub fn from_reference(amount_out: U256, amount_in: U256) -> Result<Self, FundingMathError> {
        if amount_out.is_zero() || amount_in.is_zero() {
            return Err(FundingMathError::InvalidRate);
        }
        Ok(Self(mul_div_up(amount_out, RATE_SCALE, amount_in)?))
    }

    /// Normalizes an already-approved 1:1 pair. Decimals alone do not establish parity.
    pub fn parity(decimals_in: u8, decimals_out: u8) -> Result<Self, FundingMathError> {
        let exponent = 18 + i16::from(decimals_out) - i16::from(decimals_in);
        if exponent < 0 {
            return Ok(Self(U256::ONE));
        }
        U256::from(10)
            .checked_pow(U256::from(exponent as u16))
            .map(Self)
            .ok_or(FundingMathError::Overflow)
    }

    /// Returns the rate encoded in a funding plan.
    pub const fn get(self) -> U256 {
        self.0
    }

    /// Floors the maximum input allowed by the budget, saturating only this result.
    pub fn input_capacity(self, remaining_cost: U256) -> U256 {
        let capacity = U512::from(remaining_cost) * U512::from(RATE_SCALE) / U512::from(self.0);
        U256::saturating_from(capacity)
    }

    /// Rounds cumulative gross input cost up. Meter deltas between cumulative costs.
    pub fn input_cost(self, cumulative_amount_in: U256) -> Result<U256, FundingMathError> {
        mul_div_up(cumulative_amount_in, self.0, RATE_SCALE)
    }
}

/// Floors the aggregate input budget for the initial output shortfall.
pub fn cost_budget(shortfall: U256, slippage_bps: u16) -> Result<U256, FundingMathError> {
    if slippage_bps > BPS_SCALE {
        return Err(FundingMathError::InvalidSlippage);
    }
    let budget =
        U512::from(shortfall) * U512::from(BPS_SCALE + slippage_bps) / U512::from(BPS_SCALE);
    U256::checked_from_limbs_slice(budget.as_limbs()).ok_or(FundingMathError::Overflow)
}

fn mul_div_up(a: U256, b: U256, divisor: U256) -> Result<U256, FundingMathError> {
    let (quotient, remainder) = (U512::from(a) * U512::from(b)).div_rem(U512::from(divisor));
    let rounded = quotient + U512::from(!remainder.is_zero());
    U256::checked_from_limbs_slice(rounded.as_limbs()).ok_or(FundingMathError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn normalizes_parity_decimals_conservatively() {
        for (input, output, expected) in [
            (6, 6, RATE_SCALE),
            (18, 6, uint!(1_000_000_U256)),
            (6, 18, uint!(1_000_000_000_000_000_000_000_000_000_000_U256)),
            (255, 255, RATE_SCALE),
            (19, 0, U256::ONE),
            (255, 0, U256::ONE),
        ] {
            assert_eq!(InputRate::parity(input, output).unwrap().get(), expected);
        }
        assert_eq!(
            InputRate::parity(0, 59).unwrap().get(),
            U256::from(10).pow(U256::from(77))
        );
        assert_eq!(InputRate::parity(0, 60), Err(FundingMathError::Overflow));
        assert_eq!(InputRate::parity(0, 255), Err(FundingMathError::Overflow));
    }

    #[test]
    fn reference_rates_round_up_without_intermediate_overflow() {
        assert_eq!(
            InputRate::from_reference(U256::MAX, U256::MAX)
                .unwrap()
                .get(),
            RATE_SCALE
        );
        assert_eq!(
            InputRate::from_reference(U256::ONE, U256::from(3))
                .unwrap()
                .get(),
            uint!(333_333_333_333_333_334_U256)
        );
        assert_eq!(
            InputRate::from_reference(U256::ONE, U256::MAX)
                .unwrap()
                .get(),
            U256::ONE
        );
        assert_eq!(
            InputRate::from_reference(U256::MAX, U256::ONE),
            Err(FundingMathError::Overflow)
        );
        assert_eq!(
            InputRate::from_reference(U256::ZERO, U256::ONE),
            Err(FundingMathError::InvalidRate)
        );
        assert_eq!(
            InputRate::from_reference(U256::ONE, U256::ZERO),
            Err(FundingMathError::InvalidRate)
        );
        assert_eq!(
            InputRate::new(U256::ZERO),
            Err(FundingMathError::InvalidRate)
        );
    }

    #[test]
    fn budgets_floor_and_reject_invalid_or_overflowing_results() {
        assert_eq!(
            cost_budget(U256::from(50_000_000), 100).unwrap(),
            U256::from(50_500_000)
        );
        assert_eq!(cost_budget(U256::ONE, 100).unwrap(), U256::ONE);
        assert_eq!(cost_budget(U256::ONE, 10_000).unwrap(), U256::from(2));
        assert_eq!(cost_budget(U256::ZERO, 10_000).unwrap(), U256::ZERO);
        assert_eq!(cost_budget(U256::MAX, 0).unwrap(), U256::MAX);
        assert_eq!(cost_budget(U256::MAX, 1), Err(FundingMathError::Overflow));
        assert_eq!(
            cost_budget(U256::ZERO, 10_001),
            Err(FundingMathError::InvalidSlippage)
        );
        assert_eq!(
            cost_budget(U256::ONE, u16::MAX),
            Err(FundingMathError::InvalidSlippage)
        );
    }

    #[test]
    fn meters_shares_and_rounds_cumulative_cost() {
        let shares = InputRate::from_reference(U256::from(2), U256::ONE).unwrap();
        assert_eq!(shares.input_capacity(U256::from(10)), U256::from(5));
        assert_eq!(shares.input_cost(U256::from(4)).unwrap(), U256::from(8));
        let rate = InputRate::from_reference(U256::ONE, U256::from(2)).unwrap();
        assert_eq!(rate.input_capacity(U256::ONE), U256::from(2));
        assert_eq!(rate.input_cost(U256::ONE).unwrap(), U256::ONE);
        assert_eq!(rate.input_cost(U256::from(2)).unwrap(), U256::ONE);
        assert_eq!(rate.input_cost(U256::from(3)).unwrap(), U256::from(2));
    }

    #[test]
    fn only_input_capacity_saturates() {
        let parity = InputRate::new(RATE_SCALE).unwrap();
        assert_eq!(parity.input_capacity(U256::MAX), U256::MAX);
        assert_eq!(parity.input_cost(U256::MAX).unwrap(), U256::MAX);
        let smallest = InputRate::new(U256::ONE).unwrap();
        assert_eq!(smallest.input_capacity(U256::MAX), U256::MAX);
        let largest = InputRate::new(U256::MAX).unwrap();
        assert_eq!(largest.input_capacity(U256::MAX), RATE_SCALE);
        assert_eq!(largest.input_cost(RATE_SCALE).unwrap(), U256::MAX);
        assert_eq!(
            largest.input_cost(RATE_SCALE + U256::ONE),
            Err(FundingMathError::Overflow)
        );
        assert_eq!(largest.input_cost(U256::ZERO).unwrap(), U256::ZERO);
        assert_eq!(largest.input_capacity(U256::ZERO), U256::ZERO);
    }

    #[test]
    fn rejects_overflow_from_rounding_up() {
        let amount = uint!(
            115792089237316195307778895771371712545491088894268851493966495113644278145969_U256
        );
        let rate = InputRate::new(RATE_SCALE + U256::ONE).unwrap();
        assert_eq!(rate.input_cost(amount - U256::ONE).unwrap(), U256::MAX);
        assert_eq!(rate.input_cost(amount), Err(FundingMathError::Overflow));

        let reference = uint!(
            115792089237316195307778895771371712429698999656952656186187599342272565600478_U256
        );
        assert_eq!(
            InputRate::from_reference(reference - U256::ONE, RATE_SCALE - U256::ONE)
                .unwrap()
                .get(),
            U256::MAX
        );
        assert_eq!(
            InputRate::from_reference(reference, RATE_SCALE - U256::ONE),
            Err(FundingMathError::Overflow)
        );
    }

    fn arb_u256() -> impl Strategy<Value = U256> {
        prop_oneof![
            Just(U256::ZERO),
            Just(U256::ONE),
            Just(U256::MAX),
            Just(RATE_SCALE),
            any::<u64>().prop_map(U256::from),
            any::<u128>().prop_map(U256::from),
            any::<[u64; 4]>().prop_map(U256::from_limbs),
        ]
    }

    proptest! {
        #[test]
        fn reference_rate_rounding_is_conservative(raw_out in arb_u256(), raw_in in arb_u256()) {
            let amount_out = raw_out.max(U256::ONE);
            let amount_in = raw_in.max(U256::ONE);
            let scaled_output = U512::from(amount_out) * U512::from(RATE_SCALE);
            match InputRate::from_reference(amount_out, amount_in) {
                Ok(rate) => {
                    prop_assert!(U512::from(rate.get()) * U512::from(amount_in) >= scaled_output);
                    prop_assert!(U512::from(rate.get() - U256::ONE) * U512::from(amount_in) < scaled_output);
                }
                Err(error) => {
                    prop_assert_eq!(error, FundingMathError::Overflow);
                    prop_assert!(scaled_output > U512::from(U256::MAX) * U512::from(amount_in));
                }
            }
        }

        #[test]
        fn capacity_is_maximal_within_budget(budget in arb_u256(), raw_rate in arb_u256()) {
            let rate = InputRate::new(raw_rate.max(U256::ONE)).unwrap();
            let cap = rate.input_capacity(budget);
            let scaled_budget = U512::from(budget) * U512::from(RATE_SCALE);
            prop_assert!(U512::from(cap) * U512::from(rate.get()) <= scaled_budget);
            if cap < U256::MAX {
                prop_assert!(U512::from(cap + U256::ONE) * U512::from(rate.get()) > scaled_budget);
            }
            prop_assert!(rate.input_cost(cap).unwrap() <= budget);
        }

        #[test]
        fn cost_rounding_is_conservative(amount in arb_u256(), raw_rate in arb_u256()) {
            let rate = InputRate::new(raw_rate.max(U256::ONE)).unwrap();
            let product = U512::from(amount) * U512::from(rate.get());
            let scale = U512::from(RATE_SCALE);
            match rate.input_cost(amount) {
                Ok(cost) => {
                    prop_assert!(U512::from(cost) * scale >= product);
                    if cost > U256::ZERO {
                        prop_assert!(U512::from(cost - U256::ONE) * scale < product);
                    }
                }
                Err(error) => {
                    prop_assert_eq!(error, FundingMathError::Overflow);
                    prop_assert!(product > U512::from(U256::MAX) * scale);
                }
            }
        }

        #[test]
        fn budget_is_rounded_down(shortfall in arb_u256(), slippage in 0u16..=10_000) {
            let product = U512::from(shortfall) * U512::from(10_000u16 + slippage);
            match cost_budget(shortfall, slippage) {
                Ok(budget) => {
                    prop_assert!(U512::from(budget) * U512::from(10_000) <= product);
                    prop_assert!((U512::from(budget) + U512::ONE) * U512::from(10_000) > product);
                }
                Err(error) => {
                    prop_assert_eq!(error, FundingMathError::Overflow);
                    prop_assert!(product >= (U512::from(U256::MAX) + U512::ONE) * U512::from(10_000));
                }
            }
        }
    }
}
