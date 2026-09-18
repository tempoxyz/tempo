//! TIP-1102 precompile repricing, active from T13.

use alloy_evm::precompiles::{DynPrecompile, PrecompilesMap};
use alloy_primitives::{Address, U256};
use revm::precompile::{
    self, EthPrecompileResult, PrecompileFn, PrecompileHalt, PrecompileId, PrecompileOutput,
    PrecompileResult,
};

const ECRECOVER_BASE: u64 = 25_000;
const SHA256_BASE: u64 = 104;
const SHA256_PER_WORD: u64 = 13;
const IDENTITY_BASE: u64 = 50;
const IDENTITY_PER_WORD: u64 = 1;
const BN254_ADD: u64 = 750;
const BN254_MUL: u64 = 30_000;
const BN254_PAIR_BASE: u64 = 285_000;
const BN254_PAIR_PER_POINT: u64 = 243_000;
const BLAKE2_F_ROUND: u64 = 10;
const BLS12_G1_ADD: u64 = 2_300;
const BLS12_G1_MSM_BASE: u64 = 78_000;
const BLS12_G2_ADD: u64 = 3_500;
const BLS12_G2_MSM_BASE: u64 = 143_000;
const BLS12_PAIRING_OFFSET: u64 = 230_000;
const BLS12_PAIRING_MULTIPLIER: u64 = 167_000;
const BLS12_MAP_FP_TO_G1: u64 = 26_000;
const BLS12_MAP_FP2_TO_G2: u64 = 95_000;
const P256_VERIFY_BASE: u64 = 27_000;
const MODEXP_MIN_GAS: u64 = 500;
const MODEXP_SMALL_MULTIPLICATION_COMPLEXITY: u64 = 81;
const MODEXP_LARGE_BASE_MODULUS_MULTIPLIER: u64 = 2;
const MODEXP_EXPONENT_BYTE_MULTIPLIER: u64 = 20;

/// Applies the T13 precompile schedule and removes the KZG point-evaluation precompile.
pub(crate) fn apply(precompiles: &mut PrecompilesMap) {
    use precompile::bls12_381_const::{
        G1_ADD_ADDRESS, G1_MSM_ADDRESS, G2_ADD_ADDRESS, G2_MSM_ADDRESS, MAP_FP_TO_G1_ADDRESS,
        MAP_FP2_TO_G2_ADDRESS, PAIRING_ADDRESS,
    };

    replace(
        precompiles,
        precompile::secp256k1::ECRECOVER.address(),
        PrecompileId::EcRec,
        ecrecover,
    );
    replace(
        precompiles,
        precompile::hash::SHA256.address(),
        PrecompileId::Sha256,
        sha256,
    );
    replace(
        precompiles,
        precompile::identity::FUN.address(),
        PrecompileId::Identity,
        identity,
    );
    replace(
        precompiles,
        precompile::modexp::OSAKA.address(),
        PrecompileId::ModExp,
        modexp,
    );
    replace(
        precompiles,
        &precompile::bn254::add::ADDRESS,
        PrecompileId::Bn254Add,
        bn254_add,
    );
    replace(
        precompiles,
        &precompile::bn254::mul::ADDRESS,
        PrecompileId::Bn254Mul,
        bn254_mul,
    );
    replace(
        precompiles,
        &precompile::bn254::pair::ADDRESS,
        PrecompileId::Bn254Pairing,
        bn254_pairing,
    );
    replace(
        precompiles,
        precompile::blake2::FUN.address(),
        PrecompileId::Blake2F,
        blake2f,
    );
    replace(
        precompiles,
        &G1_ADD_ADDRESS,
        PrecompileId::Bls12G1Add,
        bls12_g1_add,
    );
    replace(
        precompiles,
        &G1_MSM_ADDRESS,
        PrecompileId::Bls12G1Msm,
        bls12_g1_msm,
    );
    replace(
        precompiles,
        &G2_ADD_ADDRESS,
        PrecompileId::Bls12G2Add,
        bls12_g2_add,
    );
    replace(
        precompiles,
        &G2_MSM_ADDRESS,
        PrecompileId::Bls12G2Msm,
        bls12_g2_msm,
    );
    replace(
        precompiles,
        &PAIRING_ADDRESS,
        PrecompileId::Bls12Pairing,
        bls12_pairing,
    );
    replace(
        precompiles,
        &MAP_FP_TO_G1_ADDRESS,
        PrecompileId::Bls12MapFpToGp1,
        bls12_map_fp_to_g1,
    );
    replace(
        precompiles,
        &MAP_FP2_TO_G2_ADDRESS,
        PrecompileId::Bls12MapFp2ToGp2,
        bls12_map_fp2_to_g2,
    );
    replace(
        precompiles,
        precompile::secp256r1::P256VERIFY_OSAKA.address(),
        PrecompileId::P256Verify,
        p256_verify,
    );

    precompiles.apply_precompile(&precompile::kzg_point_evaluation::ADDRESS, |_| None);
}

fn replace(
    precompiles: &mut PrecompilesMap,
    address: &Address,
    id: PrecompileId,
    function: PrecompileFn,
) {
    precompiles.apply_precompile(address, |_| Some(DynPrecompile::from((id, function))));
}

fn into_result(result: EthPrecompileResult, reservoir: u64) -> PrecompileResult {
    Ok(PrecompileOutput::from_eth_result(result, reservoir))
}

fn run_repriced(
    input: &[u8],
    gas_limit: u64,
    reservoir: u64,
    required_gas: u64,
    run: fn(&[u8], u64) -> EthPrecompileResult,
) -> PrecompileResult {
    if required_gas > gas_limit {
        return into_result(Err(PrecompileHalt::OutOfGas), reservoir);
    }

    let result = run(input, u64::MAX).map(|mut output| {
        output.gas_used = required_gas;
        output
    });
    into_result(result, reservoir)
}

fn ecrecover(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    run_repriced(
        input,
        gas_limit,
        reservoir,
        ECRECOVER_BASE,
        precompile::secp256k1::ec_recover_run,
    )
}

fn p256_verify(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    run_repriced(
        input,
        gas_limit,
        reservoir,
        P256_VERIFY_BASE,
        precompile::secp256r1::p256_verify_osaka,
    )
}

fn sha256(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    run_repriced(
        input,
        gas_limit,
        reservoir,
        precompile::calc_linear_cost(input.len(), SHA256_BASE, SHA256_PER_WORD),
        precompile::hash::sha256_run,
    )
}

fn identity(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    run_repriced(
        input,
        gas_limit,
        reservoir,
        precompile::calc_linear_cost(input.len(), IDENTITY_BASE, IDENTITY_PER_WORD),
        precompile::identity::identity_run,
    )
}

fn modexp_gas_calc(base_len: u64, exp_len: u64, mod_len: u64, exp_highp: &U256) -> u64 {
    precompile::modexp::gas_calc::<MODEXP_MIN_GAS, MODEXP_EXPONENT_BYTE_MULTIPLIER, 1, _>(
        base_len,
        exp_len,
        mod_len,
        exp_highp,
        |max_len| {
            if max_len <= 32 {
                return U256::from(MODEXP_SMALL_MULTIPLICATION_COMPLEXITY);
            }

            let words = U256::from(max_len.div_ceil(8));
            words * words * U256::from(MODEXP_LARGE_BASE_MODULUS_MULTIPLIER)
        },
    )
}

fn modexp(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    into_result(
        precompile::modexp::run_inner::<_, true>(input, gas_limit, MODEXP_MIN_GAS, modexp_gas_calc),
        reservoir,
    )
}

fn bn254_add(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    into_result(
        precompile::bn254::run_add(input, BN254_ADD, gas_limit),
        reservoir,
    )
}

fn bn254_mul(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    into_result(
        precompile::bn254::run_mul(input, BN254_MUL, gas_limit),
        reservoir,
    )
}

fn bn254_pairing(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    into_result(
        precompile::bn254::run_pair(input, BN254_PAIR_PER_POINT, BN254_PAIR_BASE, gas_limit),
        reservoir,
    )
}

fn blake2f(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    // BLAKE2F validates its exact input length before reading the round count.
    if input.len() != 213 {
        return into_result(precompile::blake2::run(input, gas_limit), reservoir);
    }
    let rounds = u32::from_be_bytes(input[..4].try_into().expect("length checked"));
    run_repriced(
        input,
        gas_limit,
        reservoir,
        u64::from(rounds).saturating_mul(BLAKE2_F_ROUND),
        precompile::blake2::run,
    )
}

fn bls12_g1_add(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    run_repriced(
        input,
        gas_limit,
        reservoir,
        BLS12_G1_ADD,
        precompile::bls12_381::g1_add::g1_add,
    )
}

fn bls12_g1_msm(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    use precompile::bls12_381_const::{DISCOUNT_TABLE_G1_MSM, G1_MSM_INPUT_LENGTH};

    if input.is_empty() || !input.len().is_multiple_of(G1_MSM_INPUT_LENGTH) {
        return into_result(
            precompile::bls12_381::g1_msm::g1_msm(input, gas_limit),
            reservoir,
        );
    }
    let required_gas = precompile::bls12_381_utils::msm_required_gas(
        input.len() / G1_MSM_INPUT_LENGTH,
        &DISCOUNT_TABLE_G1_MSM,
        BLS12_G1_MSM_BASE,
    );
    run_repriced(
        input,
        gas_limit,
        reservoir,
        required_gas,
        precompile::bls12_381::g1_msm::g1_msm,
    )
}

fn bls12_g2_add(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    run_repriced(
        input,
        gas_limit,
        reservoir,
        BLS12_G2_ADD,
        precompile::bls12_381::g2_add::g2_add,
    )
}

fn bls12_g2_msm(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    use precompile::bls12_381_const::{DISCOUNT_TABLE_G2_MSM, G2_MSM_INPUT_LENGTH};

    if input.is_empty() || !input.len().is_multiple_of(G2_MSM_INPUT_LENGTH) {
        return into_result(
            precompile::bls12_381::g2_msm::g2_msm(input, gas_limit),
            reservoir,
        );
    }
    let required_gas = precompile::bls12_381_utils::msm_required_gas(
        input.len() / G2_MSM_INPUT_LENGTH,
        &DISCOUNT_TABLE_G2_MSM,
        BLS12_G2_MSM_BASE,
    );
    run_repriced(
        input,
        gas_limit,
        reservoir,
        required_gas,
        precompile::bls12_381::g2_msm::g2_msm,
    )
}

fn bls12_pairing(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    use precompile::bls12_381_const::PAIRING_INPUT_LENGTH;

    if input.is_empty() || !input.len().is_multiple_of(PAIRING_INPUT_LENGTH) {
        return into_result(
            precompile::bls12_381::pairing::pairing(input, gas_limit),
            reservoir,
        );
    }
    let required_gas = BLS12_PAIRING_MULTIPLIER
        .saturating_mul((input.len() / PAIRING_INPUT_LENGTH) as u64)
        .saturating_add(BLS12_PAIRING_OFFSET);
    run_repriced(
        input,
        gas_limit,
        reservoir,
        required_gas,
        precompile::bls12_381::pairing::pairing,
    )
}

fn bls12_map_fp_to_g1(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    run_repriced(
        input,
        gas_limit,
        reservoir,
        BLS12_MAP_FP_TO_G1,
        precompile::bls12_381::map_fp_to_g1::map_fp_to_g1,
    )
}

fn bls12_map_fp2_to_g2(input: &[u8], gas_limit: u64, reservoir: u64) -> PrecompileResult {
    run_repriced(
        input,
        gas_limit,
        reservoir,
        BLS12_MAP_FP2_TO_G2,
        precompile::bls12_381::map_fp2_to_g2::map_fp2_to_g2,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::precompile::PrecompileStatus;

    fn assert_price(run: PrecompileFn, input: &[u8], expected: u64, expected_output_len: usize) {
        let oog = run(input, expected - 1, 0).unwrap();
        assert_eq!(oog.status, PrecompileStatus::Halt(PrecompileHalt::OutOfGas));

        let output = run(input, expected, 0).unwrap();
        assert_eq!(output.status, PrecompileStatus::Success);
        assert_eq!(output.gas_used, expected);
        assert_eq!(output.bytes.len(), expected_output_len);
    }

    #[test]
    fn fixed_and_linear_prices_match_tip_1102() {
        assert_price(ecrecover, &[], ECRECOVER_BASE, 0);
        assert_price(p256_verify, &[], P256_VERIFY_BASE, 0);
        assert_price(sha256, &[], SHA256_BASE, 32);
        assert_price(sha256, &[0; 33], SHA256_BASE + 2 * SHA256_PER_WORD, 32);
        assert_price(identity, &[], IDENTITY_BASE, 0);
        assert_price(
            identity,
            &[0; 33],
            IDENTITY_BASE + 2 * IDENTITY_PER_WORD,
            33,
        );
        assert_price(bn254_add, &[], BN254_ADD, 64);
        assert_price(bn254_mul, &[], BN254_MUL, 64);
        assert_price(bn254_pairing, &[], BN254_PAIR_BASE, 32);
    }

    #[test]
    fn blake2_round_price_matches_tip_1102() {
        let mut input = [0u8; 213];
        input[..4].copy_from_slice(&12u32.to_be_bytes());
        assert_price(blake2f, &input, 12 * BLAKE2_F_ROUND, 64);
    }

    #[test]
    fn bls12_prices_match_tip_1102() {
        assert_price(bls12_g1_add, &[0; 256], BLS12_G1_ADD, 128);
        assert_price(bls12_g1_msm, &[0; 160], BLS12_G1_MSM_BASE, 128);
        assert_price(bls12_g2_add, &[0; 512], BLS12_G2_ADD, 256);
        assert_price(bls12_g2_msm, &[0; 288], BLS12_G2_MSM_BASE, 256);
        assert_price(
            bls12_pairing,
            &[0; 384],
            BLS12_PAIRING_OFFSET + BLS12_PAIRING_MULTIPLIER,
            32,
        );
        assert_price(bls12_map_fp_to_g1, &[0; 64], BLS12_MAP_FP_TO_G1, 128);
        assert_price(bls12_map_fp2_to_g2, &[0; 128], BLS12_MAP_FP2_TO_G2, 256);
    }

    #[test]
    fn modexp_prices_match_tip_1102() {
        fn input(size: usize) -> Vec<u8> {
            let mut input = Vec::new();
            let encoded_size = U256::from(size).to_be_bytes::<32>();
            input.extend_from_slice(&encoded_size);
            input.extend_from_slice(&encoded_size);
            input.extend_from_slice(&encoded_size);
            input.extend(std::iter::repeat_n(0xff, 3 * size));
            input
        }

        assert_price(modexp, &input(32), 20_655, 32);
        assert_price(modexp, &input(64), 114_560, 64);
        assert_price(modexp, &input(128), 1_113_600, 128);
    }
}
