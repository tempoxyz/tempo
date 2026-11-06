//! TIP-1102 prices for Ethereum precompiles, active from T15.

use alloy_primitives::{Address, U256};
use evm2::{
    Evm, EvmTypesHost, Precompiles,
    interpreter::{GasTracker, Message},
    precompiles::{
        PrecompileError, PrecompileHalt, PrecompileResult, blake2, bls12_381, bn254, hash,
        identity, modexp, secp256k1, secp256r1,
    },
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::transaction::tt_signature::PrimitiveSignature;

pub(crate) const ECRECOVER_GAS: u64 = 25_000;
pub(crate) const P256_VERIFY_GAS: u64 = 27_000;
const KECCAK256_BASE_GAS: u64 = 205;
const KECCAK256_WORD_GAS: u64 = 41;

const G1_MSM_BASE: u64 = 78_000;
const G2_MSM_BASE: u64 = 143_000;

/// Installs TIP-1102 pricing on built-in descriptors for the active Tempo fork.
/// The implementation stays attached when a precompile is relocated.
pub fn configure_base_precompiles<T: EvmTypesHost>(base: &mut Precompiles<T>, spec: TempoHardfork) {
    if !spec.is_t15() {
        return;
    }

    macro_rules! install {
        ($($address:literal),* $(,)?) => {
            $(
                base.as_map_mut().map_precompile(
                    &Address::from_word(U256::from($address).into()),
                    |data| data.with_run(execute_registered::<$address, T>),
                );
            )*
        };
    }
    install!(
        0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x100,
    );
}

fn execute_registered<const ADDRESS: u16, T: EvmTypesHost>(
    _evm: &mut Evm<'_, T>,
    message: &Message<T>,
    gas: &mut GasTracker,
) -> PrecompileResult {
    if ADDRESS == 0x0a {
        return Err(PrecompileError::Halt(
            PrecompileHalt::BlobVerifyKzgProofFailed,
        ));
    }
    if ADDRESS == 0x100 {
        return run_p256(&message.input, gas);
    }
    run(
        Address::from_word(U256::from(ADDRESS).into()),
        &message.input,
        gas,
    )
    .expect("registered TIP-1102 precompile has a price")
}

pub(crate) fn keccak_gas(len: usize) -> Option<u64> {
    let words = u64::try_from(len.div_ceil(32)).ok()?;
    KECCAK256_WORD_GAS
        .checked_mul(words)?
        .checked_add(KECCAK256_BASE_GAS)
}

pub(crate) fn sha256_gas(len: usize) -> u64 {
    linear(len, 104, 13)
}

pub(crate) fn primitive_verification_gas(signature: &PrimitiveSignature) -> Option<u64> {
    match signature {
        PrimitiveSignature::Secp256k1(_) => Some(ECRECOVER_GAS),
        PrimitiveSignature::P256(_) => Some(P256_VERIFY_GAS),
        PrimitiveSignature::WebAuthn(inner) => {
            P256_VERIFY_GAS.checked_add(sha256_gas(inner.webauthn_data.len()))
        }
    }
}

/// Reprices built-in precompiles while retaining EVM2's input validation and cryptography.
pub(super) fn run(
    address: Address,
    input: &[u8],
    gas: &mut GasTracker,
) -> Option<PrecompileResult> {
    let last = address.as_slice()[19];
    if address != Address::with_last_byte(last) {
        return None;
    }
    let result = match last {
        0x01 => repriced(input, gas, ECRECOVER_GAS, secp256k1::run),
        0x02 => repriced(input, gas, sha256_gas(input.len()), hash::run_sha256),
        0x04 => repriced(input, gas, linear(input.len(), 50, 1), identity::run),
        0x05 => modexp::run_inner(input, gas, 500, true, modexp_gas),
        0x06 => bn254::run_add(input, 2_000, gas),
        0x07 => bn254::run_mul(input, 45_000, gas),
        0x08 => bn254::run_pair(input, 243_000, 285_000, gas),
        0x09 => {
            if input.len() != 213 {
                blake2::run(input, gas)
            } else {
                let rounds = u32::from_be_bytes(input[..4].try_into().expect("length checked"));
                repriced(
                    input,
                    gas,
                    u64::from(rounds).saturating_mul(10).saturating_add(64),
                    blake2::run,
                )
            }
        }
        0x0b => repriced(input, gas, 2_300, bls12_381::g1_add::run),
        0x0c => msm(
            input,
            gas,
            160,
            G1_MSM_BASE,
            &G1_MSM_DISCOUNT,
            bls12_381::g1_msm::run,
        ),
        0x0d => repriced(input, gas, 3_500, bls12_381::g2_add::run),
        0x0e => msm(
            input,
            gas,
            288,
            G2_MSM_BASE,
            &G2_MSM_DISCOUNT,
            bls12_381::g2_msm::run,
        ),
        0x0f => {
            if input.is_empty() || !input.len().is_multiple_of(384) {
                bls12_381::pairing::run(input, gas)
            } else {
                let pairs = (input.len() / 384) as u64;
                repriced(
                    input,
                    gas,
                    230_000u64.saturating_add(pairs.saturating_mul(167_000)),
                    bls12_381::pairing::run,
                )
            }
        }
        0x10 => repriced(input, gas, 26_000, bls12_381::map_fp_to_g1::run),
        0x11 => repriced(input, gas, 95_000, bls12_381::map_fp2_to_g2::run),
        _ => return None,
    };
    Some(result)
}

/// P-256 lives at address 0x100, outside the one-byte precompile range.
pub(super) fn run_p256(input: &[u8], gas: &mut GasTracker) -> PrecompileResult {
    repriced(input, gas, P256_VERIFY_GAS, secp256r1::run_osaka)
}

fn linear(len: usize, base: u64, per_word: u64) -> u64 {
    base.saturating_add((len.div_ceil(32) as u64).saturating_mul(per_word))
}

fn repriced(
    input: &[u8],
    gas: &mut GasTracker,
    required: u64,
    run: fn(&[u8], &mut GasTracker) -> PrecompileResult,
) -> PrecompileResult {
    gas.spend(required)?;
    run(input, &mut GasTracker::new(u64::MAX))
}

fn msm(
    input: &[u8],
    gas: &mut GasTracker,
    element_len: usize,
    base: u64,
    discount: &[u16; 128],
    run: fn(&[u8], &mut GasTracker) -> PrecompileResult,
) -> PrecompileResult {
    if input.is_empty() || !input.len().is_multiple_of(element_len) {
        return run(input, gas);
    }
    let k = input.len() / element_len;
    let discount = u64::from(discount[(k - 1).min(127)]);
    let required = (k as u64).saturating_mul(discount).saturating_mul(base) / 1_000;
    repriced(input, gas, required, run)
}

fn modexp_gas(base_len: u64, exp_len: u64, mod_len: u64, exp_highp: &U256) -> u64 {
    let max_len = base_len.max(mod_len);
    let words = U256::from(max_len.div_ceil(8));
    let complexity = (words * words * U256::from(2)).max(U256::from(81));
    let iteration = if exp_len <= 32 {
        exp_highp.bit_len().saturating_sub(1) as u64
    } else {
        20u64
            .saturating_mul(exp_len - 32)
            .saturating_add(exp_highp.bit_len().max(1) as u64 - 1)
    }
    .max(1);
    let size_floor = words * words * U256::from(16);
    let price = (complexity * U256::from(iteration)).max(size_floor);
    500.max(price.saturating_to())
}

// EIP-2537 discounts copied from EVM2's gas schedule; only the base prices change.
const G1_MSM_DISCOUNT: [u16; 128] = [
    1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677, 673, 669, 665,
    661, 658, 654, 651, 648, 645, 642, 640, 637, 635, 632, 630, 627, 625, 623, 621, 619, 617, 615,
    613, 611, 609, 608, 606, 604, 603, 601, 599, 598, 596, 595, 593, 592, 591, 589, 588, 586, 585,
    584, 582, 581, 580, 579, 577, 576, 575, 574, 573, 572, 570, 569, 568, 567, 566, 565, 564, 563,
    562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 551, 550, 549, 548, 547, 547, 546, 545,
    544, 543, 542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534, 533, 532, 532, 531, 530, 529,
    528, 528, 527, 526, 525, 525, 524, 523, 522, 522, 521, 520, 520, 519,
];
const G2_MSM_DISCOUNT: [u16; 128] = [
    1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717, 711, 704,
    699, 693, 688, 683, 679, 674, 670, 666, 663, 659, 655, 652, 649, 646, 643, 640, 637, 634, 632,
    629, 627, 624, 622, 620, 618, 615, 613, 611, 609, 607, 606, 604, 602, 600, 598, 597, 595, 593,
    592, 590, 589, 587, 586, 584, 583, 582, 580, 579, 578, 576, 575, 574, 573, 571, 570, 569, 568,
    567, 566, 565, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 552, 551, 550, 549,
    548, 547, 546, 545, 545, 544, 543, 542, 541, 541, 540, 539, 538, 537, 537, 536, 535, 535, 534,
    533, 532, 532, 531, 530, 530, 529, 528, 528, 527, 526, 526, 525, 524, 524,
];

#[cfg(test)]
mod tests {
    use super::*;
    use evm2::precompiles::{PrecompileError, PrecompileHalt};
    use tempo_primitives::transaction::tt_signature::{
        P256SignatureWithPreHash, WebAuthnSignature,
    };

    #[test]
    fn native_signature_prices() {
        let p256 = P256SignatureWithPreHash {
            r: Default::default(),
            s: Default::default(),
            pub_key_x: Default::default(),
            pub_key_y: Default::default(),
            pre_hash: false,
        };
        assert_eq!(
            primitive_verification_gas(&PrimitiveSignature::P256(p256)),
            Some(27_000)
        );
        let webauthn = WebAuthnSignature {
            r: Default::default(),
            s: Default::default(),
            pub_key_x: Default::default(),
            pub_key_y: Default::default(),
            webauthn_data: vec![0; 33].into(),
        };
        assert_eq!(
            primitive_verification_gas(&PrimitiveSignature::WebAuthn(webauthn)),
            Some(27_000 + 104 + 13 * 2)
        );
    }

    fn assert_price(address: Address, input: &[u8], expected: u64, output_len: usize) {
        let mut gas = GasTracker::new(expected - 1);
        assert!(matches!(
            run(address, input, &mut gas).unwrap(),
            Err(PrecompileError::Halt(PrecompileHalt::OutOfGas))
        ));
        let mut gas = GasTracker::new(expected);
        let output = run(address, input, &mut gas).unwrap().unwrap();
        assert_eq!(gas.remaining(), 0);
        assert_eq!(output.bytes().len(), output_len);
    }

    #[test]
    fn fixed_and_linear_prices() {
        assert_price(Address::with_last_byte(1), &[], 25_000, 0);
        assert_price(Address::with_last_byte(2), &[], 104, 32);
        assert_price(Address::with_last_byte(2), &[0; 33], 130, 32);
        assert_price(Address::with_last_byte(4), &[0; 33], 52, 33);
        assert_price(Address::with_last_byte(6), &[], 2_000, 64);
        assert_price(Address::with_last_byte(7), &[], 45_000, 64);
        assert_price(Address::with_last_byte(8), &[], 285_000, 32);
        let mut gas = GasTracker::new(27_000);
        assert_eq!(run_p256(&[], &mut gas).unwrap().bytes().len(), 0);
        assert_eq!(gas.remaining(), 0);
    }

    #[test]
    fn blake_and_bls_prices() {
        let mut blake_input = [0u8; 213];
        blake_input[..4].copy_from_slice(&12u32.to_be_bytes());
        assert_price(Address::with_last_byte(9), &blake_input, 184, 64);
        assert_price(Address::with_last_byte(0x0b), &[0; 256], 2_300, 128);
        assert_price(Address::with_last_byte(0x0c), &[0; 160], 78_000, 128);
        assert_price(Address::with_last_byte(0x0d), &[0; 512], 3_500, 256);
        assert_price(Address::with_last_byte(0x0e), &[0; 288], 143_000, 256);
        assert_price(Address::with_last_byte(0x0f), &[0; 384], 397_000, 32);
        assert_price(Address::with_last_byte(0x10), &[0; 64], 26_000, 128);
        assert_price(Address::with_last_byte(0x11), &[0; 128], 95_000, 256);
    }

    #[test]
    fn modexp_prices() {
        assert_eq!(modexp_gas(32, 33, 32, &U256::MAX), 81 * 275);
        assert_eq!(modexp_gas(33, 33, 33, &U256::MAX), 81 * 275);
        assert_eq!(modexp_gas(1_024, 1, 1_024, &U256::from(3)), 262_144);

        fn input(size: usize) -> Vec<u8> {
            let mut input = Vec::new();
            let encoded_size = U256::from(size).to_be_bytes::<32>();
            input.extend_from_slice(&encoded_size);
            input.extend_from_slice(&encoded_size);
            input.extend_from_slice(&encoded_size);
            input.extend(std::iter::repeat_n(0xff, 3 * size));
            input
        }
        assert_price(Address::with_last_byte(5), &input(32), 20_655, 32);
        assert_price(Address::with_last_byte(5), &input(64), 114_560, 64);
        assert_price(Address::with_last_byte(5), &input(128), 1_113_600, 128);
    }
}
