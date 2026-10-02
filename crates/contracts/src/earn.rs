//! Canonical versioned Earn dispatcher runtime for native vault and fee accounts.
//!
//! Compiled from `tempoxyz/earn` `src/core/NativeEarnDispatcher.sol` with the
//! repository's pinned Solidity 0.8.36 Foundry profile. The runtime delegates
//! nonpayment calls through the ERC-1967 implementation slot.

use alloy_primitives::{Address, B256, U256, address, b256, keccak256};

/// System-owned storage account for approved native Earn identities.
pub const NATIVE_EARN_REGISTRY_ADDRESS: Address =
    address!("0x5aea000000000000000000000000000000000000");

/// ERC-1967 implementation slot used by the v1 dispatcher.
pub const EARN_IMPLEMENTATION_SLOT: U256 = U256::from_be_bytes([
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
    0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
]);

/// Registry slot discriminator for an admitted vault or fee account.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarnRegistrationField {
    Kind = 0,
    Pair = 1,
    Implementation = 2,
    ImplementationHash = 3,
    Asset = 4,
    EarnShare = 5,
    EngineHash = 6,
}

/// Which registered account owns a native Earn payment selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarnPaymentKind {
    Vault,
    Fees,
}

/// Bounded ABI envelope for native Earn payment admission. Identity and caller
/// authority are checked by the handler after this stateless candidate check.
pub fn earn_payment_kind(input: &[u8]) -> Option<EarnPaymentKind> {
    if input.len() < 4 || input.len() > 8_192 {
        return None;
    }
    let selector = &input[..4];
    let (kind, expected_words, dynamic_offset) = match selector {
        [0x37, 0xa4, 0xe8, 0x34] => (EarnPaymentKind::Vault, 0, None), // accrueFees
        [0xbf, 0x94, 0xb7, 0x91] | [0xc1, 0xcb, 0xbc, 0xa7] => {
            (EarnPaymentKind::Vault, 1, None) // absorb / contribute
        }
        [0xe2, 0xbb, 0xb1, 0x58]
        | [0xf4, 0x2e, 0xd4, 0x96]
        | [0x7c, 0xbc, 0x23, 0x73]
        | [0x1e, 0xab, 0x77, 0xf4]
        | [0x2f, 0xa4, 0x62, 0x97] => (EarnPaymentKind::Vault, 2, None),
        [0xbc, 0x15, 0x7a, 0xc1]
        | [0xf4, 0x8e, 0x66, 0x2c]
        | [0xd8, 0x78, 0x01, 0x61]
        | [0x06, 0xee, 0xbf, 0x59]
        | [0xfb, 0x3a, 0xc8, 0xb8] => (EarnPaymentKind::Vault, 3, None),
        [0xff, 0x99, 0x89, 0x38] => (EarnPaymentKind::Vault, 4, None),
        [0x83, 0xad, 0x65, 0x2d] => (EarnPaymentKind::Vault, 2, Some(1)),
        [0x63, 0x02, 0xca, 0xdc] => (EarnPaymentKind::Vault, 3, Some(2)),
        [0x9f, 0xed, 0x97, 0xfb] => (EarnPaymentKind::Vault, 3, Some(1)),
        [0xaa, 0xd3, 0xec, 0x96] => (EarnPaymentKind::Fees, 2, None),
        _ => return None,
    };
    let head_end = 4 + expected_words * 32;
    if input.len() < head_end {
        return None;
    }
    if let Some(offset_word) = dynamic_offset {
        let offset = read_u64_word(&input[4 + offset_word * 32..4 + (offset_word + 1) * 32])?;
        if offset != expected_words * 32 || input.len() < head_end + 32 {
            return None;
        }
        let len = read_u64_word(&input[head_end..head_end + 32])?;
        if len > 4_096 {
            return None;
        }
        let padded = len.checked_add(31)?.checked_div(32)?.checked_mul(32)?;
        if input.len() != head_end + 32 + padded
            || input[head_end + 32 + len..].iter().any(|byte| *byte != 0)
        {
            return None;
        }
    } else if input.len() != head_end {
        return None;
    }
    Some(kind)
}

fn read_u64_word(word: &[u8]) -> Option<usize> {
    if word.len() != 32 || word[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    usize::try_from(u64::from_be_bytes(word[24..].try_into().ok()?)).ok()
}

/// Storage key for one account's system-owned registration field.
pub fn earn_registration_slot(account: Address, field: EarnRegistrationField) -> U256 {
    U256::from_be_bytes(keccak256(earn_registration_preimage(account, field)).0)
}

/// Canonical registry key input, also used by the metered native handler.
pub fn earn_registration_preimage(account: Address, field: EarnRegistrationField) -> [u8; 96] {
    const DOMAIN: B256 =
        b256!("0xbdebdfb899fbf90c067b2db549c68afc9c76bb8a8c86ce9eda615244bcd63fdf");
    let mut input = [0u8; 96];
    input[..32].copy_from_slice(DOMAIN.as_slice());
    input[44..64].copy_from_slice(account.as_slice());
    input[95] = field as u8;
    input
}

/// TIP-20's nested `roles[vault][ISSUER_ROLE]` storage slot.
pub fn earn_share_issuer_role_slot(vault: Address) -> U256 {
    let mut account_input = [0u8; 64];
    account_input[12..32].copy_from_slice(vault.as_slice());
    let account_slot = keccak256(account_input);
    let mut role_input = [0u8; 64];
    role_input[..32].copy_from_slice(keccak256(b"ISSUER_ROLE").as_slice());
    role_input[32..].copy_from_slice(account_slot.as_slice());
    U256::from_be_bytes(keccak256(role_input).0)
}

/// Canonical EIP-1167 clone runtime for an implementation.
pub fn earn_fees_clone_runtime(implementation: Address) -> [u8; 45] {
    let mut code = [0u8; 45];
    code[..10].copy_from_slice(&[0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73]);
    code[10..30].copy_from_slice(implementation.as_slice());
    code[30..].copy_from_slice(&[
        0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3,
    ]);
    code
}

/// Deployed runtime bytecode for the v1 native Earn dispatcher.
pub const NATIVE_EARN_DISPATCHER_V1_RUNTIME: &[u8] =
    include_bytes!("../abi/NativeEarnDispatcherV1.bin");

/// Exact hash used by admission and fork migration.
pub const NATIVE_EARN_DISPATCHER_V1_HASH: B256 =
    b256!("0x502aeca502056d259b30dcce44d73a0bfbbcca8fd0aaec28647e53978c2ee1b4");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_runtime_matches_pinned_hash() {
        assert_eq!(
            alloy_primitives::keccak256(NATIVE_EARN_DISPATCHER_V1_RUNTIME),
            NATIVE_EARN_DISPATCHER_V1_HASH
        );
    }

    #[test]
    fn issuer_role_slot_matches_archived_earn_share_proof() {
        let vault = address!("0x856e4424f806d16e8cbc702b3c0f2ede5468eae5");
        assert_eq!(
            earn_share_issuer_role_slot(vault),
            U256::from_be_bytes(
                b256!("0xb28033fdea4a4b58223b20ff75df53a1ab6ded509f7fd500d7a056357a2e1678").0
            )
        );
    }

    #[test]
    fn payment_selectors_match_earn_abi_and_bound_dynamic_data() {
        for (signature, words, kind) in [
            ("accrueFees()", 0, EarnPaymentKind::Vault),
            (
                "absorbEngineShareSurplus(uint256)",
                1,
                EarnPaymentKind::Vault,
            ),
            ("contribute(uint256)", 1, EarnPaymentKind::Vault),
            ("deposit(uint256,uint256)", 2, EarnPaymentKind::Vault),
            (
                "deposit(uint256,address,uint256)",
                3,
                EarnPaymentKind::Vault,
            ),
            (
                "depositVenueShares(uint256,uint256)",
                2,
                EarnPaymentKind::Vault,
            ),
            (
                "depositVenueShares(uint256,address,uint256)",
                3,
                EarnPaymentKind::Vault,
            ),
            ("redeem(uint256,uint256)", 2, EarnPaymentKind::Vault),
            ("redeem(uint256,address,uint256)", 3, EarnPaymentKind::Vault),
            (
                "spendFromEarn(uint256,address,uint256,bytes32)",
                4,
                EarnPaymentKind::Vault,
            ),
            ("withdrawExact(uint256,uint256)", 2, EarnPaymentKind::Vault),
            (
                "withdrawExact(uint256,address,uint256)",
                3,
                EarnPaymentKind::Vault,
            ),
            ("cancelRedeem(bytes32,uint256)", 2, EarnPaymentKind::Vault),
            (
                "finalizeRedeem(bytes32,address,uint256)",
                3,
                EarnPaymentKind::Vault,
            ),
            ("claim(address,uint256)", 2, EarnPaymentKind::Fees),
        ] {
            let mut input = keccak256(signature).as_slice()[..4].to_vec();
            input.resize(4 + 32 * words, 0);
            assert_eq!(earn_payment_kind(&input), Some(kind), "{signature}");
            input.push(0);
            assert_eq!(earn_payment_kind(&input), None, "{signature} trailing byte");
        }
        for (signature, words, offset_word) in [
            ("requestRedeem(uint256,bytes)", 2, 1),
            ("requestRedeem(uint256,address,bytes)", 3, 2),
            ("requestRedeem(uint256,bytes,address)", 3, 1),
        ] {
            let mut input = keccak256(signature).as_slice()[..4].to_vec();
            input.resize(4 + 32 * words + 32, 0);
            input[4 + offset_word * 32 + 31] = (words * 32) as u8;
            assert_eq!(earn_payment_kind(&input), Some(EarnPaymentKind::Vault));
            input[4 + offset_word * 32 + 31] = 0;
            assert_eq!(earn_payment_kind(&input), None);
        }
    }
}
