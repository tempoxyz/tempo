//! TIP-1069 canonical stealth-address transfer precompile.

pub mod dispatch;

use crate::{
    TIP20_STEALTH_ADDRESS,
    error::Result,
    tip20::{ITIP20, TIP20Token},
};
use alloy::primitives::{Address, U256};
pub use tempo_contracts::precompiles::{ITIP20Stealth, TIP20StealthError, TIP20StealthEvent};
use tempo_precompiles_macros::contract;

/// secp256k1 stealth-address derivation scheme.
pub const SCHEME_SECP256K1: u8 = 0x01;
/// P-256 stealth-address derivation scheme.
pub const SCHEME_P256: u8 = 0x02;
/// Metadata length for all TIP-1069 v1 schemes.
pub const V1_METADATA_LEN: usize = 35;

#[contract(addr = TIP20_STEALTH_ADDRESS)]
pub struct TIP20Stealth {}

impl TIP20Stealth {
    /// Initializes the precompile marker bytecode.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Transfers TIP-20 funds from `msg_sender` to a derived stealth address and announces it.
    pub fn transfer(
        &mut self,
        msg_sender: Address,
        call: ITIP20Stealth::transferCall,
    ) -> Result<bool> {
        validate_metadata(&call.metadata)?;

        let mut token = TIP20Token::from_address(call.token)?;
        self.ensure_no_custody(&token)?;

        token.transfer_as_system(
            self.address,
            ITIP20::transferAsSystemCall {
                from: msg_sender,
                to: call.stealthAddress,
                amount: call.amount,
            },
        )?;

        self.ensure_no_custody(&token)?;
        self.emit_event(TIP20StealthEvent::announce(
            call.token,
            call.stealthAddress,
            call.metadata,
            call.memo,
        ))?;

        Ok(true)
    }

    fn ensure_no_custody(&self, token: &TIP20Token) -> Result<()> {
        let balance = token.balance_of(ITIP20::balanceOfCall {
            account: self.address,
        })?;
        if balance != U256::ZERO {
            return Err(TIP20StealthError::precompile_custody().into());
        }
        Ok(())
    }
}

/// Validates TIP-1069 metadata without parsing or curve-validating the ephemeral pubkey.
pub fn validate_metadata(metadata: &[u8]) -> Result<()> {
    let Some((&scheme, _)) = metadata.split_first() else {
        return Err(TIP20StealthError::invalid_metadata().into());
    };

    match scheme {
        SCHEME_SECP256K1 | SCHEME_P256 => {
            if metadata.len() != V1_METADATA_LEN {
                return Err(TIP20StealthError::invalid_metadata().into());
            }
        }
        _ => return Err(TIP20StealthError::unknown_scheme().into()),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::{ITIP20, TIP20Event},
    };
    use alloy::primitives::{Bytes, U256};
    use tempo_chainspec::hardfork::TempoHardfork;

    fn metadata(scheme: u8) -> Bytes {
        let mut metadata = vec![0u8; V1_METADATA_LEN];
        metadata[0] = scheme;
        metadata[1] = 0x02;
        metadata[34] = 0xa7;
        metadata.into()
    }

    #[test]
    fn test_validate_metadata_accepts_v1_schemes() -> eyre::Result<()> {
        validate_metadata(&metadata(SCHEME_SECP256K1))?;
        validate_metadata(&metadata(SCHEME_P256))?;
        Ok(())
    }

    #[test]
    fn test_validate_metadata_rejects_empty_unknown_and_wrong_length() {
        assert!(matches!(
            validate_metadata(&[]),
            Err(TempoPrecompileError::TIP20StealthError(
                TIP20StealthError::InvalidMetadata(_)
            ))
        ));

        assert!(matches!(
            validate_metadata(&metadata(0xff)),
            Err(TempoPrecompileError::TIP20StealthError(
                TIP20StealthError::UnknownScheme(_)
            ))
        ));

        let mut short = metadata(SCHEME_SECP256K1).to_vec();
        short.pop();
        assert!(matches!(
            validate_metadata(&short),
            Err(TempoPrecompileError::TIP20StealthError(
                TIP20StealthError::InvalidMetadata(_)
            ))
        ));
    }

    #[test]
    fn test_transfer_moves_funds_and_emits_announce() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let admin = Address::random();
        let sender = Address::random();
        let stealth_address = Address::random();
        let amount = U256::from(250);
        let metadata = metadata(SCHEME_SECP256K1);
        let memo = Bytes::from_static(b"encrypted memo");

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(sender, amount)
                .clear_events()
                .apply()?;
            let mut stealth = TIP20Stealth::new();

            let ok = stealth.transfer(
                sender,
                ITIP20Stealth::transferCall {
                    token: token.address(),
                    stealthAddress: stealth_address,
                    amount,
                    metadata: metadata.clone(),
                    memo: memo.clone(),
                },
            )?;
            assert!(ok);

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: sender })?,
                U256::ZERO
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: stealth_address
                })?,
                amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: TIP20_STEALTH_ADDRESS
                })?,
                U256::ZERO
            );

            token.assert_emitted_events(vec![TIP20Event::transfer(
                sender,
                stealth_address,
                amount,
            )]);
            stealth.assert_emitted_events(vec![TIP20StealthEvent::announce(
                token.address(),
                stealth_address,
                metadata,
                memo,
            )]);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_rejects_invalid_metadata_before_moving_funds() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        let admin = Address::random();
        let sender = Address::random();
        let stealth_address = Address::random();
        let amount = U256::from(250);

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(sender, amount)
                .clear_events()
                .apply()?;
            let mut stealth = TIP20Stealth::new();

            let result = stealth.transfer(
                sender,
                ITIP20Stealth::transferCall {
                    token: token.address(),
                    stealthAddress: stealth_address,
                    amount,
                    metadata: Bytes::new(),
                    memo: Bytes::new(),
                },
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20StealthError(
                    TIP20StealthError::InvalidMetadata(_)
                ))
            ));
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: sender })?,
                amount
            );
            assert!(stealth.emitted_events().is_empty());

            Ok(())
        })
    }
}
