//! Adapter between Tempo's protocol fee hooks and the Zone fee manager.

use alloy_primitives::{Address, U256};
use evm2::{Evm, registry::HandlerResult};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{
    ProtocolFeeContext, ProtocolFeeManager, ResolvedFeeToken, TempoEvmTypes,
    TempoInvalidTransaction, TempoStateAccess, TempoTx, TempoTxEnv,
};
use tempo_precompiles::{
    error::Result,
    storage::{ContractStorage, StorageActions},
    tip20::TIP20Token,
};
use zone_precompiles::ZoneFeeManager;

/// Resolves the fee token selected by a Zone transaction against the supplied state view.
///
/// Both protocol execution and RPC gas allowance use this function so omitted fee tokens always
/// resolve through the Zone fee manager at the state being executed or simulated.
pub(crate) fn resolve_fee_token<S, M>(
    state: &mut S,
    tx: &TempoTxEnv,
    spec: TempoHardfork,
    actions: StorageActions,
) -> Result<Address>
where
    S: TempoStateAccess<M>,
{
    if let Some(token) = tx.fee_token() {
        return Ok(token);
    }

    state.with_read_only_storage_ctx(spec, actions, || ZoneFeeManager::new().default_fee_token())
}

/// Resolves and collects fees without Tempo token preferences or FeeAMM settlement.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ZoneProtocolFeeManager;

impl ZoneProtocolFeeManager {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl ProtocolFeeManager for ZoneProtocolFeeManager {
    fn get_fee_token(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        tx: &TempoTxEnv,
        _fee_payer: Address,
        _max_fee: U256,
        spec: TempoHardfork,
    ) -> Result<ResolvedFeeToken> {
        // Tempo's transaction handler calls this hook. The trait default reads the L1
        // TipFeeManager, so Zones must override it to resolve their genesis-configured default.
        let actions = host.ext().actions.clone();
        resolve_fee_token(host, tx, spec, actions).map(ResolvedFeeToken::Selected)
    }

    fn validate_fee_token(
        &self,
        host: &mut Evm<'_, TempoEvmTypes>,
        fee_token: Address,
        spec: TempoHardfork,
    ) -> HandlerResult<()> {
        let actions = host.ext().actions.clone();
        let initialized = host.with_read_only_storage_ctx(spec, actions, || {
            // The handler validates the TIP-20 prefix before entering this hook.
            TIP20Token::from_address_unchecked(fee_token).is_initialized()
        })?;

        if !initialized {
            return Err(TempoInvalidTransaction::InvalidFeeToken(fee_token).into());
        }

        Ok(())
    }

    fn collect_fee_pre_tx(
        &self,
        ctx: ProtocolFeeContext<'_, '_>,
        fee_payer: Address,
        fee_token: Address,
        max_amount: U256,
        beneficiary: Address,
        _skip_liquidity_check: bool,
    ) -> Result<Address> {
        ctx.enter(|| {
            ZoneFeeManager::new().collect_fee_pre_tx(fee_payer, fee_token, max_amount, beneficiary)
        })
    }

    fn collect_fee_post_tx(
        &self,
        ctx: ProtocolFeeContext<'_, '_>,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> Result<U256> {
        ctx.enter(|| {
            ZoneFeeManager::new().collect_fee_post_tx(
                fee_payer,
                actual_spending,
                refund_amount,
                fee_token,
                beneficiary,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes, TxKind, U256, address};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use evm2::{
        SpecId,
        bytecode::Bytecode,
        evm::{AccountInfo, InMemoryDB},
        registry::HandlerError,
    };
    use reth_evm::BlockExecutorFactory;
    use reth_primitives_traits::Recovered;
    use tempo_contracts::zones::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};
    use tempo_evm::TempoEvmEnv;
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        storage::{Handler, StorageCtx, StorageKey},
        storage_credits::StorageCredits,
        test_util::TIP20Setup,
        zone_factory::portal,
    };
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{
            Call, PrimitiveSignature, TempoSignature, TempoTransaction, calc_gas_balance_spending,
        },
    };
    use zone_precompiles::{
        ZONE_FEE_MANAGER_ADDRESS, ZoneOutbox, tempo_state::TEMPO_BLOCK_NUMBER_SLOT,
        test_utils::MockL1Reader, zone_fee_manager,
    };
    use zone_primitives::constants::TEMPO_STATE_ADDRESS;

    use crate::zone_evm::tests::config;

    fn tx_env(fee_token: Option<Address>) -> TempoTxEnv {
        Recovered::new_unchecked(
            TempoTxEnvelope::AA(
                TempoTransaction {
                    fee_token,
                    ..Default::default()
                }
                .into_signed(TempoSignature::default()),
            ),
            Address::ZERO,
        )
        .into()
    }

    #[test]
    fn resolves_explicit_token_or_zone_default() {
        let default_token = address!("0x20c00000000000000000000000000000000000d1");
        let explicit_token = address!("0x20c00000000000000000000000000000000000e1");
        let mut db = InMemoryDB::default();
        db.insert_account_info(&ZONE_FEE_MANAGER_ADDRESS, AccountInfo::default());
        db.insert_account_storage(
            &ZONE_FEE_MANAGER_ADDRESS,
            &zone_fee_manager::slots::DEFAULT_FEE_TOKEN,
            &U256::from_be_slice(default_token.as_slice()),
        );
        let mut evm = config(MockL1Reader::default()).evm_with_env(db, TempoEvmEnv::default());

        assert_eq!(
            resolve_fee_token(
                &mut evm,
                &tx_env(None),
                TempoHardfork::T1,
                StorageActions::disabled(),
            )
            .unwrap(),
            default_token,
        );
        assert_eq!(
            resolve_fee_token(
                &mut evm,
                &tx_env(Some(explicit_token)),
                TempoHardfork::T1,
                StorageActions::disabled(),
            )
            .unwrap(),
            explicit_token,
        );
    }

    #[test]
    fn accepts_any_initialized_zone_tip20_as_a_fee_token() {
        let initialized_token = address!("0x20c00000000000000000000000000000000000e1");
        let missing_token = address!("0x20c00000000000000000000000000000000000e2");
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &initialized_token,
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[0xef]))),
        );
        let mut evm = config(MockL1Reader::default()).evm_with_env(db, TempoEvmEnv::default());
        let manager = ZoneProtocolFeeManager::new();

        assert!(
            manager
                .validate_fee_token(&mut evm, initialized_token, TempoHardfork::T9)
                .is_ok()
        );
        assert!(matches!(
            manager.validate_fee_token(&mut evm, missing_token, TempoHardfork::T9),
            Err(HandlerError::External(error))
                if error.downcast_ref::<TempoInvalidTransaction>()
                    == Some(&TempoInvalidTransaction::InvalidFeeToken(missing_token))
        ));
    }

    /// A sponsored transaction by the block beneficiary that withdraws its whole fee-token balance
    /// clears the slot fee settlement then recreates without TIP-1060 accounting, so from T15 the
    /// clear must not mint a storage credit. Earlier forks keep minting it.
    #[test]
    fn fee_recipient_balance_clear_mints_no_storage_credit_from_t15() -> eyre::Result<()> {
        const ANCHOR: u64 = 42;
        const BENEFICIARY_FUNDS: u128 = 10_000_000;
        let gas_limit = 5_000_000;
        let gas_price = 1_000_000_000_000;
        let max_fee = calc_gas_balance_spending(gas_limit, gas_price);
        let token = PATH_USD_ADDRESS;

        for (spec, sponsored) in [
            TempoHardfork::T7,
            TempoHardfork::T13,
            TempoHardfork::T14,
            TempoHardfork::T15,
        ]
        .into_iter()
        .flat_map(|spec| [(spec, true), (spec, false)])
        {
            let beneficiary = PrivateKeySigner::random();
            let sponsor = PrivateKeySigner::random();
            let fee_payer = if sponsored { &sponsor } else { &beneficiary };

            let mut db = InMemoryDB::default();
            db.insert_account_storage(
                &TEMPO_STATE_ADDRESS,
                &TEMPO_BLOCK_NUMBER_SLOT,
                &U256::from(ANCHOR),
            );
            let l1 = MockL1Reader::default();
            l1.insert(
                Address::ZERO,
                token.mapping_slot(portal::slots::TOKEN_CONFIGS),
                ANCHOR,
                U256::ONE,
            );
            let mut env = TempoEvmEnv {
                spec,
                ..Default::default()
            };
            env.version = tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, false);
            env.block.gas_limit = U256::from(30_000_000);
            env.block.beneficiary = beneficiary.address();
            let mut evm = config(l1).evm_with_env(db, env);
            StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || -> eyre::Result<()> {
                ZoneOutbox::new().initialize()?;
                TIP20Setup::path_usd(sponsor.address())
                    .with_issuer(sponsor.address())
                    .with_issuer(ZONE_OUTBOX_ADDRESS)
                    .with_mint(beneficiary.address(), U256::from(BENEFICIARY_FUNDS))
                    .with_mint(sponsor.address(), max_fee)
                    .with_approval(beneficiary.address(), ZONE_OUTBOX_ADDRESS, U256::MAX)
                    .apply()?;
                Ok(())
            })?;
            // Accept the setup so the mirrored-storage check sees only the transaction's writes.
            evm.state_mut().commit_transaction();
            evm.state_mut().clear_transaction_state();

            let amount = if sponsored {
                BENEFICIARY_FUNDS
            } else {
                BENEFICIARY_FUNDS - max_fee.to::<u128>()
            };
            let mut tx = TempoTransaction {
                chain_id: 1,
                fee_token: Some(token),
                gas_limit,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: gas_price,
                calls: vec![Call {
                    to: TxKind::Call(ZONE_OUTBOX_ADDRESS),
                    value: U256::ZERO,
                    input: IZoneOutbox::requestWithdrawalCall {
                        token,
                        to: beneficiary.address(),
                        amount,
                        memo: B256::ZERO,
                        gasLimit: 0,
                        zoneFallbackRecipient: beneficiary.address(),
                        data: Bytes::new(),
                        revealTo: Bytes::new(),
                    }
                    .abi_encode()
                    .into(),
                }],
                ..Default::default()
            };
            if sponsored {
                tx.fee_payer_signature = Some(
                    fee_payer
                        .sign_hash_sync(&tx.fee_payer_signature_hash(beneficiary.address()))?,
                );
            }
            let signature = beneficiary.sign_hash_sync(&tx.signature_hash())?;
            let envelope = TempoTxEnvelope::AA(tx.into_signed(TempoSignature::Primitive(
                PrimitiveSignature::Secp256k1(signature),
            )));
            let tx_env: TempoTxEnv =
                Recovered::new_unchecked(envelope, beneficiary.address()).into();
            assert_eq!(tx_env.fee_payer()?, fee_payer.address());
            let result = evm
                .transact(&Recovered::new_unchecked(tx_env, beneficiary.address()))?
                .commit();
            assert!(result.status, "withdrawal should succeed: {result:?}");

            let (fee_recipient_balance, credits) =
                StorageCtx::enter_evm_without_tip1060_accounting(
                    &mut evm,
                    || -> eyre::Result<(U256, u64)> {
                        let balance = TIP20Token::from_address(token)?.balances
                            [beneficiary.address()]
                        .read()?;
                        Ok((balance, StorageCredits::new().balance_of(token)?))
                    },
                )?;
            assert!(
                !fee_recipient_balance.is_zero(),
                "fee settlement should recreate the beneficiary's cleared balance"
            );
            let expected = u64::from(sponsored && !spec.is_t15());
            assert_eq!(credits, expected, "{spec}, sponsored: {sponsored}");
        }
        Ok(())
    }
}
