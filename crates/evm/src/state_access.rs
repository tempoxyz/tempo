//! State access of TIP-20 payment transactions, derived without executing them.

use alloy_consensus::{Transaction as _, transaction::Recovered};
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::{
    Address, B256, U256,
    map::{AddressMap, B256Set},
};
use reth_evm::TxStateAccess;
use tempo_contracts::precompiles::PaymentSlots;
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS, nonce,
    storage::{StorableType, StorageKey},
    tip_fee_manager,
    tip20::{rewards::UserRewardInfo, tip20_slots},
    tip403_registry::tip403_registry_slots,
};
use tempo_primitives::{TempoAddressExt, transaction::TEMPO_EXPIRING_NONCE_KEY};

use crate::{TempoEvmEnv, TempoEvmTx, TempoTx, TempoTxEnv};

/// Returns the state a [TIP-20 payment] transaction is expected to access in `env`, derived
/// from the transaction alone.
///
/// Covers the sender's nonce, the fee debit and the fee recipient's fee manager entries, and per
/// call the token's pause flag, balances and allowance, its transfer policy ID, the recipient's
/// receive policy and, before T8, the holders' reward state. State whose location depends on other state is left out: the policies
/// those registry entries point to, the expiring nonce ring entry, and the fee swap pools used when
/// the fee recipient's validator token is not the fee token. Without a fee token on the
/// transaction, the fee token is taken to be the called token when the sender pays and every call
/// targets that token, as fee token inference resolves it when the payer has no preference.
///
/// Returns `None` unless every call is a [`PaymentSlots`] call to a TIP-20 token, and for
/// transactions with access or authorization lists, inline key authorizations or access key
/// signatures, whose additional state is not derived.
///
/// [TIP-20 payment]: <https://docs.tempo.xyz/protocol/tip20/overview#get-predictable-payment-fees>
pub(crate) fn payment_state_access(
    env: &TempoEvmEnv,
    tx: &Recovered<TempoTxEnv>,
) -> Option<TxStateAccess> {
    let sender = tx.signer();
    let tx = tx.inner();
    let nonce_key = match tx.evm_tx() {
        TempoEvmTx::AA(aa) => {
            let signed = aa.inner();
            let aa_tx = signed.tx();
            if !aa_tx.access_list.is_empty()
                || !aa_tx.tempo_authorization_list.is_empty()
                || aa_tx.key_authorization.is_some()
                || signed.signature().is_keychain()
            {
                return None;
            }
            aa_tx.nonce_key
        }
        TempoEvmTx::Eip7702(_) => return None,
        TempoEvmTx::Legacy { .. } | TempoEvmTx::Eip2930(_) | TempoEvmTx::Eip1559(_) => {
            if tx.access_list().is_some_and(|list| !list.is_empty()) {
                return None;
            }
            U256::ZERO
        }
    };
    let payments = tx
        .calls()
        .map(|(kind, input)| {
            let token = *kind.to().filter(|to| to.is_tip20())?;
            Some((token, PaymentSlots::classify(input)?))
        })
        .collect::<Option<Vec<_>>>()?;
    let first_token = payments.first()?.0;

    let mut access = AccessBuilder::default();

    // Fee collection.
    let fee_payer = tx.fee_payer().ok()?;
    let beneficiary = env.block.beneficiary;
    access.read(
        TIP_FEE_MANAGER_ADDRESS,
        beneficiary.mapping_slot(tip_fee_manager::slots::VALIDATOR_TOKENS),
    );
    let fee_token = tx.fee_token().or_else(|| {
        access.read(
            TIP_FEE_MANAGER_ADDRESS,
            fee_payer.mapping_slot(tip_fee_manager::slots::USER_TOKENS),
        );
        (fee_payer == sender && payments.iter().all(|(token, _)| *token == first_token))
            .then_some(first_token)
    });
    if let Some(fee_token) = fee_token {
        access.read(fee_token, tip20_slots::CURRENCY);
        access.read(fee_token, tip20_slots::PAUSED);
        access.write(fee_token, fee_payer.mapping_slot(tip20_slots::BALANCES));
        access.write(
            fee_token,
            TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES),
        );
        access.write(
            TIP_FEE_MANAGER_ADDRESS,
            fee_token
                .mapping_slot(beneficiary.mapping_slot(tip_fee_manager::slots::COLLECTED_FEES)),
        );
    }

    // Replay protection.
    if nonce_key.is_zero() {
        access.account_writes.push(sender);
    } else {
        access.reads.entry(sender).or_default();
        if nonce_key == TEMPO_EXPIRING_NONCE_KEY && env.spec.is_t1() {
            let replay_hash = if env.spec.is_t1b() {
                tx.unique_tx_identifier()
            } else {
                tx.tx_hash()
            };
            access.write(
                NONCE_PRECOMPILE_ADDRESS,
                nonce::slots::EXPIRING_NONCE_RING_PTR,
            );
            access.write(
                NONCE_PRECOMPILE_ADDRESS,
                replay_hash.mapping_slot(nonce::slots::EXPIRING_NONCE_SEEN),
            );
        } else {
            access.write(
                NONCE_PRECOMPILE_ADDRESS,
                nonce_key.mapping_slot(sender.mapping_slot(nonce::slots::NONCES)),
            );
        }
    }

    // Payment calls.
    for (token, payment) in payments {
        access.read(token, tip20_slots::PAUSED);
        // From T9 a registry binding overrides the policy ID stored on the token.
        if env.spec.is_t9() {
            access.read(
                TIP403_REGISTRY_ADDRESS,
                token.mapping_slot(tip403_registry_slots::TOKEN_TRANSFER_POLICIES),
            );
        } else {
            access.read(token, tip20_slots::TRANSFER_POLICY_ID);
        }
        let owner = payment.from().unwrap_or(sender);
        access.write(token, owner.mapping_slot(tip20_slots::BALANCES));
        // Before T8 transfers update the reward state of both holders.
        if !env.spec.is_t8() {
            access.read(token, tip20_slots::GLOBAL_REWARD_PER_TOKEN);
            for holder in core::iter::once(owner).chain(payment.to()) {
                let info = holder.mapping_slot(tip20_slots::USER_REWARD_INFO);
                for offset in 0..UserRewardInfo::SLOTS {
                    access.read(token, info + U256::from(offset));
                }
            }
        }
        if let Some(to) = payment.to() {
            access.write(token, to.mapping_slot(tip20_slots::BALANCES));
            if env.spec.is_t6() {
                access.read(
                    TIP403_REGISTRY_ADDRESS,
                    to.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES),
                );
            }
        }
        if let Some(from) = payment.from() {
            access.write(
                token,
                sender.mapping_slot(from.mapping_slot(tip20_slots::ALLOWANCES)),
            );
        }
    }

    Some(access.finish())
}

/// Collects the accounts and storage slots of a [`TxStateAccess`].
#[derive(Default)]
struct AccessBuilder {
    reads: AddressMap<B256Set>,
    writes: AddressMap<B256Set>,
    account_writes: Vec<Address>,
}

impl AccessBuilder {
    fn read(&mut self, address: Address, slot: U256) {
        self.reads.entry(address).or_default().insert(slot.into());
    }

    fn write(&mut self, address: Address, slot: U256) {
        self.writes.entry(address).or_default().insert(slot.into());
    }

    /// Returns the access, with every written slot left out of the reads.
    fn finish(mut self) -> TxStateAccess {
        for (address, written) in &self.writes {
            if let Some(read) = self.reads.get_mut(address) {
                read.retain(|slot| !written.contains(slot));
                if read.is_empty() {
                    self.reads.remove(address);
                }
            }
        }
        TxStateAccess {
            reads: access_list(self.reads),
            account_writes: self.account_writes,
            storage_writes: access_list(self.writes),
        }
    }
}

fn access_list(slots: AddressMap<B256Set>) -> AccessList {
    AccessList(
        slots
            .into_iter()
            .map(|(address, slots)| AccessListItem {
                address,
                storage_keys: slots.into_iter().collect::<Vec<B256>>(),
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TempoBlockEnv, TempoBlockExt, TempoEvmConfig, tempo_execution_config};
    use alloy_consensus::{SignableTransaction, TxEip1559, TxEip7702, TxLegacy};
    use alloy_primitives::{Signature, TxKind, map::HashSet};
    use alloy_sol_types::SolCall;
    use evm2::{
        DatabaseError,
        bytecode::Bytecode,
        evm::{AccountInfo, Database, InMemoryDB},
    };
    use reth_evm::{BlockExecutorFactory, ConfigureEvm, Evm as _};
    use std::{
        num::NonZeroU64,
        sync::{Arc, Mutex},
    };
    use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE};
    use tempo_contracts::precompiles::ITIP20;
    use tempo_precompiles::{
        PATH_USD_ADDRESS, nonce::NonceManager, storage::StorageCtx, test_util::TIP20Setup,
        tip_fee_manager::TipFeeManager, tip403_registry::TIP403Registry,
    };
    use tempo_primitives::{
        TempoSignature, TempoTransaction, TempoTxEnvelope,
        transaction::{Call, tt_signature::PrimitiveSignature},
    };

    const CHAIN_ID: u64 = 1337;
    const TIMESTAMP: u64 = 1_700_000_000;
    const GAS_PRICE: u128 = 100_000_000_000;
    const OWNER: Address = Address::repeat_byte(0x10);
    const SENDER: Address = Address::repeat_byte(0x11);
    const RECIPIENT: Address = Address::repeat_byte(0x12);

    /// The accounts and storage slots a database served.
    #[derive(Default)]
    struct Reads {
        accounts: HashSet<Address>,
        storage: HashSet<(Address, B256)>,
    }

    /// Database that records the state execution reads from it.
    struct RecordingDb {
        db: InMemoryDB,
        reads: Arc<Mutex<Reads>>,
    }

    impl Database for RecordingDb {
        type Error = DatabaseError;

        fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
            self.reads.lock().unwrap().accounts.insert(*address);
            self.db.get_account(address)
        }

        fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
            self.db.get_code_by_hash(code_hash)
        }

        fn get_storage(&mut self, address: &Address, key: &U256) -> Result<U256, Self::Error> {
            self.reads
                .lock()
                .unwrap()
                .storage
                .insert((*address, B256::from(*key)));
            self.db.get_storage(address, key)
        }

        fn get_block_hash(&mut self, number: &U256) -> Result<B256, Self::Error> {
            self.db.get_block_hash(number)
        }
    }

    fn evm_env(spec: TempoHardfork) -> TempoEvmEnv {
        let mut version = *tempo_execution_config(spec, CHAIN_ID).version();
        version.tx_gas_limit_cap = spec.tx_gas_limit_cap().unwrap_or(u64::MAX);
        TempoEvmEnv {
            spec,
            version,
            block: TempoBlockEnv {
                number: U256::ONE,
                beneficiary: Address::repeat_byte(0x42),
                timestamp: U256::from(TIMESTAMP),
                basefee: U256::from(TEMPO_T1_BASE_FEE),
                gas_limit: U256::from(10_000_000_000u64),
                ext: TempoBlockExt::default(),
                ..Default::default()
            },
        }
    }

    /// Returns pathUSD state in which [`SENDER`] and [`OWNER`] hold tokens and [`OWNER`] lets
    /// [`SENDER`] spend them.
    fn seeded_db(spec: TempoHardfork) -> InMemoryDB {
        let mut evm =
            TempoEvmConfig::moderato().evm_with_database(InMemoryDB::default(), evm_env(spec));
        StorageCtx::enter_evm(&mut evm, || {
            TIP403Registry::new().initialize()?;
            TipFeeManager::new().initialize()?;
            NonceManager::new().initialize()?;
            TIP20Setup::path_usd(OWNER)
                .with_issuer(OWNER)
                .with_mint(OWNER, U256::from(u64::MAX))
                .with_mint(SENDER, U256::from(u64::MAX))
                .with_approval(OWNER, SENDER, U256::from(u64::MAX))
                .apply()
                .map(drop)
        })
        .unwrap();
        evm.state_mut().commit_transaction();
        evm.state_mut().clear_transaction_state();
        InMemoryDB {
            cache: evm.overlay_db().cache.clone(),
            ..Default::default()
        }
    }

    fn aa_tx(nonce_key: U256, fee_token: Option<Address>, calls: Vec<Call>) -> TempoTransaction {
        TempoTransaction {
            chain_id: CHAIN_ID,
            fee_token,
            max_priority_fee_per_gas: GAS_PRICE,
            max_fee_per_gas: GAS_PRICE,
            gas_limit: 2_000_000,
            calls,
            nonce_key,
            valid_before: NonZeroU64::new(TIMESTAMP + 10),
            ..Default::default()
        }
    }

    fn payment_call(input: Vec<u8>) -> Call {
        Call {
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
        }
    }

    fn recovered_aa(tx: TempoTransaction) -> Recovered<TempoTxEnvelope> {
        let signature =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        Recovered::new_unchecked(TempoTxEnvelope::AA(tx.into_signed(signature)), SENDER)
    }

    fn transfer() -> Vec<u8> {
        ITIP20::transferCall {
            to: RECIPIENT,
            amount: U256::from(5),
        }
        .abi_encode()
    }

    fn slots(list: &AccessList) -> HashSet<(Address, B256)> {
        list.iter()
            .flat_map(|item| item.storage_keys.iter().map(|slot| (item.address, *slot)))
            .collect()
    }

    /// Executes `tx` and checks the derived access against the state it accessed.
    fn assert_access_matches_execution(spec: TempoHardfork, tx: Recovered<TempoTxEnvelope>) {
        let config = TempoEvmConfig::moderato();
        let env = evm_env(spec);
        let tx_env = Recovered::new_unchecked(TempoTxEnv::from(tx.clone()), tx.signer());
        let access = config
            .tx_state_access(&env, &tx_env)
            .expect("payment access is derived");

        let reads = Arc::<Mutex<Reads>>::default();
        let db = RecordingDb {
            db: seeded_db(spec),
            reads: Arc::clone(&reads),
        };
        let mut evm = config.evm_with_database(db, env);
        let (success, storage_writes, account_writes) = evm
            .transact_and_discard(&tx_env, |executed| {
                let mut storage_writes = HashSet::default();
                let mut account_writes = HashSet::default();
                for changes in executed.account_changes() {
                    if changes.original != changes.current {
                        account_writes.insert(changes.address);
                    }
                    for (slot, _) in changes.storage.changed_slots() {
                        storage_writes.insert((changes.address, B256::from(*slot)));
                    }
                }
                (executed.result().status, storage_writes, account_writes)
            })
            .unwrap();
        assert!(success, "{spec:?}: transaction reverted");
        let reads = reads.lock().unwrap();

        // The expiring nonce ring entry is the only written slot whose location depends on state.
        let ring_entry = (
            NONCE_PRECOMPILE_ADDRESS,
            B256::from(0u32.mapping_slot(nonce::slots::EXPIRING_NONCE_RING)),
        );
        let derived_writes = slots(&access.storage_writes);
        let mut expected_writes = storage_writes;
        expected_writes.remove(&ring_entry);
        assert_eq!(derived_writes, expected_writes, "{spec:?}: storage writes");
        assert_eq!(
            access
                .account_writes
                .iter()
                .copied()
                .collect::<HashSet<_>>(),
            account_writes,
            "{spec:?}: account writes"
        );

        let derived_reads = slots(&access.reads);
        assert!(
            derived_reads.is_subset(&reads.storage),
            "{spec:?}: derived reads not read: {:?}",
            derived_reads.difference(&reads.storage).collect::<Vec<_>>()
        );
        // Execution also reads the policies the TIP-403 registry entries point to.
        let missed = reads
            .storage
            .iter()
            .filter(|read| {
                !derived_reads.contains(read)
                    && !derived_writes.contains(read)
                    && **read != ring_entry
                    && read.0 != TIP403_REGISTRY_ADDRESS
            })
            .collect::<Vec<_>>();
        assert!(missed.is_empty(), "{spec:?}: reads not derived: {missed:?}");

        let derived_accounts = access
            .reads
            .iter()
            .chain(access.storage_writes.iter())
            .map(|item| item.address)
            .chain(access.account_writes.iter().copied())
            .collect::<HashSet<_>>();
        assert!(
            derived_accounts.is_subset(&reads.accounts),
            "{spec:?}: derived accounts not loaded"
        );
    }

    #[test]
    fn payment_state_access_matches_execution() {
        let transfer_from = ITIP20::transferFromCall {
            from: OWNER,
            to: RECIPIENT,
            amount: U256::from(5),
        }
        .abi_encode();
        for spec in [
            TempoHardfork::T0,
            TempoHardfork::T1,
            TempoHardfork::T13,
            TempoHardfork::T15,
        ] {
            for tx in [
                // Expiring nonce, which is a 2D nonce key before T1.
                recovered_aa(aa_tx(
                    TEMPO_EXPIRING_NONCE_KEY,
                    Some(PATH_USD_ADDRESS),
                    vec![payment_call(transfer())],
                )),
                // 2D nonce, fee token inferred from the call.
                recovered_aa(aa_tx(U256::from(7), None, vec![payment_call(transfer())])),
                // Protocol nonce.
                recovered_aa(aa_tx(
                    U256::ZERO,
                    Some(PATH_USD_ADDRESS),
                    vec![
                        payment_call(transfer()),
                        payment_call(transfer_from.clone()),
                    ],
                )),
            ] {
                assert_access_matches_execution(spec, tx);
            }
            let legacy = TxLegacy {
                chain_id: Some(CHAIN_ID),
                gas_price: GAS_PRICE,
                gas_limit: 2_000_000,
                to: TxKind::Call(PATH_USD_ADDRESS),
                input: transfer().into(),
                ..Default::default()
            };
            assert_access_matches_execution(
                spec,
                Recovered::new_unchecked(
                    TempoTxEnvelope::Legacy(legacy.into_signed(Signature::test_signature())),
                    SENDER,
                ),
            );
        }
    }

    #[test]
    fn non_derivable_transactions_have_no_access() {
        let env = evm_env(TempoHardfork::T15);
        let config = TempoEvmConfig::moderato();
        let access_list = AccessList(vec![AccessListItem {
            address: PATH_USD_ADDRESS,
            storage_keys: Vec::new(),
        }]);
        let non_payment = ITIP20::claimRewardsCall {}.abi_encode();
        let to_contract = Call {
            to: TxKind::Call(Address::repeat_byte(1)),
            ..payment_call(transfer())
        };
        let eip1559 = TxEip1559 {
            chain_id: CHAIN_ID,
            to: TxKind::Call(PATH_USD_ADDRESS),
            input: transfer().into(),
            access_list: access_list.clone(),
            ..Default::default()
        };
        let eip7702 = TxEip7702 {
            chain_id: CHAIN_ID,
            to: PATH_USD_ADDRESS,
            input: transfer().into(),
            ..Default::default()
        };
        for (case, tx) in [
            ("no calls", recovered_aa(aa_tx(U256::ONE, None, Vec::new()))),
            (
                "non-payment call",
                recovered_aa(aa_tx(U256::ONE, None, vec![payment_call(non_payment)])),
            ),
            (
                "non-TIP-20 target",
                recovered_aa(aa_tx(U256::ONE, None, vec![to_contract])),
            ),
            (
                "AA access list",
                recovered_aa(TempoTransaction {
                    access_list,
                    ..aa_tx(U256::ONE, None, vec![payment_call(transfer())])
                }),
            ),
            (
                "EIP-1559 access list",
                Recovered::new_unchecked(
                    TempoTxEnvelope::Eip1559(eip1559.into_signed(Signature::test_signature())),
                    SENDER,
                ),
            ),
            (
                "EIP-7702",
                Recovered::new_unchecked(
                    TempoTxEnvelope::Eip7702(eip7702.into_signed(Signature::test_signature())),
                    SENDER,
                ),
            ),
        ] {
            let tx_env = Recovered::new_unchecked(TempoTxEnv::from(tx.clone()), tx.signer());
            assert_eq!(config.tx_state_access(&env, &tx_env), None, "{case}");
        }
    }
}
