use alloy_primitives::{Address, B256};
use reth_errors::RethError;
use reth_evm::revm::Database;
use reth_rpc_eth_types::EthApiError;
use tempo_alloy::rpc::{
    MultisigSimulationApproval, MultisigSimulationHint, TempoTransactionRequest,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{
    ECRECOVER_GAS, error::TempoPrecompileError, native_multisig::NativeMultisig,
    storage::StorageActions,
};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_NESTING_DEPTH, MAX_MULTISIG_SIGNATURES,
    MAX_WEBAUTHN_SIGNATURE_LENGTH, SignatureType,
};
use tempo_revm::{
    NATIVE_MULTISIG_NESTED_ACCOUNT_GAS, NATIVE_MULTISIG_OWNER_WEIGHT_GAS,
    NATIVE_MULTISIG_VALIDATION_GAS, P256_VERIFY_GAS,
    native_multisig_complete_config_validation_gas,
};

pub(super) fn populate_native_multisig_simulation_hints(
    request: &mut TempoTransactionRequest,
    spec: TempoHardfork,
    db: &mut impl Database,
) -> Result<(), EthApiError> {
    if request.from.is_none()
        || request.key_id.is_some()
        || request.multisig_simulation_hint.is_some()
    {
        return Ok(());
    }

    db.with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
        populate_native_multisig_simulation_hints_inner(request)
    })
}

fn populate_native_multisig_simulation_hints_inner(
    request: &mut TempoTransactionRequest,
) -> Result<(), EthApiError> {
    let from = request
        .from
        .expect("checked before entering storage context");

    if let Some(hint) =
        load_native_multisig_simulation_hint_at_depth(from, 1, request.multisig_signature_count)?
    {
        // `multisig_init` is advisory: a registered sender cannot re-init, so the stored config
        // wins and the bootstrap hint is dropped.
        request.multisig_init = None;
        if request.multisig_signature_count.is_none() {
            request.multisig_signature_count = Some(hint.approvals.len());
        }
        request.multisig_simulation_hint = Some(hint);
        return Ok(());
    }

    if let Some(init) = request.multisig_init.as_ref() {
        let hint = native_multisig_simulation_hint_for_config(
            init.account()
                .map_err(|err| EthApiError::InvalidParams(err.to_string()))?,
            init,
            1,
            request.multisig_signature_count,
        )?;
        if request.multisig_signature_count.is_none() {
            request.multisig_signature_count = Some(hint.approvals.len());
        }
        request.multisig_simulation_hint = Some(hint);
    }

    Ok(())
}

fn load_native_multisig_simulation_hint_at_depth(
    account: Address,
    depth: usize,
    signature_count: Option<usize>,
) -> Result<Option<MultisigSimulationHint>, EthApiError> {
    let Some(registered) = NativeMultisig::new()
        .load_registered_config_if_present(account)
        .map_err(map_config_load_error)?
    else {
        return Ok(None);
    };

    let config = InitMultisig {
        salt: B256::ZERO,
        threshold: registered.threshold,
        owners: registered.owners,
    };
    native_multisig_simulation_hint_for_config(account, &config, depth, signature_count).map(Some)
}

fn map_config_load_error(error: TempoPrecompileError) -> EthApiError {
    match error {
        error @ TempoPrecompileError::NativeMultisigError(_) => {
            EthApiError::InvalidParams(error.to_string())
        }
        TempoPrecompileError::Fatal(reason) => EthApiError::Internal(RethError::msg(reason)),
        error => EthApiError::Internal(RethError::msg(error.to_string())),
    }
}

fn native_multisig_simulation_hint_for_config(
    account: Address,
    config: &InitMultisig,
    depth: usize,
    signature_count: Option<usize>,
) -> Result<MultisigSimulationHint, EthApiError> {
    if signature_count.is_some_and(|count| count == 0 || count > MAX_MULTISIG_SIGNATURES) {
        return Err(EthApiError::InvalidParams(
            "invalid native multisig signature count".to_string(),
        ));
    }

    let mut owner_approvals = Vec::with_capacity(config.owners.len());
    for owner in &config.owners {
        let approval = if depth < MAX_MULTISIG_NESTING_DEPTH {
            load_native_multisig_simulation_hint_at_depth(owner.owner, depth + 1, None)?
                .map(Box::new)
                .map(MultisigSimulationApproval::Multisig)
                .unwrap_or(MultisigSimulationApproval::UnknownPrimitive)
        } else {
            MultisigSimulationApproval::UnknownPrimitive
        };
        owner_approvals.push(approval);
    }

    let approvals =
        select_native_multisig_simulation_approvals(config, owner_approvals, signature_count)?;

    Ok(MultisigSimulationHint {
        account,
        owner_count: config.owners.len(),
        approvals,
    })
}

#[derive(Clone, Copy)]
struct MultisigSimulationSelection {
    gas: u64,
    owner_indices: [usize; MAX_MULTISIG_SIGNATURES],
    len: usize,
}

fn select_native_multisig_simulation_approvals(
    config: &InitMultisig,
    owner_approvals: Vec<MultisigSimulationApproval>,
    signature_count: Option<usize>,
) -> Result<Vec<MultisigSimulationApproval>, EthApiError> {
    let threshold = usize::from(config.threshold);
    // Retain the highest-gas partial quorum for each signature-count and weight pair. Completed
    // candidates stop when they first reach the threshold, matching validation.
    let mut states = vec![vec![None; threshold]; MAX_MULTISIG_SIGNATURES + 1];
    states[0][0] = Some(MultisigSimulationSelection {
        gas: 0,
        owner_indices: [0; MAX_MULTISIG_SIGNATURES],
        len: 0,
    });
    let mut best: Option<MultisigSimulationSelection> = None;

    for (owner_index, (owner, approval)) in config.owners.iter().zip(&owner_approvals).enumerate() {
        // Walk backwards so this owner cannot be selected more than once.
        for count in (0..MAX_MULTISIG_SIGNATURES).rev() {
            for weight in (0..threshold).rev() {
                let Some(selection) = states[count][weight] else {
                    continue;
                };
                let next_count = count + 1;
                let mut candidate = selection;
                candidate.gas = candidate
                    .gas
                    .saturating_add(native_multisig_simulation_approval_gas(approval));
                candidate.owner_indices[count] = owner_index;
                candidate.len = next_count;

                let next_weight = weight.saturating_add(usize::from(owner.weight));
                if next_weight >= threshold {
                    if signature_count.is_none_or(|expected| expected == next_count)
                        && best
                            .as_ref()
                            .is_none_or(|current| candidate.gas > current.gas)
                    {
                        best = Some(candidate);
                    }
                } else if states[next_count][next_weight]
                    .as_ref()
                    .is_none_or(|current| candidate.gas > current.gas)
                {
                    states[next_count][next_weight] = Some(candidate);
                }
            }
        }
    }

    best.map(|selection| {
        selection.owner_indices[..selection.len]
            .iter()
            .map(|&index| owner_approvals[index].clone())
            .collect()
    })
    .ok_or_else(|| {
        let reason = signature_count.map_or_else(
            || "native multisig config cannot satisfy its threshold".to_string(),
            |count| format!("native multisig threshold cannot be satisfied by {count} signatures"),
        );
        EthApiError::InvalidParams(reason)
    })
}

fn native_multisig_simulation_approval_gas(approval: &MultisigSimulationApproval) -> u64 {
    const P256_OWNER_GAS: u64 = ECRECOVER_GAS + P256_VERIFY_GAS;
    const MAX_WEBAUTHN_GAS: u64 =
        P256_OWNER_GAS + (MAX_WEBAUTHN_SIGNATURE_LENGTH as u64 - 128) * 16;

    let verification_gas = match approval {
        MultisigSimulationApproval::Primitive { key_type, .. } => match key_type {
            SignatureType::Secp256k1 => ECRECOVER_GAS,
            SignatureType::P256 => P256_OWNER_GAS,
            SignatureType::WebAuthn => MAX_WEBAUTHN_GAS,
        },
        MultisigSimulationApproval::UnknownPrimitive => MAX_WEBAUTHN_GAS,
        MultisigSimulationApproval::Multisig(hint) => NATIVE_MULTISIG_NESTED_ACCOUNT_GAS
            .saturating_add(NATIVE_MULTISIG_VALIDATION_GAS)
            .saturating_add(native_multisig_complete_config_validation_gas(
                hint.owner_count,
            ))
            .saturating_add(
                hint.approvals
                    .iter()
                    .map(native_multisig_simulation_approval_gas)
                    .fold(0u64, u64::saturating_add),
            ),
    };

    NATIVE_MULTISIG_OWNER_WEIGHT_GAS.saturating_add(verification_gas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{TxKind, U256};
    use alloy_rpc_types_eth::TransactionRequest;
    use reth_errors::ProviderError;
    use reth_evm::revm::{bytecode::Bytecode, state::AccountInfo};
    use std::collections::HashMap;
    use tempo_precompiles::NATIVE_MULTISIG_ADDRESS;
    use tempo_primitives::transaction::MultisigOwner;
    use tempo_revm::TempoTxEnv;

    #[derive(Default)]
    struct SlotDb(HashMap<U256, U256>);

    impl SlotDb {
        fn insert_u8(&mut self, (slot, offset): (U256, Option<usize>), value: u8) {
            *self.0.entry(slot).or_default() |=
                U256::from(value) << (offset.unwrap_or_default() * 8);
        }

        fn insert_address(&mut self, (slot, offset): (U256, Option<usize>), value: Address) {
            *self.0.entry(slot).or_default() |=
                U256::from_be_slice(value.as_slice()) << (offset.unwrap_or_default() * 8);
        }

        fn insert_config(&mut self, account: Address, threshold: u8, owners: &[(Address, u8)]) {
            self.insert_u8(
                NativeMultisig::account_threshold_storage_slot(account),
                threshold,
            );
            self.insert_u8(
                NativeMultisig::account_owners_len_storage_slot(account),
                owners.len() as u8,
            );
            let (version_slot, version_offset) =
                NativeMultisig::account_version_storage_slot(account);
            *self.0.entry(version_slot).or_default() |=
                U256::from(1) << (version_offset.unwrap_or_default() * 8);
            for (index, &(owner, weight)) in owners.iter().enumerate() {
                self.insert_address(
                    NativeMultisig::config_owner_address_storage_slot(account, index),
                    owner,
                );
                self.insert_u8(
                    NativeMultisig::config_owner_weight_storage_slot(account, index),
                    weight,
                );
                self.insert_u8(
                    NativeMultisig::config_owner_lookup_weight_storage_slot(account, owner),
                    weight,
                );
            }
        }

        fn registered_one_of_one(account: Address) -> Self {
            let mut db = Self::default();
            db.insert_config(account, 1, &[(Address::from([0x11; 20]), 1)]);
            db
        }
    }

    impl Database for SlotDb {
        type Error = ProviderError;

        fn basic(&mut self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(None)
        }

        fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(Bytecode::default())
        }

        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            debug_assert_eq!(address, NATIVE_MULTISIG_ADDRESS);
            Ok(self.0.get(&index).copied().unwrap_or_default())
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    fn with_storage<R>(db: &mut SlotDb, f: impl FnOnce() -> R) -> R {
        db.with_read_only_storage_ctx(TempoHardfork::T11, StorageActions::disabled(), f)
    }

    fn load_hint(
        db: &mut SlotDb,
        account: Address,
    ) -> Result<Option<MultisigSimulationHint>, EthApiError> {
        with_storage(db, || {
            load_native_multisig_simulation_hint_at_depth(account, 1, None)
        })
    }

    fn init_request(from: Address) -> TempoTransactionRequest {
        TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(from),
                ..Default::default()
            },
            multisig_init: Some(InitMultisig {
                salt: B256::ZERO,
                threshold: 1,
                owners: vec![MultisigOwner {
                    owner: Address::from([0x11; 20]),
                    weight: 1,
                }],
            }),
            ..Default::default()
        }
    }

    fn populate(request: &mut TempoTransactionRequest, db: &mut SlotDb) {
        populate_native_multisig_simulation_hints(request, TempoHardfork::T11, db).unwrap();
    }

    #[test]
    fn populate_drops_multisig_init_for_registered_senders() {
        let account = Address::from([0xaa; 20]);
        let mut db = SlotDb::registered_one_of_one(account);
        let hint = load_hint(&mut db, account)
            .unwrap()
            .expect("registered account hint");
        assert_eq!(hint.account, account);
        assert_eq!(hint.owner_count, 1);
        assert_eq!(
            hint.approvals,
            vec![MultisigSimulationApproval::UnknownPrimitive]
        );

        let mut request = init_request(account);
        populate(&mut request, &mut db);
        assert!(request.multisig_init.is_none());
        assert_eq!(request.multisig_signature_count, Some(1));
        assert_eq!(request.multisig_simulation_hint, Some(hint));
    }

    #[test]
    fn populate_keeps_multisig_init_for_unregistered_senders() {
        let account = Address::from([0xbb; 20]);
        let mut db = SlotDb::default();

        let mut request = init_request(account);
        populate(&mut request, &mut db);
        assert!(request.multisig_init.is_some());
        assert_eq!(request.multisig_signature_count, Some(1));
        assert!(request.multisig_simulation_hint.is_some());
    }

    #[test]
    fn populate_preserves_access_key_simulation_for_registered_multisig_sender() {
        let account = Address::from([0xaa; 20]);
        let key_id = Address::from([0xbb; 20]);
        let mut db = SlotDb::registered_one_of_one(account);
        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                to: Some(TxKind::Call(Address::from([0xcc; 20]))),
                ..Default::default()
            },
            key_id: Some(key_id),
            ..Default::default()
        };

        populate(&mut request, &mut db);
        assert!(request.multisig_signature_count.is_none());
        assert!(request.multisig_simulation_hint.is_none());

        let tx_env = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect("valid access-key simulation request");
        let aa_env = tx_env.tempo_tx_env.expect("AA simulation env");
        assert_eq!(aa_env.override_key_id, Some(key_id));
        assert!(aa_env.signature.is_v2_keychain());
    }

    #[test]
    fn populate_models_nested_multisig_approvals() {
        let account = Address::from([0xaa; 20]);
        let nested_account = Address::from([0x11; 20]);
        let mut db = SlotDb::default();
        db.insert_config(account, 1, &[(nested_account, 1)]);
        db.insert_config(
            nested_account,
            2,
            &[
                (Address::from([0x21; 20]), 1),
                (Address::from([0x22; 20]), 1),
            ],
        );

        for signature_count in [None, Some(1)] {
            let mut request = TempoTransactionRequest {
                inner: TransactionRequest {
                    from: Some(account),
                    ..Default::default()
                },
                multisig_signature_count: signature_count,
                ..Default::default()
            };
            populate(&mut request, &mut db);

            assert_eq!(request.multisig_signature_count, Some(1));
            let hint = request
                .multisig_simulation_hint
                .expect("registered account hint");
            assert_eq!(hint.account, account);
            assert_eq!(hint.owner_count, 1);
            assert_eq!(hint.approvals.len(), 1);
            let MultisigSimulationApproval::Multisig(nested) = &hint.approvals[0] else {
                panic!("registered threshold owner should use a nested approval");
            };
            assert_eq!(nested.account, nested_account);
            assert_eq!(nested.owner_count, 2);
            assert_eq!(
                nested.approvals,
                vec![
                    MultisigSimulationApproval::UnknownPrimitive,
                    MultisigSimulationApproval::UnknownPrimitive,
                ]
            );
        }
    }

    #[test]
    fn populate_uses_the_most_expensive_valid_quorum() {
        let account = Address::from([0xaa; 20]);
        let owners = (0..9)
            .map(|index| {
                (
                    Address::from([0x11 + index as u8; 20]),
                    if index == 0 { 8 } else { 1 },
                )
            })
            .collect::<Vec<_>>();
        let mut db = SlotDb::default();
        db.insert_config(account, 8, &owners);

        let mut conservative = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                ..Default::default()
            },
            ..Default::default()
        };
        populate(&mut conservative, &mut db);
        assert_eq!(conservative.multisig_signature_count, Some(8));
        assert_eq!(
            conservative
                .multisig_simulation_hint
                .as_ref()
                .unwrap()
                .approvals
                .len(),
            8
        );

        let mut explicit = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                ..Default::default()
            },
            multisig_signature_count: Some(1),
            ..Default::default()
        };
        populate(&mut explicit, &mut db);
        assert_eq!(explicit.multisig_signature_count, Some(1));
        assert_eq!(
            explicit
                .multisig_simulation_hint
                .as_ref()
                .unwrap()
                .approvals
                .len(),
            1
        );
    }

    #[test]
    fn populate_supports_threshold_above_signature_cap() {
        let account = Address::from([0xaa; 20]);
        let mut db = SlotDb::default();
        db.insert_config(account, u8::MAX, &[(Address::from([0x11; 20]), u8::MAX)]);

        let hint = load_hint(&mut db, account)
            .unwrap()
            .expect("registered account hint");

        assert_eq!(hint.approvals.len(), 1);
    }

    #[test]
    fn populate_prefers_the_more_expensive_approval_shape() {
        let account = Address::from([0xaa; 20]);
        let nested_account = Address::from([0x22; 20]);
        let mut db = SlotDb::default();
        db.insert_config(
            account,
            1,
            &[(Address::from([0x11; 20]), 1), (nested_account, 1)],
        );
        let nested_owners = (0..8)
            .map(|index| (Address::from([0x31 + index as u8; 20]), 1))
            .collect::<Vec<_>>();
        db.insert_config(nested_account, 8, &nested_owners);

        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                ..Default::default()
            },
            ..Default::default()
        };
        populate(&mut request, &mut db);

        assert_eq!(request.multisig_signature_count, Some(1));
        let hint = request
            .multisig_simulation_hint
            .expect("registered account hint");
        assert_eq!(hint.approvals.len(), 1);
        let MultisigSimulationApproval::Multisig(nested) = &hint.approvals[0] else {
            panic!("the higher-gas nested approval should be selected");
        };
        assert_eq!(nested.account, nested_account);
        assert_eq!(nested.approvals.len(), 8);
    }

    #[test]
    fn nested_simulation_approval_includes_account_access_gas() {
        let approval = MultisigSimulationApproval::Multisig(Box::new(MultisigSimulationHint {
            account: Address::from([0x22; 20]),
            owner_count: 1,
            approvals: vec![MultisigSimulationApproval::Primitive {
                key_type: SignatureType::Secp256k1,
                key_data: None,
            }],
        }));

        assert_eq!(
            native_multisig_simulation_approval_gas(&approval),
            2_100 + NATIVE_MULTISIG_NESTED_ACCOUNT_GAS + 2_100 + 4_200 + 2_100 + 3_000
        );
    }

    #[test]
    fn simulation_hints_reject_zero_config_version() {
        let account = Address::from([0xaa; 20]);
        let mut db = SlotDb::default();
        db.insert_u8(NativeMultisig::account_threshold_storage_slot(account), 1);
        db.insert_u8(NativeMultisig::account_owners_len_storage_slot(account), 1);

        assert!(matches!(
            load_hint(&mut db, account),
            Err(EthApiError::InvalidParams(_))
        ));
    }

    #[test]
    fn simulation_hints_reject_self_owned_config() {
        let account = Address::from([0xaa; 20]);
        let mut db = SlotDb::default();
        db.insert_config(account, 1, &[(account, 1)]);

        assert!(matches!(
            load_hint(&mut db, account),
            Err(EthApiError::InvalidParams(_))
        ));
    }

    #[test]
    fn simulation_hints_reject_nonzero_reserved_storage_bits() {
        let account = Address::from([0xaa; 20]);
        let owner = Address::from([0x11; 20]);
        let corrupted_slots = [
            NativeMultisig::account_threshold_storage_slot(account).0,
            NativeMultisig::config_owner_address_storage_slot(account, 0).0,
            NativeMultisig::config_owner_lookup_weight_storage_slot(account, owner).0,
        ];

        for corrupted_slot in corrupted_slots {
            let mut db = SlotDb::registered_one_of_one(account);
            *db.0.entry(corrupted_slot).or_default() |= U256::ONE << 255;
            assert!(matches!(
                load_hint(&mut db, account),
                Err(EthApiError::InvalidParams(_))
            ));
        }
    }
}
