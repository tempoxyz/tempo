use reth_errors::RethError;
use reth_evm::revm::Database;
use reth_rpc_eth_types::EthApiError;
use tempo_alloy::rpc::{TempoTransactionRequest, create_mock_native_multisig_signature};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{
    native_multisig::{NativeMultisig, NativeMultisigAuthError},
    storage::StorageActions,
};
use tempo_primitives::transaction::MultisigSignature;

/// Builds the mock signature and validates its config witnesses against current state.
pub(super) fn prepare_native_multisig_simulation(
    request: &mut TempoTransactionRequest,
    hardfork: TempoHardfork,
    db: &mut impl Database,
) -> Result<(), EthApiError> {
    let Some(signature) = replace_multisig_spec_with_mock_signature(request)? else {
        return Ok(());
    };
    db.with_read_only_storage_ctx(hardfork, StorageActions::disabled(), || {
        NativeMultisig::new().validate_authorization_state(signature)
    })
    .map_err(map_validation_error)
}

/// Replaces the public simulation spec with the internal signature used by request conversion.
pub(super) fn replace_multisig_spec_with_mock_signature(
    request: &mut TempoTransactionRequest,
) -> Result<Option<&MultisigSignature>, EthApiError> {
    let Some(spec) = request.multisig_simulation.as_ref() else {
        return Ok(None);
    };
    if request.key_id.is_some() {
        return Err(EthApiError::InvalidParams(
            "keyId cannot be combined with a native multisig spec".to_string(),
        ));
    }
    let account = request.inner.from.ok_or_else(|| {
        EthApiError::InvalidParams("native multisig simulation requires from".to_string())
    })?;

    let signature =
        create_mock_native_multisig_signature(account, spec).map_err(EthApiError::InvalidParams)?;
    request.multisig_simulation = None;
    request.multisig_simulation_signature = Some(signature);
    Ok(request.multisig_simulation_signature.as_ref())
}

fn map_validation_error(error: NativeMultisigAuthError) -> EthApiError {
    match error {
        NativeMultisigAuthError::Fatal(reason) => EthApiError::Internal(RethError::msg(reason)),
        error => EthApiError::InvalidParams(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use reth_errors::ProviderError;
    use reth_evm::revm::{bytecode::Bytecode, state::AccountInfo};
    use std::collections::HashMap;
    use tempo_alloy::rpc::{
        MultisigSimulationApproval, MultisigSimulationNestedSpec,
        MultisigSimulationPrimitiveApproval, MultisigSimulationSpec,
    };
    use tempo_precompiles::NATIVE_MULTISIG_ADDRESS;
    use tempo_primitives::transaction::{
        MultisigConfig, MultisigOwner, MultisigQuorumError, PrimitiveSignature, SignatureType,
        TempoSignature,
    };

    #[derive(Default)]
    struct SlotDb(HashMap<U256, U256>);

    impl SlotDb {
        fn insert_commitment(&mut self, account: Address, commitment: B256) {
            self.0.insert(
                NativeMultisig::config_commitment_storage_slot(account),
                U256::from_be_slice(commitment.as_slice()),
            );
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

    fn spec(version: u64) -> (Address, MultisigSimulationSpec) {
        let owner = Address::repeat_byte(0x11);
        let config = MultisigConfig {
            salt: B256::repeat_byte(0x55),
            version,
            threshold: 1,
            owners: vec![MultisigOwner { owner, weight: 1 }],
        };
        let account = if version == 0 {
            config.derive_account().unwrap()
        } else {
            Address::repeat_byte(0x22)
        };
        (
            account,
            MultisigSimulationSpec {
                config,
                approvals: vec![MultisigSimulationApproval::Primitive(
                    MultisigSimulationPrimitiveApproval {
                        owner,
                        key_type: Some(SignatureType::Secp256k1),
                        key_data: None,
                    },
                )],
            },
        )
    }

    fn request(account: Address, spec: MultisigSimulationSpec) -> TempoTransactionRequest {
        TempoTransactionRequest {
            inner: alloy_rpc_types_eth::TransactionRequest {
                from: Some(account),
                ..Default::default()
            },
            multisig_simulation: Some(spec),
            ..Default::default()
        }
    }

    #[test]
    fn prepares_initial_spec_against_zero_commitment() {
        let (account, spec) = spec(0);
        let mut request = request(account, spec);
        prepare_native_multisig_simulation(
            &mut request,
            TempoHardfork::T12,
            &mut SlotDb::default(),
        )
        .unwrap();
        assert!(request.multisig_simulation.is_none());
        assert!(request.multisig_simulation_signature.is_some());
    }

    #[test]
    fn current_spec_requires_matching_commitment() {
        let (account, spec) = spec(1);
        let mut db = SlotDb::default();
        db.insert_commitment(account, spec.config.commitment().unwrap());
        let mut request = request(account, spec);

        prepare_native_multisig_simulation(&mut request, TempoHardfork::T12, &mut db).unwrap();
        assert!(request.multisig_simulation.is_none());
        assert!(request.multisig_simulation_signature.is_some());
    }

    #[test]
    fn validates_nested_spec_commitments() {
        let nested_owner = Address::repeat_byte(0x11);
        let nested = MultisigSimulationNestedSpec {
            account: Address::repeat_byte(0x22),
            config: MultisigConfig {
                salt: B256::repeat_byte(0x44),
                version: 1,
                threshold: 1,
                owners: vec![MultisigOwner {
                    owner: nested_owner,
                    weight: 1,
                }],
            },
            approvals: vec![MultisigSimulationPrimitiveApproval {
                owner: nested_owner,
                key_type: Some(SignatureType::P256),
                key_data: None,
            }],
        };
        let account = Address::repeat_byte(0x33);
        let spec = MultisigSimulationSpec {
            config: MultisigConfig {
                salt: B256::repeat_byte(0x55),
                version: 1,
                threshold: 1,
                owners: vec![MultisigOwner {
                    owner: nested.account,
                    weight: 1,
                }],
            },
            approvals: vec![MultisigSimulationApproval::Multisig {
                spec: nested.clone(),
            }],
        };
        let mut db = SlotDb::default();
        db.insert_commitment(account, spec.config.commitment().unwrap());
        db.insert_commitment(nested.account, nested.config.commitment().unwrap());
        let mut request = request(account, spec);

        prepare_native_multisig_simulation(&mut request, TempoHardfork::T12, &mut db).unwrap();
        assert!(request.multisig_simulation.is_none());
        let signature = request.multisig_simulation_signature.as_ref().unwrap();
        assert!(matches!(
            signature.signatures(),
            [TempoSignature::Multisig(nested)]
                if matches!(
                    nested.signatures(),
                    [TempoSignature::Primitive(PrimitiveSignature::P256(_))]
                )
        ));
    }

    #[test]
    fn rejects_invalid_specs() {
        let invalid_params = |mut request: TempoTransactionRequest, mut db: SlotDb| {
            match prepare_native_multisig_simulation(&mut request, TempoHardfork::T12, &mut db) {
                Err(EthApiError::InvalidParams(error)) => error,
                result => panic!("unexpected result: {result:?}"),
            }
        };

        let (_, simulation) = spec(0);
        let missing_sender = TempoTransactionRequest {
            multisig_simulation: Some(simulation),
            ..Default::default()
        };
        assert_eq!(
            invalid_params(missing_sender, SlotDb::default()),
            "native multisig simulation requires from"
        );

        let (account, simulation) = spec(0);
        let mut with_key_id = request(account, simulation);
        with_key_id.key_id = Some(Address::repeat_byte(0x44));
        assert_eq!(
            invalid_params(with_key_id, SlotDb::default()),
            "keyId cannot be combined with a native multisig spec"
        );

        let (account, mut excess) = spec(1);
        let extra_owner = Address::repeat_byte(0x33);
        excess.config.owners.push(MultisigOwner {
            owner: extra_owner,
            weight: 1,
        });
        excess.approvals.push(MultisigSimulationApproval::Primitive(
            MultisigSimulationPrimitiveApproval {
                owner: extra_owner,
                key_type: Some(SignatureType::Secp256k1),
                key_data: None,
            },
        ));
        assert_eq!(
            invalid_params(request(account, excess), SlotDb::default()),
            MultisigQuorumError::ExcessSignatures.to_string()
        );

        let (account, simulation) = spec(1);
        let actual = simulation.config.commitment().unwrap();
        assert_eq!(
            invalid_params(request(account, simulation), SlotDb::default()),
            format!(
                "multisig configuration commitment mismatch: expected {}, actual {actual}",
                B256::ZERO
            )
        );
    }
}
