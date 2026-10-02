//! Verify saved post-T16 factory account and storage proofs against one state root.

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use reth_trie_common::AccountProof;
use serde_json::Value;
use std::io::Read;
use tempo_contracts::earn::{
    EARN_IMPLEMENTATION_SLOT, EarnRegistrationField, NATIVE_EARN_DISPATCHER_V1_HASH,
    earn_engine_approval_slot, earn_registration_slot, earn_share_issuer_role_slot, factory_slots,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let proof_path = args
        .next()
        .ok_or("expected proof JSON path or - for stdin")?;
    let summary_path = args.next().ok_or("expected summary JSON path")?;
    let proof_bytes = if proof_path == "-" {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes)?;
        bytes
    } else {
        std::fs::read(proof_path)?
    };
    let evidence: Value = serde_json::from_slice(&proof_bytes)?;
    let summary: Value = serde_json::from_slice(&std::fs::read(summary_path)?)?;
    let root: B256 = text_at(&evidence, "stateRoot")?.parse()?;
    if root != text_at(&summary["stateProof"], "stateRoot")?.parse::<B256>()? {
        return Err("proof root differs from summary".into());
    }
    let proofs = evidence["proofs"]
        .as_object()
        .ok_or("missing account proofs")?;
    let mut storage_count = 0;
    for (name, value) in proofs {
        let expected: Address = match name.as_str() {
            "registry" => "0x5aea000000000000000000000000000000000000".parse()?,
            "earnShare" => text_at(&summary, "earnShare")?.parse()?,
            "vault" | "fees" | "engine" | "venue" => text_at(&summary, name)?.parse()?,
            _ => return Err(format!("unexpected account proof {name}").into()),
        };
        let response: EIP1186AccountProofResponse = serde_json::from_value(value.clone())?;
        if response.address != expected {
            return Err(format!("proof address differs for {name}").into());
        }
        storage_count += response.storage_proof.len();
        AccountProof::from_eip1186_proof(response).verify(root)?;
    }
    if proofs.len() != 6 || storage_count != 38 {
        return Err("unexpected proof coverage".into());
    }

    let registry = &proofs["registry"];
    let vault = &proofs["vault"];
    let fees = &proofs["fees"];
    let share = &proofs["earnShare"];
    let engine = &proofs["engine"];
    let vault_addr: Address = text_at(&summary, "vault")?.parse()?;
    let fees_addr: Address = text_at(&summary, "fees")?.parse()?;
    let asset_addr: Address = text_at(&summary, "asset")?.parse()?;
    let share_addr: Address = text_at(&summary, "earnShare")?.parse()?;
    let engine_addr: Address = text_at(&summary, "engine")?.parse()?;
    let factory_addr: Address = text_at(&summary, "factory")?.parse()?;
    let vault_impl: Address = text_at(&summary, "factoryVaultImplementation")?.parse()?;
    let fees_impl: Address = text_at(&summary, "factoryFeesImplementation")?.parse()?;
    let factory_hash: B256 = text_at(&summary, "factoryCodeHash")?.parse()?;
    let vault_impl_hash: B256 = text_at(&summary, "factoryVaultImplementationHash")?.parse()?;
    let vault_runtime_hash: B256 = text_at(&summary, "factoryVaultRuntimeHash")?.parse()?;
    let fees_impl_hash: B256 = text_at(&summary, "factoryFeesImplementationHash")?.parse()?;
    let engine_hash: B256 = text_at(&summary, "engineHash")?.parse()?;

    check_code(registry, keccak256([0xef]))?;
    check_code(vault, NATIVE_EARN_DISPATCHER_V1_HASH)?;
    check_code(fees, NATIVE_EARN_DISPATCHER_V1_HASH)?;
    check_code(engine, engine_hash)?;
    for (slot, value) in [
        (factory_slots::ADDRESS, address_word(factory_addr)),
        (factory_slots::CODE_HASH, hash_word(factory_hash)),
        (
            factory_slots::VAULT_RUNTIME_HASH,
            hash_word(vault_runtime_hash),
        ),
        (
            factory_slots::VAULT_IMPLEMENTATION,
            address_word(vault_impl),
        ),
        (
            factory_slots::VAULT_IMPLEMENTATION_HASH,
            hash_word(vault_impl_hash),
        ),
        (factory_slots::FEES_IMPLEMENTATION, address_word(fees_impl)),
        (
            factory_slots::FEES_IMPLEMENTATION_HASH,
            hash_word(fees_impl_hash),
        ),
        (
            earn_engine_approval_slot(engine_addr),
            hash_word(engine_hash),
        ),
    ] {
        check_slot(registry, slot, value)?;
    }
    for (account, expected) in [
        (
            vault_addr,
            [
                U256::ONE,
                address_word(fees_addr),
                address_word(vault_impl),
                hash_word(vault_impl_hash),
                address_word(asset_addr),
                address_word(share_addr),
                hash_word(engine_hash),
            ],
        ),
        (
            fees_addr,
            [
                U256::from(2),
                address_word(vault_addr),
                address_word(fees_impl),
                hash_word(fees_impl_hash),
                address_word(asset_addr),
                address_word(share_addr),
                U256::ZERO,
            ],
        ),
    ] {
        for (field, value) in [
            EarnRegistrationField::Kind,
            EarnRegistrationField::Pair,
            EarnRegistrationField::Implementation,
            EarnRegistrationField::ImplementationHash,
            EarnRegistrationField::Asset,
            EarnRegistrationField::EarnShare,
            EarnRegistrationField::EngineHash,
        ]
        .into_iter()
        .zip(expected)
        {
            check_slot(registry, earn_registration_slot(account, field), value)?;
        }
    }
    for (slot, value) in [
        (EARN_IMPLEMENTATION_SLOT, address_word(vault_impl)),
        (U256::ZERO, address_word(engine_addr)),
        (U256::from(1), address_word(asset_addr)),
        (U256::from(2), address_word(share_addr)),
        (U256::from(3), address_word(fees_addr)),
    ] {
        check_slot(vault, slot, value)?;
    }
    for (slot, value) in [
        (EARN_IMPLEMENTATION_SLOT, address_word(fees_impl)),
        (U256::ZERO, address_word(vault_addr)),
        (U256::from(1), address_word(share_addr)),
    ] {
        check_slot(fees, slot, value)?;
    }
    check_slot(share, earn_share_issuer_role_slot(vault_addr), U256::ONE)?;
    println!(
        "verified {} account and {} storage proofs against {root}",
        proofs.len(),
        storage_count
    );
    Ok(())
}

fn text_at<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing {key}").into())
}

fn address_word(address: Address) -> U256 {
    U256::from_be_slice(address.as_slice())
}

fn hash_word(hash: B256) -> U256 {
    U256::from_be_slice(hash.as_slice())
}

fn check_code(proof: &Value, expected: B256) -> Result<(), Box<dyn std::error::Error>> {
    if text_at(proof, "codeHash")?.parse::<B256>()? != expected {
        return Err("account code hash differs from approved identity".into());
    }
    Ok(())
}

fn check_slot(proof: &Value, slot: U256, expected: U256) -> Result<(), Box<dyn std::error::Error>> {
    let slots = proof["storageProof"]
        .as_array()
        .ok_or("missing storageProof")?;
    let actual = slots
        .iter()
        .find(|item| {
            item["key"]
                .as_str()
                .and_then(|text| text.parse::<U256>().ok())
                == Some(slot)
        })
        .ok_or_else(|| format!("missing slot proof for {slot}"))?;
    if text_at(actual, "value")?.parse::<U256>()? != expected {
        return Err(format!("storage value differs at slot {slot}").into());
    }
    Ok(())
}
