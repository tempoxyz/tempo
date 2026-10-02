//! Verify archived EIP-1186 Earn account and storage proofs against one block root.

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use reth_trie_common::AccountProof;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("expected evidence JSON path")?;
    let evidence: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let root: B256 = evidence["stateRoot"]
        .as_str()
        .ok_or("missing stateRoot")?
        .parse()?;
    let proofs = evidence["proofs"].as_object().ok_or("missing proofs")?;
    let manifest = evidence["nativeEarnManifest"]
        .as_array()
        .ok_or("missing nativeEarnManifest")?;
    let mut storage_slots = 0;
    for (key, value) in proofs {
        let expected_address: Address = key.parse()?;
        let response: EIP1186AccountProofResponse = serde_json::from_value(value.clone())?;
        if response.address != expected_address {
            return Err(format!("proof address differs from map key {key}").into());
        }
        storage_slots += response.storage_proof.len();
        AccountProof::from_eip1186_proof(response).verify(root)?;
    }
    for entry in manifest {
        for (address_field, hash_field) in [
            ("vault", "vaultRuntimeHash"),
            ("vaultImplementation", "vaultImplementationHash"),
            ("fees", "feesRuntimeHash"),
            ("feesImplementation", "feesImplementationHash"),
            ("engine", "engineHash"),
        ] {
            let address = entry[address_field]
                .as_str()
                .ok_or("missing manifest address")?;
            let expected: B256 = entry[hash_field]
                .as_str()
                .ok_or("missing manifest code hash")?
                .parse()?;
            let actual: B256 = proof_for(proofs, address)?["codeHash"]
                .as_str()
                .ok_or("missing proof code hash")?
                .parse()?;
            if actual != expected {
                return Err(format!("{address_field} code hash differs from its proof").into());
            }
        }
        for (account_field, slot, value_field) in [
            (
                "vault",
                "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                Some("vaultImplementation"),
            ),
            ("vault", "0x0", Some("engine")),
            ("vault", "0x1", Some("asset")),
            ("vault", "0x2", Some("earnShare")),
            ("vault", "0x3", Some("fees")),
            ("fees", "0x0", Some("vault")),
            ("fees", "0x1", Some("earnShare")),
            (
                "fees",
                "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                None,
            ),
        ] {
            let address = entry[account_field]
                .as_str()
                .ok_or("missing manifest account")?;
            let storage = proof_for(proofs, address)?["storageProof"]
                .as_array()
                .ok_or("missing storage proofs")?;
            let proof = storage
                .iter()
                .find(|proof| proof["key"].as_str() == Some(slot))
                .ok_or("missing required storage proof")?;
            let actual: U256 = proof["value"]
                .as_str()
                .ok_or("missing storage value")?
                .parse()?;
            let expected = match value_field {
                Some(field) => {
                    let address: Address =
                        entry[field].as_str().ok_or("missing binding")?.parse()?;
                    U256::from_be_slice(address.as_slice())
                }
                None => U256::ZERO,
            };
            if actual != expected {
                return Err(format!("{account_field} slot {slot} differs from manifest").into());
            }
        }
    }
    let issuer = &evidence["earnShareIssuerRole"];
    let share = issuer["earnShare"].as_str().ok_or("missing issuer share")?;
    let vault: Address = issuer["vault"]
        .as_str()
        .ok_or("missing issuer vault")?
        .parse()?;
    let role: B256 = issuer["role"]
        .as_str()
        .ok_or("missing issuer role")?
        .parse()?;
    if role != keccak256(b"ISSUER_ROLE") {
        return Err("EarnShare issuer role is not canonical".into());
    }
    if !manifest.iter().any(|entry| {
        entry["vault"].as_str() == issuer["vault"].as_str()
            && entry["earnShare"].as_str() == Some(share)
    }) {
        return Err("issuer role binding differs from manifest".into());
    }
    let mut outer_input = [0u8; 64];
    outer_input[12..32].copy_from_slice(vault.as_slice());
    let outer_slot = keccak256(outer_input);
    let mut inner_input = [0u8; 64];
    inner_input[..32].copy_from_slice(role.as_slice());
    inner_input[32..].copy_from_slice(outer_slot.as_slice());
    let expected_slot = keccak256(inner_input);
    let actual_slot: B256 = issuer["slot"]
        .as_str()
        .ok_or("missing issuer slot")?
        .parse()?;
    if actual_slot != expected_slot {
        return Err("EarnShare issuer role proof slot differs from binding".into());
    }
    let proof = proof_for(proofs, share)?["storageProof"]
        .as_array()
        .ok_or("missing EarnShare storage proofs")?
        .iter()
        .find(|proof| proof["key"].as_str() == issuer["slot"].as_str())
        .ok_or("missing EarnShare issuer role proof")?;
    let role_value: U256 = proof["value"]
        .as_str()
        .ok_or("missing issuer value")?
        .parse()?;
    if role_value != U256::from(1) {
        return Err("EarnVault lacks the proven issuer role".into());
    }
    println!(
        "verified {} account proofs, {} storage proofs, and {} manifest entries against {}",
        proofs.len(),
        storage_slots,
        manifest.len(),
        root
    );
    Ok(())
}

fn proof_for<'a>(
    proofs: &'a serde_json::Map<String, Value>,
    address: &str,
) -> Result<&'a Value, Box<dyn std::error::Error>> {
    proofs
        .get(&address.to_lowercase())
        .ok_or_else(|| format!("missing account proof for {address}").into())
}
