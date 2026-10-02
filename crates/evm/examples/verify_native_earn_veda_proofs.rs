//! Verify saved native Veda settlement account and binding proofs against one state root.

use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use reth_trie_common::AccountProof;
use serde_json::Value;
use std::io::Read;
use tempo_contracts::earn::{EARN_IMPLEMENTATION_SLOT, NATIVE_EARN_DISPATCHER_V1_HASH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let proof_path = args.next().ok_or("expected proof JSON path or -")?;
    let summary_path = args.next().ok_or("expected settlement summary JSON path")?;
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
    if root != text_at(&summary, "stateRoot")?.parse::<B256>()?
        || evidence["blockNumber"] != summary["proofBlock"]
    {
        return Err("proof block or state root differs from summary".into());
    }
    let proofs = evidence["proofs"]
        .as_object()
        .ok_or("missing account proofs")?;
    let mut storage_count = 0;
    for (name, value) in proofs {
        let address_key = if name == "registry" {
            "nativeRegistry"
        } else {
            name
        };
        let address: Address = text_at(&summary["addresses"], address_key)?.parse()?;
        let response: EIP1186AccountProofResponse = serde_json::from_value(value.clone())?;
        if response.address != address {
            return Err(format!("proof address differs for {name}").into());
        }
        storage_count += response.storage_proof.len();
        AccountProof::from_eip1186_proof(response).verify(root)?;
    }
    if proofs.len() != 9 || storage_count != 9 {
        return Err("unexpected proof coverage".into());
    }
    for name in ["vault", "fees", "forwarder"] {
        check_code(&proofs[name], NATIVE_EARN_DISPATCHER_V1_HASH)?;
    }
    check_code(
        &proofs["snapshot"],
        text_at(&summary, "forwarderOriginalCodeHash")?.parse()?,
    )?;
    check_code(
        &proofs["engine"],
        text_at(&summary, "engineCodeHash")?.parse()?,
    )?;

    let addr = |name: &str| -> Result<U256, Box<dyn std::error::Error>> {
        Ok(U256::from_be_slice(
            text_at(&summary["addresses"], name)?
                .parse::<Address>()?
                .as_slice(),
        ))
    };
    let implementation = |name: &str| -> Result<U256, Box<dyn std::error::Error>> {
        Ok(U256::from_be_slice(
            text_at(&summary, name)?.parse::<Address>()?.as_slice(),
        ))
    };
    for (account, expected) in [
        (
            "vault",
            [
                (
                    EARN_IMPLEMENTATION_SLOT,
                    implementation("vaultImplementation")?,
                ),
                (U256::ZERO, addr("engine")?),
                (U256::from(1), addr("asset")?),
                (U256::from(2), addr("earnShare")?),
                (U256::from(3), addr("fees")?),
            ]
            .as_slice(),
        ),
        (
            "fees",
            [
                (
                    EARN_IMPLEMENTATION_SLOT,
                    implementation("feesImplementation")?,
                ),
                (U256::ZERO, addr("vault")?),
                (U256::from(1), addr("earnShare")?),
            ]
            .as_slice(),
        ),
        (
            "forwarder",
            [(EARN_IMPLEMENTATION_SLOT, addr("snapshot")?)].as_slice(),
        ),
    ] {
        for (slot, value) in expected {
            check_slot(&proofs[account], *slot, *value)?;
        }
    }
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
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            format!("missing slot proof for {slot}").into()
        })?;
    if text_at(actual, "value")?.parse::<U256>()? != expected {
        return Err(format!("storage value differs at slot {slot}").into());
    }
    Ok(())
}
