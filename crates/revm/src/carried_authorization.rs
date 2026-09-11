//! TIP-1086 transaction validation. The existing native verifier handles configurable roles.
use crate::{TempoInvalidTransaction, TempoTxEnv};
use alloy_rlp::Encodable;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::transaction::{
    PrimitiveSignature, SignedKeyAuthorization, TempoSignature,
    carried_authorization::MAX_CARRIED_AUTHORIZATION_BYTES,
};

pub(crate) fn invalid(reason: impl Into<String>) -> TempoInvalidTransaction {
    TempoInvalidTransaction::KeychainValidationFailed {
        reason: reason.into(),
    }
}

pub(crate) fn validate(
    tx: &TempoTxEnv,
    spec: TempoHardfork,
    chain: u64,
    now: u64,
) -> Result<(), TempoInvalidTransaction> {
    let Some(aa) = &tx.tempo_tx_env else {
        return Ok(());
    };
    let Some(auth) = &aa.key_authorization else {
        return Ok(());
    };
    let Some(carried) = &auth.carried else {
        if auth.tree.is_some() {
            return Err(invalid("tree requires carried policy"));
        }
        return Ok(());
    };
    if !spec.is_t12() {
        return Err(invalid("carried authorization is not active before T12"));
    }
    if auth.length() > MAX_CARRIED_AUTHORIZATION_BYTES {
        return Err(invalid("carried certificate exceeds size bound"));
    }
    carried
        .validate_policy(&auth.authorization)
        .map_err(invalid)?;
    if let Some(tree) = &auth.tree {
        if carried.authority_config.is_zero()
            || tree.witness.opening.authority != carried.authority_config
        {
            return Err(invalid("tree requires configurable parent authority"));
        }
        tree.open(
            auth.signature_hash(),
            auth.limits.as_ref().map_or(0, Vec::len),
        )
        .map_err(invalid)?;
    }
    if auth.chain_id != chain || auth.account != Some(tx.caller) {
        return Err(invalid("carried account or chain mismatch"));
    }
    if now < carried.valid_after {
        return Err(TempoInvalidTransaction::ValidAfter {
            current: now,
            valid_after: carried.valid_after,
        });
    }
    if now >= auth.expiry.expect("policy checked").get() {
        return Err(TempoInvalidTransaction::ValidBefore {
            current: now,
            valid_before: auth.expiry.expect("policy checked").get(),
        });
    }
    if !aa.tempo_authorization_list.is_empty() || aa.aa_calls.iter().any(|call| call.to.is_create())
    {
        return Err(invalid(
            "carried authorization forbids delegation and creation",
        ));
    }
    let key = aa
        .signature
        .as_keychain()
        .ok_or_else(|| invalid("carried certificate requires keychain transaction"))?;
    let key_id = aa
        .override_key_id
        .map(Ok)
        .unwrap_or_else(|| key.key_id(&aa.signature_hash))
        .map_err(|_| invalid("carried access key recovery failed"))?;
    if key.is_legacy()
        || key.user_address != tx.caller
        || key_id != auth.key_id
        || key.signature.key_type() != auth.key_type
    {
        return Err(invalid("carried access key mismatch"));
    }
    if auth.signature.is_keychain() {
        return Err(invalid("carried issuer must sign directly"));
    }
    Ok(())
}

fn primitive_crypto(signature: &PrimitiveSignature) -> u64 {
    match signature {
        PrimitiveSignature::Secp256k1(_) => 3_000,
        PrimitiveSignature::P256(_) => 8_000,
        PrimitiveSignature::WebAuthn(signature) => {
            8_000 + 6 * (signature.webauthn_data.len() as u64).div_ceil(32)
        }
    }
}

/// Full bytes charged once; native witness bytes and issuer WebAuthn bytes are not double billed.
pub(crate) fn intrinsic(auth: &SignedKeyAuthorization) -> u64 {
    let carried = auth.carried.as_ref().expect("carried mode");
    let bytes = alloy_rlp::encode(auth);
    let data: u64 = bytes
        .iter()
        .map(|byte| if *byte == 0 { 4 } else { 16 })
        .sum();
    let (tokens, scopes) = carried.entries(&auth.authorization);
    let crypto = match &auth.signature {
        TempoSignature::Primitive(signature) => primitive_crypto(signature),
        TempoSignature::Multisig(signature) => {
            use tempo_precompiles::native_multisig::keccak_cost;
            use tempo_primitives::transaction::multisig::MULTISIG_SIGNATURE_DOMAIN;
            signature
                .signatures()
                .iter()
                .map(primitive_crypto)
                .sum::<u64>()
                + keccak_cost(signature.config().commitment_preimage_len())
                + keccak_cost(MULTISIG_SIGNATURE_DOMAIN.len() + 32 + 20 + 8)
        }
        TempoSignature::Keychain(_) => 0, // rejected before execution
    };
    data + 80 * (bytes.len() as u64).div_ceil(32) + 20 * (tokens + scopes) + crypto + 2_000
}
