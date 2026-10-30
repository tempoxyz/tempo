//! The authority a transaction's signatures name, for the configurable account checks.

use alloy_primitives::{Address, B256};
use tempo_invariants::account::{
    Approval, Authority, ConfigurableAccountConfig, ConfigurableAccountOwner, Grant, Key, Quorum,
    Role, spec,
};
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        AccountSignature, ConfigurableAccountSignature, KeychainSignature, TempoSignature,
    },
};

/// The accounts `tx`'s signatures act for, as sent by `sender`, in a block where
/// configurable accounts are `active` or not. A signer that does not recover is left out: the
/// transaction executed, so the executor recovered it, or did not need to.
pub(crate) fn authority(tx: &TempoTxEnvelope, sender: Address, active: bool) -> Authority {
    let mut authority = Authority {
        active,
        ..Default::default()
    };
    let key = |role, account| Key { role, account };
    let TempoTxEnvelope::AA(aa) = tx else {
        authority.keys.push(key(Role::Sender, sender));
        return authority;
    };
    let signature_hash = aa.signature_hash();
    match aa.signature() {
        TempoSignature::Primitive(_) => authority.keys.push(key(Role::Sender, sender)),
        TempoSignature::ConfigurableAccount(signature) => {
            authority
                .quorums
                .push(quorum(Role::Sender, signature, signature_hash));
        }
        TempoSignature::Keychain(keychain) => match &keychain.signature {
            AccountSignature::ConfigurableAccount(signature) => {
                let inner = KeychainSignature::signing_hash(signature_hash, keychain.user_address);
                authority
                    .quorums
                    .push(quorum(Role::AccessKey, signature, inner));
            }
            AccountSignature::Primitive(_) => {
                if let Ok(key_id) = keychain.key_id(&signature_hash) {
                    authority.keys.push(key(Role::AccessKey, key_id));
                }
            }
        },
    }
    let inner = aa.tx();
    if let Some(grant) = &inner.key_authorization {
        authority.grant = Some(Grant {
            key_type: grant.key_type.into(),
            key_id: grant.key_id,
        });
        match &grant.signature {
            AccountSignature::ConfigurableAccount(signature) => {
                let digest = grant.signature_hash();
                authority
                    .quorums
                    .push(quorum(Role::KeyAuthorization, signature, digest));
            }
            AccountSignature::Primitive(_) => {
                if let Ok(signer) = grant.recover_signer() {
                    authority.keys.push(key(Role::KeyAuthorization, signer));
                }
            }
        }
    }
    if inner.fee_payer_signature.is_some()
        && let Ok(fee_payer) = tx.fee_payer(sender)
    {
        authority.keys.push(key(Role::FeePayer, fee_payer));
    }
    authority
}

/// `signature`'s quorum in `role`, its approvals recovered over the TIP-1107 digest of
/// `inner_digest`.
fn quorum(role: Role, signature: &ConfigurableAccountSignature, inner_digest: B256) -> Quorum {
    let account = signature.account();
    let config = signature.config();
    let digest = spec::approval_digest(inner_digest, account, config.version);
    Quorum {
        role,
        account,
        config: ConfigurableAccountConfig {
            salt: config.salt,
            version: config.version,
            threshold: config.threshold,
            owners: config
                .owners
                .iter()
                .map(|owner| ConfigurableAccountOwner {
                    owner: owner.owner,
                    weight: owner.weight,
                })
                .collect(),
        },
        approvals: signature
            .signatures()
            .iter()
            .map(|approval| Approval {
                owner: approval.recover_signer(&digest).ok(),
                len: approval.encoded_length(),
            })
            .collect(),
    }
}
