//! Configurable account checks: the signatures' authority and the accounts' leaves.

use super::{Reader, StepEffects, all};
use crate::state::{Db, Net};
use alloy_primitives::{Address, B256};
use evm2::evm::{AccountInfo, Database as _};
use invariants_core::Report;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::CONFIGURABLE_ACCOUNT_ADDRESS;
use tempo_invariants::configurable_account::{
    Approval, At, Authority, Commitments, ConfigurableAccountConfig, ConfigurableAccountOwner,
    Grant, Key, Leaf, Leaves, Quorum, Role, VIEW, spec,
};
use tempo_precompiles::storage::account_config_commitment;
use tempo_primitives::{
    TempoTxEnvelope,
    transaction::{
        AccountSignature, ConfigurableAccountSignature, KeychainSignature, TempoSignature,
    },
};

/// What `tx`'s signatures authorize it for; signers that don't recover are left out.
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

/// `signature`'s quorum, its approvals recovered over the TIP-1107 digest.
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

/// Checks the commitments and leaves of the accounts a transaction changed or its signatures name.
pub(super) fn check(reader: &Reader<'_>, db: &Db, effects: &StepEffects<'_>, report: &mut Report) {
    let mut accounts: Vec<Address> = effects
        .net
        .addresses()
        .copied()
        .chain([effects.tx.sender])
        .chain(effects.tx.authority.accounts())
        .collect();
    accounts.sort_unstable();
    accounts.dedup();
    let at = At {
        precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
        accounts: &accounts,
    };
    reader.check::<Commitments>(report, at, CONFIGURABLE_ACCOUNT_ADDRESS, VIEW);
    let leaves = Leaves {
        of: accounts
            .iter()
            .filter_map(|&address| {
                let before = leaf(account_at(db, Some(effects.net), address)?, effects.spec)?;
                let after = leaf(account_at(db, None, address)?, effects.spec)?;
                Some((address, (before, after)))
            })
            .collect(),
        tx: effects.tx.clone(),
    };
    report.run_any(all(), &leaves);
}

/// The account at `address` after the step, or before it with `net`; `None` if the pre-state lacks it.
fn account_at(db: &Db, net: Option<&Net>, address: Address) -> Option<Option<AccountInfo>> {
    if let Some(change) = net.and_then(|net| net.get(&address)) {
        return Some(change.original().cloned());
    }
    db.pre.restore_missed(false);
    let info = db.view().get_account(&address).ok()?;
    (!db.pre.missed()).then_some(info)
}

/// The commitment and code hash of `info`, an account at `spec`.
fn leaf(info: Option<AccountInfo>, spec: TempoHardfork) -> Option<Leaf> {
    let Some(info) = info else {
        return Some(Leaf::EMPTY);
    };
    Some(Leaf {
        commitment: account_config_commitment(&info, spec).ok()?,
        code_hash: info.code_hash,
    })
}
