//! Acceptance tests for shared multisig accounts spending through multisig access keys.
//!
//! These are intentionally ignored until native multisig signatures can be used inside
//! Keychain signatures and AccountKeychain can authorize a multisig key type. Today the
//! transaction/keychain primitives only support primitive access-key signatures.

#[tokio::test(flavor = "multi_thread")]
#[ignore = "pending native multisig access-key support in KeyAuthorization and KeychainSignature"]
async fn shared_multisig_can_spend_through_tiered_multisig_access_keys() -> eyre::Result<()> {
    // Desired flow:
    //
    // 1. Create and fund a shared native multisig account, e.g. 7 owners with threshold 5.
    // 2. Derive a 2-of-7 native multisig account to use as the low-value access key.
    // 3. Derive a 5-of-7 native multisig account to use as the high-value access key.
    // 4. From the shared multisig, authorize both derived multisig accounts as access keys:
    //    - low-value key: PATH USD limit = 1_000, TIP-20 transfer scope only
    //    - high-value key: PATH USD limit = 10_000, TIP-20 transfer scope only
    // 5. Send a PATH USD transfer from the shared multisig using KeychainSignature {
    //    user_address: shared_multisig,
    //    signature: MultisigSignature(low_value_multisig, 2 owner approvals),
    //    version: V2,
    // }.
    // 6. Assert the transfer succeeds, debits the shared multisig balance, credits the recipient,
    //    and reduces only the low-value key's remaining spending limit.
    //
    // This cannot be expressed with the current types because KeychainSignature::signature is a
    // PrimitiveSignature and KeyAuthorization::key_type has no Multisig variant.
    eyre::bail!("native multisig access-key support is not implemented yet")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "pending native multisig access-key support in KeyAuthorization and KeychainSignature"]
async fn shared_multisig_enforces_multisig_access_key_quorum_and_policy() -> eyre::Result<()> {
    // Desired enforcement cases for the same setup as
    // `shared_multisig_can_spend_through_tiered_multisig_access_keys`:
    //
    // 1. A low-value access-key spend with only 1 owner approval fails because the 2-of-7 key's
    //    multisig threshold is not met.
    // 2. A low-value access-key spend above 1_000 PATH USD fails with SpendingLimitExceeded.
    // 3. A low-value access-key call outside its allowed TIP-20 transfer scope fails with the
    //    call-scope rejection path.
    // 4. A high-value access-key spend with only 2 owner approvals fails because the 5-of-7 key's
    //    multisig threshold is not met.
    // 5. A high-value access-key spend below 10_000 PATH USD with 5 owner approvals succeeds and
    //    spends from the shared multisig account, not from the derived access-key multisig.
    //
    // This cannot be expressed with the current types because KeychainSignature::signature is a
    // PrimitiveSignature and AccountKeychain rejects non-primitive signature types.
    eyre::bail!("native multisig access-key policy enforcement is not implemented yet")
}
