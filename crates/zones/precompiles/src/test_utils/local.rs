use alloy_evm::{
    EvmInternals,
    precompiles::{DynPrecompile, Precompile as _, PrecompileInput},
};
use alloy_primitives::{Address, B256, U256};
use k256::{AffinePoint, ProjectivePoint, Scalar, elliptic_curve::ops::Reduce};
use revm::{
    Context,
    context::{CfgEnv, TxEnv},
    database::InMemoryDB,
    precompile::PrecompileResult,
};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    storage::{actions::StorageActions, evm::EvmPrecompileStorageProvider},
    storage_credits::NonCreditableSlots,
};
use tempo_primitives::TempoBlockEnv;

use crate::{
    ZonePrecompileEnv,
    chaum_pedersen::{challenge_hash, recover_point},
    ecies::DecryptedDeposit,
};

pub(crate) use crate::ecies::{build_plaintext, compressed_x_and_parity, encrypt_plaintext};

/// EVM context used by local precompile unit tests.
pub(crate) type TestContext = Context<TempoBlockEnv, TxEnv, CfgEnv<TempoHardfork>, InMemoryDB>;

/// Create an empty test EVM context at the latest Tempo hardfork affecting Zones.
pub(crate) fn test_context() -> TestContext {
    test_context_with_hardfork(TempoHardfork::T13)
}

/// Create a test EVM context with the specified hardfork.
pub(crate) fn test_context_with_hardfork(hardfork: TempoHardfork) -> TestContext {
    Context::new(InMemoryDB::default(), hardfork)
}

/// Create an EVM-backed precompile storage provider over `ctx`.
pub(crate) fn test_storage_provider(
    ctx: &mut TestContext,
    gas_limit: u64,
    is_static: bool,
) -> EvmPrecompileStorageProvider<'_> {
    let cfg = ctx.cfg.clone();
    EvmPrecompileStorageProvider::new(
        EvmInternals::from_context(ctx),
        gas_limit,
        0,
        cfg.spec,
        cfg.enable_amsterdam_eip8037,
        is_static,
        cfg.gas_params,
    )
}

/// Create the ordinary precompile environment for a local unit test.
pub(crate) fn test_env(ctx: &TestContext) -> ZonePrecompileEnv {
    ZonePrecompileEnv::new(
        &ctx.cfg,
        StorageActions::disabled(),
        Rc::new(RefCell::new(NonCreditableSlots::empty())),
    )
}

/// Call a dynamic precompile with test defaults for value and reservoir.
pub(crate) fn call_precompile(
    ctx: &mut TestContext,
    precompile: &DynPrecompile,
    caller: Address,
    data: &[u8],
    gas: u64,
    is_static: bool,
    target: Address,
    bytecode_address: Address,
) -> PrecompileResult {
    precompile.call(PrecompileInput {
        data,
        gas,
        reservoir: 0,
        caller,
        value: U256::ZERO,
        target_address: target,
        is_static,
        bytecode_address,
        internals: EvmInternals::from_context(ctx),
    })
}

/// Assert that the Chaum-Pedersen proof inside a [`DecryptedDeposit`] is valid.
pub(crate) fn assert_cp_proof_valid(
    dec: &DecryptedDeposit,
    ephemeral_pub: &AffinePoint,
    sequencer_pub: &AffinePoint,
) {
    let s = <Scalar as Reduce<k256::U256>>::reduce_bytes(&dec.proof.cp_proof.s.0.into());
    let c = <Scalar as Reduce<k256::U256>>::reduce_bytes(&dec.proof.cp_proof.c.0.into());
    let shared_pt =
        recover_point(&dec.proof.shared_secret.0, dec.proof.shared_secret_y_parity).unwrap();

    let r1 = ProjectivePoint::GENERATOR * s - ProjectivePoint::from(*sequencer_pub) * c;
    let r2 = ProjectivePoint::from(*ephemeral_pub) * s - ProjectivePoint::from(shared_pt) * c;

    let c_prime = challenge_hash(
        ephemeral_pub,
        sequencer_pub,
        &shared_pt,
        &r1.to_affine(),
        &r2.to_affine(),
    );
    assert_eq!(c, c_prime, "Chaum-Pedersen proof must verify");
}

/// Pre-computed encrypted deposit for testing.
/// All fields are deterministic (derived from fixed seed keys).
pub(crate) struct EncryptedDepositFixture {
    pub seq_key: k256::SecretKey,
    pub seq_pub: AffinePoint,
    pub eph_pub: AffinePoint,
    pub eph_pub_x: B256,
    pub eph_pub_y_parity: u8,
    pub portal: Address,
    pub key_index: U256,
    pub sender: Address,
    pub to: Address,
    pub memo: B256,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
}

impl EncryptedDepositFixture {
    /// Create a fixture with deterministic keys for reproducible tests.
    pub(crate) fn new() -> Self {
        use sha2::{Digest, Sha256};

        // Deterministic sequencer key
        let seq_bytes: [u8; 32] = Sha256::digest(b"test-sequencer-key").into();
        let seq_key = k256::SecretKey::from_slice(&seq_bytes).expect("valid key");
        let seq_scalar: Scalar = *seq_key.to_nonzero_scalar();
        let seq_pub = AffinePoint::from(ProjectivePoint::GENERATOR * seq_scalar);

        // Deterministic ephemeral key
        let eph_bytes: [u8; 32] = Sha256::digest(b"test-ephemeral-key").into();
        let eph_key = k256::SecretKey::from_slice(&eph_bytes).expect("valid key");
        let eph_scalar: Scalar = *eph_key.to_nonzero_scalar();
        let eph_pub = AffinePoint::from(ProjectivePoint::GENERATOR * eph_scalar);
        let (eph_pub_x, eph_pub_y_parity) = compressed_x_and_parity(&eph_pub);

        // ECDH (depositor side)
        let shared_proj = ProjectivePoint::from(seq_pub) * eph_scalar;
        let shared_affine = AffinePoint::from(shared_proj);
        let (shared_secret_x, _) = compressed_x_and_parity(&shared_affine);

        let portal = Address::repeat_byte(0xAA);
        let key_index = U256::from(42u64);
        let sender = Address::repeat_byte(0xDD);

        // HKDF key derivation
        let info = crate::ecies::hkdf_info(&portal, &key_index, &eph_pub_x, &sender);
        let aes_key = crate::ecies::hkdf_sha256(&shared_secret_x, b"ecies-aes-key", &info);

        // Build and encrypt plaintext
        let to = Address::repeat_byte(0xBB);
        let memo = B256::repeat_byte(0xCC);
        let plaintext = build_plaintext(&to, &memo);
        let (ciphertext, nonce, tag) = encrypt_plaintext(&aes_key, &plaintext);

        Self {
            seq_key,
            seq_pub,
            eph_pub,
            eph_pub_x,
            eph_pub_y_parity,
            portal,
            key_index,
            sender,
            to,
            memo,
            ciphertext,
            nonce,
            tag,
        }
    }

    /// Decrypt using the fixture's sequencer key.
    pub(crate) fn decrypt(&self) -> Option<DecryptedDeposit> {
        crate::ecies::decrypt_deposit(
            &self.seq_key,
            &self.eph_pub_x,
            self.eph_pub_y_parity,
            &self.ciphertext,
            &self.nonce,
            &self.tag,
            self.portal,
            self.key_index,
            self.sender,
        )
    }
}
