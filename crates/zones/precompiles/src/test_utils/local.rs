use alloy_primitives::{Address, B256, Bytes, U256};
use evm2::{
    Evm, ExecutionConfig, SpecId,
    evm::{
        InMemoryDB, StateCheckpoint,
        precompile::{NoPrecompiles, PrecompileProvider},
    },
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt},
};
use k256::{AffinePoint, ProjectivePoint, Scalar, elliptic_curve::ops::Reduce};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoEvmExt, TempoEvmTypes, tempo_tx_registry};
use tempo_precompiles::{
    storage::{actions::StorageActions, evm::EvmPrecompileStorageProvider},
    storage_credits::NonCreditableSlots,
};
use tempo_primitives::TempoBlockEnv;

use crate::{
    ZonePrecompiles,
    chaum_pedersen::{challenge_hash, recover_point},
    ecies::DecryptedDeposit,
};

pub(crate) use crate::ecies::{build_plaintext, compressed_x_and_parity, encrypt_plaintext};

use super::MockL1Reader;

pub(crate) struct TestCfg {
    pub(crate) spec: TempoHardfork,
}

/// EVM context used by local precompile unit tests.
pub(crate) struct TestContext {
    pub(crate) cfg: TestCfg,
    pub(crate) block: TempoBlockEnv,
    evm: Evm<'static, TempoEvmTypes>,
    gas: GasTracker,
}

pub(crate) type TestPrecompiles = ZonePrecompiles<TempoEvmTypes, MockL1Reader>;

/// Create an empty test EVM context at the latest Tempo hardfork affecting Zones.
pub(crate) fn test_context() -> TestContext {
    test_context_with_hardfork(TempoHardfork::T13)
}

/// Create a test EVM context with the specified hardfork.
pub(crate) fn test_context_with_hardfork(hardfork: TempoHardfork) -> TestContext {
    let version = tempo_chainspec::gas_params::version(SpecId::OSAKA, hardfork, false);
    let block = TempoBlockEnv::default();
    TestContext {
        cfg: TestCfg { spec: hardfork },
        block,
        evm: Evm::new_with_execution_config_and_ext(
            ExecutionConfig::for_spec_and_version(hardfork, version),
            hardfork,
            block,
            tempo_tx_registry(SpecId::OSAKA),
            InMemoryDB::default(),
            NoPrecompiles::default(),
            TempoEvmExt::default(),
        ),
        gas: GasTracker::new(u64::MAX),
    }
}

/// Create an EVM-backed precompile storage provider over `ctx`.
pub(crate) fn test_storage_provider(
    ctx: &mut TestContext,
    gas_limit: u64,
    is_static: bool,
) -> EvmPrecompileStorageProvider<'_, '_, 'static, TempoEvmTypes> {
    ctx.sync();
    ctx.gas = GasTracker::new(gas_limit);
    EvmPrecompileStorageProvider::new(&mut ctx.evm, &mut ctx.gas, ctx.cfg.spec, is_static)
}

pub(crate) fn test_precompiles(
    ctx: &TestContext,
    l1: crate::L1State<MockL1Reader>,
) -> TestPrecompiles {
    ZonePrecompiles::new(
        ctx.cfg.spec,
        StorageActions::disabled(),
        Rc::new(RefCell::new(NonCreditableSlots::empty())),
        l1,
    )
}

impl TestContext {
    pub(crate) fn sync(&mut self) {
        let version = tempo_chainspec::gas_params::version(SpecId::OSAKA, self.cfg.spec, false);
        self.evm.set_block_and_execution_config(
            self.block,
            ExecutionConfig::for_spec_and_version(self.cfg.spec, version),
            self.cfg.spec,
            tempo_tx_registry(SpecId::OSAKA),
            NoPrecompiles::default(),
        );
    }

    pub(crate) fn checkpoint(&mut self) -> StateCheckpoint {
        self.evm.state_mut().checkpoint()
    }

    pub(crate) fn checkpoint_revert(&mut self, checkpoint: StateCheckpoint) {
        let features = self.evm.version().features;
        self.evm.state_mut().rollback(checkpoint, features);
    }

    pub(crate) fn evm(&mut self) -> &mut Evm<'static, TempoEvmTypes> {
        self.sync();
        &mut self.evm
    }
}

/// Result of a test precompile call. Reverts and halts are outputs; only fatal errors are `Err`.
pub(crate) type PrecompileResult = Result<PrecompileOutput, PrecompileError>;

/// How a test precompile call ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrecompileStatus {
    Success,
    Revert,
    Halt(PrecompileHalt),
}

/// Outcome of a test precompile call together with its gas accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrecompileOutput {
    pub gas_used: u64,
    pub gas_refunded: i64,
    pub state_gas_used: i64,
    pub bytes: Bytes,
    pub reservoir: u64,
    pub status: PrecompileStatus,
}

impl PrecompileOutput {
    pub(crate) const fn is_success(&self) -> bool {
        matches!(self.status, PrecompileStatus::Success)
    }

    pub(crate) const fn is_revert(&self) -> bool {
        matches!(self.status, PrecompileStatus::Revert)
    }
}

/// Call a precompile with test defaults for value and reservoir.
pub(crate) fn call_precompile(
    ctx: &mut TestContext,
    precompiles: &mut TestPrecompiles,
    caller: Address,
    data: &[u8],
    gas: u64,
    is_static: bool,
    target: Address,
    bytecode_address: Address,
) -> PrecompileResult {
    ctx.sync();
    let kind = if is_static {
        MessageKind::StaticCall
    } else {
        MessageKind::Call
    };
    let message = Message::<TempoEvmTypes> {
        kind,
        gas_limit: gas,
        caller,
        input: Bytes::copy_from_slice(data),
        value: U256::ZERO,
        destination: target,
        call_target: bytecode_address,
        code_address: bytecode_address,
        ..Default::default()
    };
    let mut gas_tracker = GasTracker::new(gas);
    let result = precompiles
        .execute(&mut ctx.evm, &message, &mut gas_tracker)
        .expect("test precompile must be registered");
    let gas_used = gas_tracker.spent();
    let gas_refunded = gas_tracker.refunded();
    let state_gas_used = gas_tracker.state_gas_spent();
    let reservoir = gas_tracker.reservoir();
    let (bytes, status) = match result {
        Ok(output) => (output.into_bytes(), PrecompileStatus::Success),
        Err(PrecompileError::Revert(bytes)) => (bytes, PrecompileStatus::Revert),
        Err(PrecompileError::Halt(halt)) => (Bytes::new(), PrecompileStatus::Halt(halt)),
        Err(error) => return Err(error),
    };
    Ok(PrecompileOutput {
        gas_used,
        gas_refunded,
        state_gas_used,
        bytes,
        reservoir,
        status,
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
