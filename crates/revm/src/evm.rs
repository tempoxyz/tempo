use crate::{TempoBlockEnv, TempoTxEnv, instructions};
use alloy_evm::{Database, precompiles::PrecompilesMap};
use alloy_primitives::{Address, U256};
use revm::{
    Context, Inspector,
    context::{Cfg, CfgEnv, ContextError, Evm, FrameStack},
    handler::{
        EthFrame, EvmTr, FrameInitOrResult, FrameTr, ItemOrResult, instructions::EthInstructions,
    },
    inspector::InspectorEvmTr,
    interpreter::{InitialAndFloorGas, interpreter::EthInterpreter},
};
use std::{cell::RefCell, rc::Rc};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{storage::StorageActions, storage_credits::NonCreditableSlots};

/// The Tempo EVM context type.
pub type TempoContext<DB> = Context<TempoBlockEnv, TempoTxEnv, CfgEnv<TempoHardfork>, DB>;

/// TempoEvm extends the Evm with Tempo specific types and logic.
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
#[expect(clippy::type_complexity)]
pub struct TempoEvm<DB: Database, I> {
    /// Inner EVM type.
    #[deref]
    #[deref_mut]
    pub inner: Evm<
        TempoContext<DB>,
        I,
        EthInstructions<EthInterpreter, TempoContext<DB>>,
        PrecompilesMap,
        EthFrame<EthInterpreter>,
    >,
    /// The fee collected in `collectFeePreTx` call.
    pub(crate) collected_fee: U256,
    /// The validator-credited amount (post-feeAMM haircut, in the validator's fee token) returned
    /// by the most recent `collectFeePostTx` call.
    ///
    /// Reset to zero before each transaction so it reflects only the current tx.
    pub validator_fee: U256,
    /// The fee token used to pay fees for the current transaction.
    pub(crate) fee_token: Option<Address>,
    /// The expiry timestamp of the access key used by the current transaction.
    /// Populated during validation for keychain-signed transactions or transactions carrying a KeyAuthorization.
    pub(crate) key_expiry: Option<u64>,
    /// When true, skips the `valid_after` time-window check during validation.
    ///
    /// The transaction pool sets this because it intentionally accepts transactions
    /// with a future `valid_after` (queued until executable).
    pub skip_valid_after_check: bool,
    /// When true, skips the AMM liquidity check in `collect_fee_pre_tx`.
    ///
    /// The transaction pool sets this because it performs its own liquidity
    /// validation against a cached view of the AMM state.
    pub skip_liquidity_check: bool,
    /// Recorded storage actions.
    pub(crate) actions: StorageActions,
    /// Transaction-local protocol slots whose clears must not mint storage credits.
    pub(crate) non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Create a new Tempo EVM.
    pub fn new(ctx: TempoContext<DB>, inspector: I) -> Self {
        let non_creditable_slots = Rc::new(RefCell::new(NonCreditableSlots::empty()));
        let actions = StorageActions::disabled();
        let precompiles = tempo_precompiles::tempo_precompiles(
            &ctx.cfg,
            actions.clone(),
            non_creditable_slots.clone(),
        );

        Self::new_inner(
            Evm {
                instruction: instructions::tempo_instructions(ctx.cfg.spec),
                ctx,
                inspector,
                precompiles,
                frame_stack: FrameStack::new(),
            },
            actions,
            non_creditable_slots,
        )
    }

    /// Inner helper function to create a new Tempo EVM with empty logs.
    #[inline]
    #[expect(clippy::type_complexity)]
    fn new_inner(
        inner: Evm<
            TempoContext<DB>,
            I,
            EthInstructions<EthInterpreter, TempoContext<DB>>,
            PrecompilesMap,
            EthFrame<EthInterpreter>,
        >,
        actions: StorageActions,
        non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    ) -> Self {
        Self {
            inner,
            collected_fee: U256::ZERO,
            validator_fee: U256::ZERO,
            fee_token: None,
            key_expiry: None,
            skip_valid_after_check: false,
            skip_liquidity_check: false,
            actions,
            non_creditable_slots,
        }
    }

    /// Computes initial gas limit and reservoir for a transaction given its initial gas spending.
    pub(crate) fn initial_gas_and_reservoir(
        &self,
        init_and_floor_gas: &InitialAndFloorGas,
    ) -> (u64, u64) {
        // Pre-T0 it could happen that the initial gas spending is greater than the gas limit due to faulty validation.
        //
        // Before that it would overflow, so we are reproducing this behavior here by setting the gas limit to u64::MAX and the reservoir to 0.
        if !self.cfg.spec.is_t0() && init_and_floor_gas.initial_total_gas() > self.tx.gas_limit {
            (u64::MAX, 0)
        } else {
            init_and_floor_gas
                .initial_gas_and_reservoir(self.tx.gas_limit, self.cfg.tx_gas_limit_cap())
        }
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Consumed self and returns a new Evm type with given Inspector.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        let Self {
            inner,
            actions,
            non_creditable_slots,
            ..
        } = self;
        TempoEvm::new_inner(
            inner.with_inspector(inspector),
            actions,
            non_creditable_slots,
        )
    }

    /// Consumes self and returns the inner Inspector.
    pub fn into_inspector(self) -> I {
        self.inner.into_inspector()
    }

    /// Returns a reference to the recorded storage actions.
    pub fn actions(&self) -> &StorageActions {
        &self.actions
    }

    /// Clears all intermediate state from the EVM.
    pub fn clear(&mut self) {
        self.collected_fee = U256::ZERO;
        self.fee_token = None;
        self.key_expiry = None;
        self.non_creditable_slots.borrow_mut().clear();
    }
}

impl<DB, I> EvmTr for TempoEvm<DB, I>
where
    DB: Database,
{
    type Context = TempoContext<DB>;
    type Instructions = EthInstructions<EthInterpreter, TempoContext<DB>>;
    type Precompiles = PrecompilesMap;
    type Frame = EthFrame<EthInterpreter>;

    fn all(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
    ) {
        self.inner.all()
    }

    fn all_mut(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
    ) {
        self.inner.all_mut()
    }

    fn frame_stack(&mut self) -> &mut FrameStack<Self::Frame> {
        &mut self.inner.frame_stack
    }

    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<DB::Error>,
    > {
        self.inner.frame_init(frame_input)
    }

    fn frame_run(&mut self) -> Result<FrameInitOrResult<Self::Frame>, ContextError<DB::Error>> {
        self.inner.frame_run()
    }

    fn frame_return_result(
        &mut self,
        result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<Option<<Self::Frame as FrameTr>::FrameResult>, ContextError<DB::Error>> {
        self.inner.frame_return_result(result)
    }
}

impl<DB, I> InspectorEvmTr for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type Inspector = I;

    fn all_inspector(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
        &Self::Inspector,
    ) {
        self.inner.all_inspector()
    }

    fn all_mut_inspector(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
        &mut Self::Inspector,
    ) {
        self.inner.all_mut_inspector()
    }
}

#[cfg(test)]
mod tests {
    use crate::gas_params::{tempo_gas_params, tempo_gas_params_with_amsterdam};
    use alloy_eips::eip7702::Authorization;
    use alloy_evm::FromRecoveredTx;
    use alloy_primitives::{Address, Bytes, TxKind, U256, bytes, hex};
    use alloy_sol_types::{SolCall, SolError};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        ecdsa::{SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::rand_core::OsRng,
    };
    use reth_evm::EvmInternals;
    use revm::{
        Context, DatabaseRef, ExecuteCommitEvm, ExecuteEvm, InspectEvm, MainContext,
        bytecode::opcode,
        context::{
            CfgEnv, ContextTr, TxEnv,
            result::{ExecutionResult, HaltReason},
        },
        database::{CacheDB, EmptyDB},
        handler::system_call::SystemCallEvm,
        inspector::{CountInspector, InspectSystemCallEvm},
        state::{AccountInfo, Bytecode},
    };
    use sha2::{Digest, Sha256};
    use tempo_chainspec::{constants::gas::STORAGE_CREDIT_VALUE, hardfork::TempoHardfork};
    use tempo_contracts::precompiles::IStorageCredits::{self, Mode};
    use tempo_precompiles::{
        AuthorizedKey, DelegateCallNotAllowed, NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
        STORAGE_CREDITS_ADDRESS,
        nonce::NonceManager,
        storage::{FromWord, Handler, StorageCtx, evm::EvmPrecompileStorageProvider},
        storage_credits::{CreditMode, StorageCredits},
        test_util::TIP20Setup,
        tip20::{ITIP20, TIP20Token},
    };
    use tempo_primitives::{
        TempoTransaction,
        transaction::{
            KeyAuthorization, KeychainSignature, SignatureType, TempoSignedAuthorization,
            tempo_transaction::Call,
            tt_signature::{
                PrimitiveSignature, TempoSignature, WebAuthnSignature, derive_p256_address,
                normalize_p256_s,
            },
        },
    };

    use crate::{TempoBlockEnv, TempoEvm, TempoHaltReason, TempoInvalidTransaction, TempoTxEnv};
    use revm::context::result::InvalidTransaction;

    // ==================== Test Constants ====================

    /// Default balance for funded accounts (1 ETH)
    const DEFAULT_BALANCE: u128 = 1_000_000_000_000_000_000;

    /// Identity precompile address (0x04)
    const IDENTITY_PRECOMPILE: Address = Address::new([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04,
    ]);

    // ==================== Test Utility Functions ====================

    /// Create an empty EVM instance with default settings and no inspector.
    fn create_evm() -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let db = CacheDB::new(EmptyDB::new());
        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(Default::default())
            .with_tx(Default::default());
        TempoEvm::new(ctx, ())
    }

    /// Create an EVM instance with a specific block timestamp.
    fn create_evm_with_timestamp(timestamp: u64) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut block = TempoBlockEnv::default();
        block.inner.timestamp = U256::from(timestamp);

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(block)
            .with_cfg(Default::default())
            .with_tx(Default::default());

        TempoEvm::new(ctx, ())
    }

    /// Fund an account with the default balance (1 ETH).
    fn fund_account(evm: &mut TempoEvm<CacheDB<EmptyDB>, ()>, address: Address) {
        fund_account_with_nonce(evm, address, 0);
    }

    /// Fund an account with the default balance and a specific nonce.
    fn fund_account_with_nonce(
        evm: &mut TempoEvm<CacheDB<EmptyDB>, ()>,
        address: Address,
        nonce: u64,
    ) {
        evm.ctx.db_mut().insert_account_info(
            address,
            AccountInfo {
                balance: U256::from(DEFAULT_BALANCE),
                nonce,
                ..Default::default()
            },
        );
    }

    /// Create an EVM with a funded account at the given address.
    fn create_funded_evm(address: Address) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let mut evm = create_evm();
        fund_account(&mut evm, address);
        evm
    }

    /// Create an EVM with T1C hardfork enabled and a funded account.
    /// This applies TIP-1000 gas params via `tempo_gas_params()`.
    fn create_funded_evm_t1(address: Address) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T1C;
        // Apply TIP-1000 gas params for T1C hardfork
        cfg.gas_params = tempo_gas_params(TempoHardfork::T1C);

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(cfg)
            .with_tx(Default::default());

        let mut evm = TempoEvm::new(ctx, ());
        fund_account(&mut evm, address);
        evm
    }

    /// Create an EVM with T3 hardfork enabled and a funded account.
    fn create_funded_evm_t3(address: Address) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T3;
        cfg.gas_params = tempo_gas_params(TempoHardfork::T3);

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(cfg)
            .with_tx(Default::default());

        let mut evm = TempoEvm::new(ctx, ());
        fund_account(&mut evm, address);
        evm
    }

    /// Create an EVM with T4 hardfork enabled and a funded account.
    fn create_funded_evm_t4(address: Address) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T4;
        cfg.gas_params = tempo_gas_params(TempoHardfork::T4);
        cfg.enable_amsterdam_eip8037 = true;

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(cfg)
            .with_tx(Default::default());

        let mut evm = TempoEvm::new(ctx, ());
        fund_account(&mut evm, address);
        evm
    }

    /// Creates a T7-enabled EVM with a funded account.
    /// This activates the TIP-1060 SSTORE storage credits hook while keeping the
    /// TIP-1016 state-gas split disabled to match production.
    fn create_funded_evm_t7(address: Address) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T7;
        cfg.gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T7, false);
        cfg.enable_amsterdam_eip8037 = false;

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(cfg)
            .with_tx(Default::default());

        let mut evm = TempoEvm::new(ctx, ());
        fund_account(&mut evm, address);
        evm
    }

    /// Create an EVM with T7 hardfork, a specific timestamp, and a funded account.
    fn create_funded_evm_t7_with_timestamp(
        address: Address,
        timestamp: u64,
    ) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T7;
        cfg.gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T7, false);
        cfg.enable_amsterdam_eip8037 = false;

        let mut block = TempoBlockEnv::default();
        block.inner.timestamp = U256::from(timestamp);

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(block)
            .with_cfg(cfg)
            .with_tx(Default::default());

        let mut evm = TempoEvm::new(ctx, ());
        fund_account(&mut evm, address);
        evm
    }

    /// Create an EVM with a specific timestamp and a funded account.
    fn create_funded_evm_with_timestamp(
        address: Address,
        timestamp: u64,
    ) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let mut evm = create_evm_with_timestamp(timestamp);
        fund_account(&mut evm, address);
        evm
    }

    /// Create an EVM with T1 hardfork, a specific timestamp, and a funded account.
    fn create_funded_evm_t1_with_timestamp(
        address: Address,
        timestamp: u64,
    ) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T1;
        cfg.gas_params = tempo_gas_params(TempoHardfork::T1);

        let mut block = TempoBlockEnv::default();
        block.inner.timestamp = U256::from(timestamp);

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(block)
            .with_cfg(cfg)
            .with_tx(Default::default());

        let mut evm = TempoEvm::new(ctx, ());
        fund_account(&mut evm, address);
        evm
    }

    /// Create an EVM instance with a custom inspector.
    fn create_evm_with_inspector<I>(inspector: I) -> TempoEvm<CacheDB<EmptyDB>, I> {
        let db = CacheDB::new(EmptyDB::new());
        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(Default::default())
            .with_tx(Default::default());
        TempoEvm::new(ctx, inspector)
    }

    /// Helper struct for managing P256 key pairs in tests.
    struct P256KeyPair {
        signing_key: SigningKey,
        pub_key_x: alloy_primitives::B256,
        pub_key_y: alloy_primitives::B256,
        address: Address,
    }

    impl P256KeyPair {
        /// Generate a new random P256 key pair.
        fn random() -> Self {
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let encoded_point = verifying_key.to_encoded_point(false);
            let pub_key_x = alloy_primitives::B256::from_slice(encoded_point.x().unwrap().as_ref());
            let pub_key_y = alloy_primitives::B256::from_slice(encoded_point.y().unwrap().as_ref());
            let address = derive_p256_address(&pub_key_x, &pub_key_y);

            Self {
                signing_key,
                pub_key_x,
                pub_key_y,
                address,
            }
        }

        /// Create a WebAuthn signature for the given challenge.
        fn sign_webauthn(&self, challenge: &[u8]) -> eyre::Result<WebAuthnSignature> {
            // Create authenticator data
            let mut authenticator_data = vec![0u8; 37];
            authenticator_data[0..32].copy_from_slice(&[0xAA; 32]); // rpIdHash
            authenticator_data[32] = 0x01; // UP flag set
            authenticator_data[33..37].copy_from_slice(&[0, 0, 0, 0]); // signCount

            // Create client data JSON
            let challenge_b64url = URL_SAFE_NO_PAD.encode(challenge);
            let client_data_json = format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
            );

            // Compute message hash
            let client_data_hash = Sha256::digest(client_data_json.as_bytes());
            let mut final_hasher = Sha256::new();
            final_hasher.update(&authenticator_data);
            final_hasher.update(client_data_hash);
            let message_hash = final_hasher.finalize();

            // Sign
            let signature: p256::ecdsa::Signature = self.signing_key.sign_prehash(&message_hash)?;
            let sig_bytes = signature.to_bytes();

            // Construct WebAuthn data
            let mut webauthn_data = Vec::new();
            webauthn_data.extend_from_slice(&authenticator_data);
            webauthn_data.extend_from_slice(client_data_json.as_bytes());

            Ok(WebAuthnSignature {
                webauthn_data: Bytes::from(webauthn_data),
                r: alloy_primitives::B256::from_slice(&sig_bytes[0..32]),
                s: normalize_p256_s(&sig_bytes[32..64]).map_err(|e| eyre::eyre!(e))?,
                pub_key_x: self.pub_key_x,
                pub_key_y: self.pub_key_y,
            })
        }

        /// Create a signed EIP-7702 authorization for the given delegate address.
        fn create_signed_authorization(
            &self,
            delegate_address: Address,
        ) -> eyre::Result<TempoSignedAuthorization> {
            let auth = Authorization {
                chain_id: U256::from(1),
                address: delegate_address,
                nonce: 0,
            };

            let mut sig_buf = Vec::new();
            sig_buf.push(tempo_primitives::transaction::tt_authorization::MAGIC);
            alloy_rlp::Encodable::encode(&auth, &mut sig_buf);
            let auth_sig_hash = alloy_primitives::keccak256(&sig_buf);

            let webauthn_sig = self.sign_webauthn(auth_sig_hash.as_slice())?;
            let aa_sig = TempoSignature::Primitive(PrimitiveSignature::WebAuthn(webauthn_sig));

            Ok(TempoSignedAuthorization::new_unchecked(auth, aa_sig))
        }

        /// Sign a transaction and return it ready for execution.
        fn sign_tx(&self, tx: TempoTransaction) -> eyre::Result<tempo_primitives::AASigned> {
            let webauthn_sig = self.sign_webauthn(tx.signature_hash().as_slice())?;
            Ok(
                tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::WebAuthn(
                    webauthn_sig,
                ))),
            )
        }

        fn sign_tx_keychain(
            &self,
            tx: TempoTransaction,
        ) -> eyre::Result<tempo_primitives::AASigned> {
            // V2: sign keccak256(0x04 || sig_hash || user_address)
            let sig_hash = tx.signature_hash();
            let effective_hash = alloy_primitives::keccak256(
                [&[0x04], sig_hash.as_slice(), self.address.as_slice()].concat(),
            );
            let webauthn_sig = self.sign_webauthn(effective_hash.as_slice())?;
            let keychain_sig =
                KeychainSignature::new(self.address, PrimitiveSignature::WebAuthn(webauthn_sig));
            Ok(tx.into_signed(TempoSignature::Keychain(keychain_sig)))
        }
    }

    /// Builder for creating test transactions with sensible defaults.
    struct TxBuilder {
        calls: Vec<Call>,
        nonce: u64,
        nonce_key: U256,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        valid_before: Option<u64>,
        valid_after: Option<u64>,
        authorization_list: Vec<TempoSignedAuthorization>,
        key_authorization: Option<tempo_primitives::transaction::SignedKeyAuthorization>,
    }

    impl Default for TxBuilder {
        fn default() -> Self {
            Self {
                calls: vec![],
                nonce: 0,
                nonce_key: U256::ZERO,
                gas_limit: 1_000_000,
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
                valid_before: Some(u64::MAX),
                valid_after: None,
                authorization_list: vec![],
                key_authorization: None,
            }
        }
    }

    impl TxBuilder {
        fn new() -> Self {
            Self::default()
        }

        /// Add a call to the identity precompile with the given input.
        fn call_identity(mut self, input: &[u8]) -> Self {
            self.calls.push(Call {
                to: TxKind::Call(IDENTITY_PRECOMPILE),
                value: U256::ZERO,
                input: Bytes::from(input.to_vec()),
            });
            self
        }

        /// Add a call to a specific address.
        fn call(mut self, to: Address, input: &[u8]) -> Self {
            self.calls.push(Call {
                to: TxKind::Call(to),
                value: U256::ZERO,
                input: Bytes::from(input.to_vec()),
            });
            self
        }

        /// Add a create call with the given initcode.
        fn create(mut self, initcode: &[u8]) -> Self {
            self.calls.push(Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: Bytes::from(initcode.to_vec()),
            });
            self
        }

        /// Add a call with a specific value transfer.
        fn call_with_value(mut self, to: Address, input: &[u8], value: U256) -> Self {
            self.calls.push(Call {
                to: TxKind::Call(to),
                value,
                input: Bytes::from(input.to_vec()),
            });
            self
        }

        fn nonce(mut self, nonce: u64) -> Self {
            self.nonce = nonce;
            self
        }

        fn nonce_key(mut self, nonce_key: U256) -> Self {
            self.nonce_key = nonce_key;
            self
        }

        fn gas_limit(mut self, gas_limit: u64) -> Self {
            self.gas_limit = gas_limit;
            self
        }

        fn with_max_fee_per_gas(mut self, max_fee_per_gas: u128) -> Self {
            self.max_fee_per_gas = max_fee_per_gas;
            self
        }

        fn with_max_priority_fee_per_gas(mut self, max_priority_fee_per_gas: u128) -> Self {
            self.max_priority_fee_per_gas = max_priority_fee_per_gas;
            self
        }

        fn valid_before(mut self, valid_before: Option<u64>) -> Self {
            self.valid_before = valid_before;
            self
        }

        fn valid_after(mut self, valid_after: Option<u64>) -> Self {
            self.valid_after = valid_after;
            self
        }

        fn authorization(mut self, auth: TempoSignedAuthorization) -> Self {
            self.authorization_list.push(auth);
            self
        }

        fn key_authorization(
            mut self,
            key_auth: tempo_primitives::transaction::SignedKeyAuthorization,
        ) -> Self {
            self.key_authorization = Some(key_auth);
            self
        }

        fn build(self) -> TempoTransaction {
            TempoTransaction {
                chain_id: 1,
                fee_token: None,
                max_priority_fee_per_gas: self.max_priority_fee_per_gas,
                max_fee_per_gas: self.max_fee_per_gas,
                gas_limit: self.gas_limit,
                calls: self.calls,
                access_list: Default::default(),
                nonce_key: self.nonce_key,
                nonce: self.nonce,
                fee_payer_signature: None,
                valid_before: self.valid_before.and_then(core::num::NonZeroU64::new),
                valid_after: self.valid_after.and_then(core::num::NonZeroU64::new),
                key_authorization: self.key_authorization,
                tempo_authorization_list: self.authorization_list,
            }
        }
    }

    // ==================== End Test Utility Functions ====================

    #[test_case::test_case(TempoHardfork::T1)]
    #[test_case::test_case(TempoHardfork::T1C)]
    fn test_access_millis_timestamp(spec: TempoHardfork) -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());

        let mut ctx = Context::mainnet()
            .with_db(db)
            .with_block(TempoBlockEnv::default())
            .with_cfg(CfgEnv::<TempoHardfork>::default())
            .with_tx(Default::default());

        ctx.cfg.spec = spec;
        ctx.block.timestamp = U256::from(1000);
        ctx.block.timestamp_millis_part = 100;

        let mut tempo_evm = TempoEvm::new(ctx, ());
        let ctx = &mut tempo_evm.ctx;

        let internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, &ctx.tx);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

        _ = StorageCtx::enter(&mut storage, || TIP20Setup::path_usd(Address::ZERO).apply())?;
        drop(storage);

        let contract = Address::random();

        // Create a simple contract that returns output of the opcode.
        ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                // MILLISTIMESTAMP PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN
                code: Some(Bytecode::new_raw(bytes!("0x4F5F5260205FF3"))),
                ..Default::default()
            },
        );

        let tx_env = TxEnv {
            kind: contract.into(),
            ..Default::default()
        };
        let result = tempo_evm.transact_one(tx_env.into())?;

        if !spec.is_t1c() {
            assert!(result.is_success());
            assert_eq!(
                U256::from_be_slice(result.output().unwrap()),
                U256::from(1000100)
            );
        } else {
            assert!(matches!(
                result,
                ExecutionResult::Halt {
                    reason: TempoHaltReason::Ethereum(HaltReason::OpcodeNotFound),
                    ..
                }
            ));
        }

        Ok(())
    }

    #[test]
    fn test_inspector_calls() -> eyre::Result<()> {
        // This test calls TIP20 setSupplyCap which emits a SupplyCapUpdate log event
        let caller = Address::repeat_byte(0x01);
        let contract = Address::repeat_byte(0x42);

        let input_bytes = ITIP20::setSupplyCapCall {
            newSupplyCap: U256::from(100),
        }
        .abi_encode();

        // Create bytecode that calls setSupplyCap(uint256 newSupplyCap) on PATH_USD
        // it is 36 bytes long
        let mut bytecode_bytes = vec![];

        for (i, &byte) in input_bytes.iter().enumerate() {
            bytecode_bytes.extend_from_slice(&[
                opcode::PUSH1,
                byte,
                opcode::PUSH1,
                i as u8,
                opcode::MSTORE8,
            ]);
        }

        // CALL to PATH_USD precompile
        // CALL(gas, addr, value, argsOffset, argsSize, retOffset, retSize)
        bytecode_bytes.extend_from_slice(&[
            opcode::PUSH1,
            0x00, // retSize
            opcode::PUSH1,
            0x00, // retOffset
            opcode::PUSH1,
            0x24, // argsSize (4 + 32 = 36 = 0x24)
            opcode::PUSH1,
            0x00, // argsOffset
            opcode::PUSH1,
            0x00, // value = 0
        ]);

        // PUSH20 PATH_USD_ADDRESS
        bytecode_bytes.push(opcode::PUSH20);
        bytecode_bytes.extend_from_slice(PATH_USD_ADDRESS.as_slice());

        bytecode_bytes.extend_from_slice(&[
            opcode::PUSH2,
            0xFF,
            0xFF, // gas
            opcode::CALL,
            opcode::POP, // pop success/failure
            opcode::STOP,
        ]);

        let bytecode = Bytecode::new_raw(bytecode_bytes.into());

        // Set up EVM with TIP20 infrastructure
        let mut evm = create_evm_with_inspector(CountInspector::new());
        // Set up TIP20 using the storage context pattern
        {
            let ctx = &mut evm.ctx;
            let internals =
                EvmInternals::new(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, &ctx.tx);

            let mut storage = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);
            StorageCtx::enter(&mut storage, || {
                TIP20Setup::path_usd(caller)
                    .with_issuer(caller)
                    .with_admin(contract) // Grant admin role to contract so it can call setSupplyCap
                    .apply()
            })?;
        }

        // Deploy the contract bytecode
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(bytecode),
                ..Default::default()
            },
        );

        // Execute a call to the contract
        let tx_env = TxEnv {
            caller,
            kind: TxKind::Call(contract),
            gas_limit: 1_000_000,
            ..Default::default()
        };
        let result = evm
            .inspect_tx(tx_env.into())
            .expect("execution should succeed");

        assert!(result.result.is_success());

        // Verify that a SupplyCapUpdate log was emitted by the TIP20 precompile
        assert_eq!(result.result.logs().len(), 3);
        // Log should be from TIP20_FACTORY
        assert_eq!(result.result.logs()[0].address, PATH_USD_ADDRESS);

        // Get the inspector and verify counts
        let inspector = &evm.inspector;

        // Verify CALL opcode was executed (the call to PATH_USD)
        assert_eq!(inspector.get_count(opcode::CALL), 1);

        assert_eq!(inspector.get_count(opcode::STOP), 1);

        // Verify log count
        assert_eq!(inspector.log_count(), 1);

        // Verify call count (initial tx + CALL to PATH_USD)
        assert_eq!(inspector.call_count(), 2);

        // Should have 2 call ends
        assert_eq!(inspector.call_end_count(), 2);

        // ==================== Multi-call Tempo transaction test ====================
        // Test inspector with a Tempo transaction that has multiple calls

        let key_pair = P256KeyPair::random();
        let tempo_caller = key_pair.address;

        // Create signed authorization for Tempo tx
        let signed_auth = key_pair.create_signed_authorization(Address::repeat_byte(0x42))?;

        // Create a transaction with 3 calls to identity precompile
        let tx = TxBuilder::new()
            .call_identity(&[0x01, 0x02])
            .call_identity(&[0x03, 0x04])
            .call_identity(&[0x05, 0x06])
            .authorization(signed_auth)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, tempo_caller);

        // Create a new EVM with fresh inspector for multi-call test
        let mut multi_evm = create_evm_with_inspector(CountInspector::new());
        multi_evm.ctx.db_mut().insert_account_info(
            tempo_caller,
            AccountInfo {
                balance: U256::from(DEFAULT_BALANCE),
                ..Default::default()
            },
        );

        // Execute the multi-call transaction with inspector
        let multi_result = multi_evm.inspect_tx(tx_env)?;
        assert!(multi_result.result.is_success(),);

        // Verify inspector tracked all 3 calls
        let multi_inspector = &multi_evm.inspector;

        // Multi-call Tempo transactions execute each call as a separate frame
        // call_count = 3 (one for each identity precompile call)
        assert_eq!(multi_inspector.call_count(), 3,);
        assert_eq!(multi_inspector.call_end_count(), 3,);

        Ok(())
    }

    #[test]
    fn test_tempo_tx_initial_gas() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Create EVM
        let mut evm = create_funded_evm(caller);
        evm.block.basefee = 100_000_000_000;

        // Set up TIP20 first (required for fee token validation)
        let block = TempoBlockEnv::default();
        let ctx = &mut evm.ctx;
        let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
        let mut provider =
            EvmPrecompileStorageProvider::new_max_gas(internals, &Default::default());

        StorageCtx::enter(&mut provider, || {
            TIP20Setup::path_usd(caller)
                .with_issuer(caller)
                .with_mint(caller, U256::from(100_000))
                .apply()
        })?;

        drop(provider);

        // First tx: single call
        let tx1 = TxBuilder::new()
            .call_identity(&[])
            .gas_limit(300_000)
            .with_max_fee_per_gas(200_000_000_000)
            .with_max_priority_fee_per_gas(0)
            .build();

        let signed_tx1 = key_pair.sign_tx(tx1)?;
        let tx_env1 = TempoTxEnv::from_recovered_tx(&signed_tx1, caller);

        let ctx = &mut evm.ctx;
        let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
        let mut provider =
            EvmPrecompileStorageProvider::new_max_gas(internals, &Default::default());

        let slot = StorageCtx::enter(&mut provider, || {
            TIP20Token::from_address(PATH_USD_ADDRESS)?.balances[caller].read()
        })?;
        drop(provider);

        assert_eq!(slot, U256::from(100_000));

        let result1 = evm.transact_commit(tx_env1)?;
        assert!(result1.is_success());
        assert_eq!(result1.tx_gas_used(), 28_671);

        let ctx = &mut evm.ctx;
        let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
        let mut provider =
            EvmPrecompileStorageProvider::new_max_gas(internals, &Default::default());

        let slot = StorageCtx::enter(&mut provider, || {
            TIP20Token::from_address(PATH_USD_ADDRESS)?.balances[caller].read()
        })?;
        drop(provider);

        assert_eq!(slot, U256::from(97_132));

        // Second tx: two calls
        let tx2 = TxBuilder::new()
            .call_identity(&[])
            .call_identity(&[])
            .nonce(1)
            .gas_limit(35_000)
            .with_max_fee_per_gas(200_000_000_000)
            .with_max_priority_fee_per_gas(0)
            .build();

        let signed_tx2 = key_pair.sign_tx(tx2)?;
        let tx_env2 = TempoTxEnv::from_recovered_tx(&signed_tx2, caller);

        let result2 = evm.transact_commit(tx_env2)?;
        assert!(result2.is_success());
        assert_eq!(result2.tx_gas_used(), 31_286);

        let ctx = &mut evm.ctx;
        let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
        let mut provider =
            EvmPrecompileStorageProvider::new_max_gas(internals, &Default::default());

        let slot = StorageCtx::enter(&mut provider, || {
            TIP20Token::from_address(PATH_USD_ADDRESS)?.balances[caller].read()
        })?;
        drop(provider);

        assert_eq!(slot, U256::from(94_003));

        Ok(())
    }

    /// Test creating and executing a Tempo transaction with:
    /// - WebAuthn signature
    /// - Authorization list (aa_auth_list)
    /// - Two calls to the identity precompile (0x04)
    #[test]
    fn test_tempo_tx() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Create signed authorization
        let signed_auth = key_pair.create_signed_authorization(Address::repeat_byte(0x42))?;

        // Create and sign transaction with two calls to identity precompile
        let tx = TxBuilder::new()
            .call_identity(&[0x01, 0x02, 0x03, 0x04])
            .call_identity(&[0xAA, 0xBB, 0xCC, 0xDD])
            .authorization(signed_auth.clone())
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        // Verify transaction has AA auth list
        assert!(tx_env.tempo_tx_env.is_some(),);
        let tempo_env = tx_env.tempo_tx_env.as_ref().unwrap();
        assert_eq!(tempo_env.tempo_authorization_list.len(), 1);
        assert_eq!(tempo_env.aa_calls.len(), 2);

        // Create EVM with T1C (required for V2 keychain signatures) and execute transaction
        let mut evm = create_funded_evm_t1(caller);

        // Execute the transaction and commit state changes
        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success());

        // Test with KeychainSignature using key_authorization to provision the access key
        let key_auth = KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, caller);
        let key_auth_webauthn_sig = key_pair.sign_webauthn(key_auth.signature_hash().as_slice())?;
        let signed_key_auth =
            key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_webauthn_sig));

        // Create transaction with incremented nonce and key_authorization
        let tx2 = TxBuilder::new()
            .call_identity(&[0x01, 0x02, 0x03, 0x04])
            .call_identity(&[0xAA, 0xBB, 0xCC, 0xDD])
            .authorization(signed_auth)
            .nonce(1)
            .gas_limit(1_000_000)
            .key_authorization(signed_key_auth)
            .build();

        let signed_tx = key_pair.sign_tx_keychain(tx2)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        // Explicitly test tempo_tx_env.signature.as_keychain()
        let tempo_env_keychain = tx_env
            .tempo_tx_env
            .as_ref()
            .expect("Transaction should have tempo_tx_env");
        let keychain_sig = tempo_env_keychain
            .signature
            .as_keychain()
            .expect("Signature should be a KeychainSignature");

        // Validate KeychainSignature properties
        // KeychainSignature user_address should match the caller
        assert_eq!(keychain_sig.user_address, caller,);

        // Verify the inner signature is WebAuthn
        assert!(matches!(
            keychain_sig.signature,
            PrimitiveSignature::WebAuthn(_)
        ));

        // Verify key_id recovery works correctly using the transaction signature hash
        let recovered_key_id = keychain_sig
            .key_id(&tempo_env_keychain.signature_hash)
            .expect("Key ID recovery should succeed");
        assert_eq!(recovered_key_id, caller,);

        // Execute the transaction with keychain signature and commit state changes
        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success());

        // Test a transaction with a failing call to TIP20 contract with wrong input
        let tx_fail = TxBuilder::new()
            .call(PATH_USD_ADDRESS, &[0x01, 0x02]) // Too short for TIP20
            .nonce(2)
            .build();

        let signed_tx_fail = key_pair.sign_tx_keychain(tx_fail)?;
        let tx_env_fail = TempoTxEnv::from_recovered_tx(&signed_tx_fail, caller);

        let result_fail = evm.transact(tx_env_fail)?;
        assert!(!result_fail.result.is_success());

        // Test 2D nonce transaction (nonce_key > 0)
        let nonce_key_2d = U256::from(42);

        let tx_2d = TxBuilder::new()
            .call_identity(&[0x2D, 0x2D, 0x2D, 0x2D])
            .nonce_key(nonce_key_2d)
            .build();

        let signed_tx_2d = key_pair.sign_tx_keychain(tx_2d)?;
        let tx_env_2d = TempoTxEnv::from_recovered_tx(&signed_tx_2d, caller);

        assert!(tx_env_2d.tempo_tx_env.is_some());
        assert_eq!(
            tx_env_2d.tempo_tx_env.as_ref().unwrap().nonce_key,
            nonce_key_2d
        );

        let result_2d = evm.transact_commit(tx_env_2d)?;
        assert!(result_2d.is_success());

        // Verify 2D nonce was incremented
        let nonce_slot = NonceManager::new().nonces[caller][nonce_key_2d].slot();
        let stored_nonce = evm
            .ctx
            .db()
            .storage_ref(NONCE_PRECOMPILE_ADDRESS, nonce_slot)
            .unwrap_or_default();
        assert_eq!(stored_nonce, U256::from(1));

        // Test second 2D nonce transaction
        let tx_2d_2 = TxBuilder::new()
            .call_identity(&[0x2E, 0x2E, 0x2E, 0x2E])
            .nonce_key(nonce_key_2d)
            .nonce(1)
            .build();

        let signed_tx_2d_2 = key_pair.sign_tx_keychain(tx_2d_2)?;
        let tx_env_2d_2 = TempoTxEnv::from_recovered_tx(&signed_tx_2d_2, caller);

        let result_2d_2 = evm.transact_commit(tx_env_2d_2)?;
        assert!(result_2d_2.is_success());

        // Verify nonce incremented again
        let stored_nonce_2 = evm
            .ctx
            .db()
            .storage_ref(NONCE_PRECOMPILE_ADDRESS, nonce_slot)
            .unwrap_or_default();
        assert_eq!(stored_nonce_2, U256::from(2));

        Ok(())
    }

    #[test]
    fn test_t3_key_authorization_deny_all_scopes_blocks_same_tx_call() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        let mut evm = create_funded_evm_t3(caller);

        // Set up TIP20 for fee payment.
        let block = TempoBlockEnv::default();
        {
            let ctx = &mut evm.ctx;
            let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
            let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

            StorageCtx::enter(&mut provider, || {
                TIP20Setup::path_usd(caller)
                    .with_issuer(caller)
                    .with_mint(caller, U256::from(10_000_000))
                    .apply()
            })?;
        }

        // Explicit deny-all marker in protocol payload: Some([]).
        let key_auth =
            KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, caller).with_no_calls();
        let key_auth_sig = key_pair.sign_webauthn(key_auth.signature_hash().as_slice())?;
        let signed_key_auth = key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_sig));

        let tx = TxBuilder::new()
            .call_identity(&[0x01])
            .key_authorization(signed_key_auth)
            .gas_limit(5_000_000)
            .build();

        // Use keychain signature so call-scope validation runs in the same tx.
        let signed_tx = key_pair.sign_tx_keychain(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(
            !result.is_success(),
            "deny-all scope should now fail during paid execution"
        );
        assert!(
            result.tx_gas_used() > 0,
            "failed execution should still consume gas"
        );

        Ok(())
    }

    #[test]
    fn test_t3_key_authorization_accepts_empty_recipient_allowlist_as_unconstrained()
    -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        let mut evm = create_funded_evm_t3(caller);

        let block = TempoBlockEnv::default();
        {
            let ctx = &mut evm.ctx;
            let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
            let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

            StorageCtx::enter(&mut provider, || {
                TIP20Setup::path_usd(caller)
                    .with_issuer(caller)
                    .with_mint(caller, U256::from(10_000_000))
                    .apply()
            })?;
        }

        let transfer_to = Address::repeat_byte(0xaa);
        let transfer_input = ITIP20::transferCall {
            to: transfer_to,
            amount: U256::from(1_u64),
        }
        .abi_encode();

        let key_auth = KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, caller)
            .with_allowed_calls(vec![tempo_primitives::transaction::CallScope {
                target: PATH_USD_ADDRESS,
                selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                    selector: ITIP20::transferCall::SELECTOR,
                    recipients: Vec::new(),
                }],
            }]);
        let key_auth_sig = key_pair.sign_webauthn(key_auth.signature_hash().as_slice())?;
        let signed_key_auth = key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_sig));

        let tx = TxBuilder::new()
            .call(PATH_USD_ADDRESS, &transfer_input)
            .key_authorization(signed_key_auth)
            .gas_limit(5_000_000)
            .build();

        let signed_tx = key_pair.sign_tx_keychain(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        evm.transact_commit(tx_env)
            .expect("empty recipient allowlist should allow the call");

        Ok(())
    }

    #[test]
    fn test_same_tx_key_authorization_rejects_key_type_mismatch() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        let mut evm = create_funded_evm_t3(caller);

        let key_auth = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, caller);
        let key_auth_sig = key_pair.sign_webauthn(key_auth.signature_hash().as_slice())?;
        let signed_key_auth = key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_sig));

        let tx = TxBuilder::new()
            .call_identity(&[0x01])
            .key_authorization(signed_key_auth)
            .gas_limit(5_000_000)
            .build();

        let signed_tx = key_pair.sign_tx_keychain(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let err = evm
            .transact_commit(tx_env)
            .expect_err("mismatched key_type should reject same-tx auth+use");

        assert!(
            matches!(
                err,
                revm::context::result::EVMError::Transaction(
                    TempoInvalidTransaction::KeychainValidationFailed { .. }
                )
            ),
            "expected KeychainValidationFailed, got: {err:?}"
        );

        Ok(())
    }

    /// Test that Tempo transaction time window validation works correctly.
    /// Tests `valid_after` and `valid_before` fields against block timestamp.
    #[test]
    fn test_tempo_tx_time_window() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Create signed authorization
        let signed_auth = key_pair.create_signed_authorization(Address::repeat_byte(0x42))?;

        // Helper to create and sign a transaction with time window parameters
        let create_signed_tx = |valid_after: Option<u64>, valid_before: Option<u64>| {
            let tx = TxBuilder::new()
                .call_identity(&[0x01, 0x02, 0x03, 0x04])
                .authorization(signed_auth.clone())
                .valid_after(valid_after)
                .valid_before(valid_before)
                .build();
            key_pair.sign_tx(tx)
        };

        // Test case 1: Transaction fails when block_timestamp < valid_after
        {
            let mut evm = create_funded_evm_with_timestamp(caller, 100);
            let signed_tx = create_signed_tx(Some(200), None)?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    revm::context::result::EVMError::Transaction(
                        TempoInvalidTransaction::ValidAfter {
                            current: 100,
                            valid_after: 200
                        }
                    )
                ),
                "Expected ValidAfter error, got: {err:?}"
            );
        }

        // Test case 2: Transaction fails when block_timestamp >= valid_before
        {
            let mut evm = create_funded_evm_with_timestamp(caller, 200);
            let signed_tx = create_signed_tx(None, Some(200))?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    revm::context::result::EVMError::Transaction(
                        TempoInvalidTransaction::ValidBefore {
                            current: 200,
                            valid_before: 200
                        }
                    )
                ),
                "Expected ValidBefore error, got: {err:?}"
            );
        }

        // Test case 3: Transaction fails when block_timestamp > valid_before
        {
            let mut evm = create_funded_evm_with_timestamp(caller, 300);
            let signed_tx = create_signed_tx(None, Some(200))?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    revm::context::result::EVMError::Transaction(
                        TempoInvalidTransaction::ValidBefore {
                            current: 300,
                            valid_before: 200
                        }
                    )
                ),
                "Expected ValidBefore error, got: {err:?}"
            );
        }

        // Test case 4: Transaction succeeds when exactly at valid_after boundary
        {
            let mut evm = create_funded_evm_with_timestamp(caller, 200);
            let signed_tx = create_signed_tx(Some(200), None)?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env)?;
            assert!(result.result.is_success());
        }

        // Test case 5: Transaction succeeds when within time window
        {
            let mut evm = create_funded_evm_with_timestamp(caller, 150);
            let signed_tx = create_signed_tx(Some(100), Some(200))?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env)?;
            assert!(result.result.is_success());
        }

        // Test case 6: Transaction fails when block_timestamp < valid_after in a window
        {
            let mut evm = create_funded_evm_with_timestamp(caller, 50);
            let signed_tx = create_signed_tx(Some(100), Some(200))?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    revm::context::result::EVMError::Transaction(
                        TempoInvalidTransaction::ValidAfter {
                            current: 50,
                            valid_after: 100
                        }
                    )
                ),
                "Expected ValidAfter error, got: {err:?}"
            );
        }

        // Test case 7: Transaction fails when block_timestamp >= valid_before in a window
        {
            let mut evm = create_funded_evm_with_timestamp(caller, 200);
            let signed_tx = create_signed_tx(Some(100), Some(200))?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    revm::context::result::EVMError::Transaction(
                        TempoInvalidTransaction::ValidBefore {
                            current: 200,
                            valid_before: 200
                        }
                    )
                ),
                "Expected ValidBefore error, got: {err:?}"
            );
        }

        Ok(())
    }

    /// Test executing a Tempo transaction where the first call is a Create kind.
    /// This should succeed as CREATE is allowed as the first call.
    #[test]
    fn test_tempo_tx_create_first_call() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Simple contract that just returns: PUSH1 0x00 PUSH1 0x00 RETURN
        let initcode = vec![0x60, 0x00, 0x60, 0x00, 0xF3];

        // Create transaction with CREATE as first call (no authorization list)
        let tx = TxBuilder::new()
            .create(&initcode)
            .call_identity(&[0x01, 0x02])
            .gas_limit(200_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        // Create EVM and execute
        let mut evm = create_funded_evm(caller);
        let result = evm.transact_commit(tx_env)?;

        assert!(result.is_success(), "CREATE as first call should succeed");

        Ok(())
    }

    /// Test that a Tempo transaction fails when CREATE is the second call.
    /// CREATE must be the first call if used.
    #[test]
    fn test_tempo_tx_create_second_call_fails() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Simple initcode
        let initcode = vec![0x60, 0x00, 0x60, 0x00, 0xF3];

        // Create transaction with a regular call first, then CREATE second
        let tx = TxBuilder::new()
            .call_identity(&[0x01, 0x02])
            .create(&initcode)
            .gas_limit(200_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        // Create EVM and execute - should fail validation
        let mut evm = create_funded_evm(caller);
        let result = evm.transact(tx_env);

        assert!(result.is_err(), "CREATE as second call should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                revm::context::result::EVMError::Transaction(
                    TempoInvalidTransaction::CallsValidation(msg)
                ) if msg.contains("first call")
            ),
            "Expected CallsValidation error about 'first call', got: {err:?}"
        );

        Ok(())
    }

    /// Test validate_aa_initial_tx_gas error cases.
    /// Tests all error paths in the AA initial transaction gas validation:
    /// - CreateInitCodeSizeLimit: when initcode exceeds max size
    /// - ValueTransferNotAllowedInAATx: when a call has non-zero value
    /// - CallGasCostMoreThanGasLimit: when gas_limit < intrinsic_gas
    #[test]
    fn test_validate_aa_initial_tx_gas_errors() -> eyre::Result<()> {
        use revm::{context::result::EVMError, handler::Handler};

        use crate::handler::TempoEvmHandler;

        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Helper to create EVM with signed transaction
        let create_evm_with_tx =
            |tx: TempoTransaction| -> eyre::Result<TempoEvm<CacheDB<EmptyDB>, ()>> {
                let signed_tx = key_pair.sign_tx(tx)?;
                let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);
                let mut evm = create_funded_evm(caller);
                evm.ctx.tx = tx_env;
                Ok(evm)
            };

        let handler = TempoEvmHandler::default();

        // Test 1: CreateInitCodeSizeLimit - initcode exceeds max size
        {
            // Default max initcode size is 49152 bytes (2 * MAX_CODE_SIZE)
            let oversized_initcode = vec![0x60; 50_000];

            let mut evm = create_evm_with_tx(
                TxBuilder::new()
                    .create(&oversized_initcode)
                    .gas_limit(10_000_000)
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&mut evm);
            assert!(
                matches!(
                    result,
                    Err(EVMError::Transaction(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            revm::context::result::InvalidTransaction::CreateInitCodeSizeLimit
                        )
                    ))
                ),
                "Expected CreateInitCodeSizeLimit error, got: {result:?}"
            );
        }

        // Test 2: ValueTransferNotAllowedInAATx - call has non-zero value
        {
            let mut evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_with_value(IDENTITY_PRECOMPILE, &[0x01, 0x02], U256::from(1000))
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&mut evm);
            assert!(
                matches!(
                    result,
                    Err(EVMError::Transaction(
                        TempoInvalidTransaction::ValueTransferNotAllowedInAATx
                    ))
                ),
                "Expected ValueTransferNotAllowedInAATx error, got: {result:?}"
            );
        }

        // Test 3: CallGasCostMoreThanGasLimit - gas_limit < intrinsic_gas
        {
            let mut evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_identity(&[0x01, 0x02, 0x03, 0x04])
                    .gas_limit(1000) // Way too low, intrinsic cost is at least 21000
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&mut evm);
            assert!(
                matches!(
                    result,
                    Err(EVMError::Transaction(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit {
                                gas_limit: 1000,
                                initial_gas
                            }
                        )
                    )) if initial_gas > 1000
                ),
                "Expected CallGasCostMoreThanGasLimit error, got: {result:?}"
            );
        }

        // Test 4: gas_limit < floor_gas (EIP-7623)
        // For AA transactions, intrinsic gas is higher than for standard txs, so with
        // gas_limit=31000 the intrinsic gas check fires first (CallGasCostMoreThanGasLimit).
        // The floor gas error (GasFloorMoreThanGasLimit) would only appear if gas_limit
        // were between intrinsic_gas and floor_gas, but AA intrinsic gas already exceeds
        // both values here.
        {
            let large_calldata = vec![0x42; 1000]; // 1000 non-zero bytes = 1000 tokens

            let mut evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_identity(&large_calldata)
                    .gas_limit(31_000)
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&mut evm);

            assert!(
                matches!(
                    result,
                    Err(EVMError::Transaction(
                        TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit {
                                gas_limit: 31_000,
                                initial_gas
                            }
                        )
                    )) if initial_gas > 31_000
                ),
                "Expected CallGasCostMoreThanGasLimit, got: {result:?}"
            );
        }

        // Test 5: Success when gas_limit >= both initial_gas and floor_gas
        // Verifies floor_gas > initial_gas for large calldata (EIP-7623 scenario)
        {
            let large_calldata = vec![0x42; 1000];

            let mut evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_identity(&large_calldata)
                    .gas_limit(1_000_000) // Plenty of gas for both initial and floor
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&mut evm);
            assert!(
                result.is_ok(),
                "Expected success with sufficient gas, got: {result:?}"
            );

            let gas = result.unwrap();
            // Verify floor_gas > initial_total_gas for this calldata (EIP-7623 scenario)
            assert!(
                gas.floor_gas > gas.initial_total_gas(),
                "Expected floor_gas ({}) > initial_total_gas ({}) for large calldata",
                gas.floor_gas,
                gas.initial_total_gas()
            );
        }

        // Test 6: Success case - sufficient gas provided (small calldata)
        {
            let mut evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_identity(&[0x01, 0x02, 0x03, 0x04])
                    .gas_limit(1_000_000)
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&mut evm);
            assert!(result.is_ok(), "Expected success, got: {result:?}");

            let gas = result.unwrap();
            assert!(
                gas.initial_total_gas() >= 21_000,
                "Initial gas should be at least 21k base"
            );
        }

        Ok(())
    }

    // ==================== TIP-1000 EVM Configuration Tests ====================

    /// Test AA transaction gas usage for simple identity precompile call.
    /// This establishes a baseline for gas comparison.
    /// Uses T1 hardfork for TIP-1000 gas costs.
    #[test]
    fn test_aa_tx_gas_baseline_identity_call() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        let mut evm = create_funded_evm_t1(caller);

        // Simple call to identity precompile
        // T1 adds 250k for new account creation (nonce == 0)
        let tx = TxBuilder::new()
            .call_identity(&[0x01, 0x02, 0x03, 0x04])
            .gas_limit(500_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success());

        // With T1 TIP-1000: new account cost (250k) + base intrinsic (21k) + WebAuthn (~3.4k) + calldata
        let gas_used = result.tx_gas_used();
        assert_eq!(
            gas_used, 278738,
            "T1 baseline identity call gas should be exact"
        );

        Ok(())
    }

    /// Test AA transaction gas usage with SSTORE to a new storage slot.
    /// This tests TIP-1000's increased SSTORE cost (250,000 gas for new slot).
    /// Uses T1 hardfork for TIP-1000 gas costs.
    #[test]
    fn test_aa_tx_gas_sstore_new_slot() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let contract = Address::repeat_byte(0x55);

        let mut evm = create_funded_evm_t1(caller);

        // Deploy contract that does SSTORE to slot 0:
        // PUSH1 0x42 PUSH1 0x00 SSTORE STOP
        // This stores value 0x42 at slot 0
        let sstore_bytecode = Bytecode::new_raw(bytes!("60426000555B00"));
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(sstore_bytecode),
                ..Default::default()
            },
        );

        // T1 costs: new account (250k) + SSTORE new slot (250k) + base costs
        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(600_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success(), "SSTORE transaction should succeed");

        // With TIP-1000: new account (250k) + SSTORE to new slot (250k) + base costs
        let gas_used = result.tx_gas_used();
        assert_eq!(
            gas_used, 530863,
            "T1 SSTORE to new slot gas should be exact"
        );

        Ok(())
    }

    /// Test AA transaction gas usage with SSTORE to an existing storage slot (warm).
    /// Warm SSTORE should be much cheaper than cold SSTORE to a new slot.
    /// Uses T1 hardfork for TIP-1000 gas costs.
    #[test]
    fn test_aa_tx_gas_sstore_warm_slot() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let contract = Address::repeat_byte(0x56);

        let mut evm = create_funded_evm_t1(caller);

        // Deploy contract that does SSTORE to slot 0:
        // PUSH1 0x42 PUSH1 0x00 SSTORE STOP
        let sstore_bytecode = Bytecode::new_raw(bytes!("60426000555B00"));
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(sstore_bytecode),
                ..Default::default()
            },
        );

        // Pre-populate storage slot 0 with a non-zero value
        evm.ctx
            .db_mut()
            .insert_account_storage(contract, U256::ZERO, U256::from(1))
            .unwrap();

        // T1 costs: new account (250k) + SSTORE reset (not new slot) + base costs
        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(500_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(
            result.is_success(),
            "SSTORE to existing slot should succeed"
        );

        // SSTORE to existing non-zero slot (reset) doesn't trigger the 250k new slot cost
        // But still has new account cost (250k) + cold SLOAD (2100) + warm SSTORE reset (~2900)
        let gas_used = result.tx_gas_used();
        assert_eq!(
            gas_used, 283663,
            "T1 SSTORE to existing slot gas should be exact"
        );

        Ok(())
    }

    /// Test AA transaction gas comparison: multiple SSTORE operations.
    /// Uses T1 hardfork for TIP-1000 gas costs.
    #[test]
    fn test_aa_tx_gas_multiple_sstores() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let contract = Address::repeat_byte(0x57);

        let mut evm = create_funded_evm_t1(caller);

        // Deploy contract that does 2 SSTOREs to different slots:
        // PUSH1 0x11 PUSH1 0x00 SSTORE  (store 0x11 at slot 0)
        // PUSH1 0x22 PUSH1 0x01 SSTORE  (store 0x22 at slot 1)
        // STOP
        let multi_sstore_bytecode = Bytecode::new_raw(bytes!("601160005560226001555B00"));
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(multi_sstore_bytecode),
                ..Default::default()
            },
        );

        // T1 costs: new account (250k) + 2 SSTORE new slots (2 * 250k) + base costs
        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(1_000_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(
            result.is_success(),
            "Multiple SSTORE transaction should succeed"
        );

        // With TIP-1000: new account (250k) + 2 SSTOREs to new slots (2 * 250k) = 750k + base
        let gas_used = result.tx_gas_used();
        assert_eq!(gas_used, 783069, "T1 multiple SSTOREs gas should be exact");

        Ok(())
    }

    /// Seed the TIP-1060 persistent storage credit balance for `owner` directly into the storage
    /// credits contract's storage. Storage creation mode is transient and must be selected inside
    /// each transaction with `setMode`.
    fn seed_storage_credit_balance(
        evm: &mut TempoEvm<CacheDB<EmptyDB>, ()>,
        owner: Address,
        balance: u64,
    ) {
        // The storage credits contract account must exist before we can write storage to it.
        evm.ctx
            .db_mut()
            .insert_account_info(STORAGE_CREDITS_ADDRESS, AccountInfo::default());
        let slot = StorageCredits::slot(owner);
        evm.ctx
            .db_mut()
            .insert_account_storage(STORAGE_CREDITS_ADDRESS, slot, U256::from(balance))
            .unwrap();
    }

    fn storage_credit_word(evm: &TempoEvm<CacheDB<EmptyDB>, ()>, owner: Address) -> U256 {
        let slot = StorageCredits::slot(owner);
        evm.ctx
            .db()
            .storage_ref(STORAGE_CREDITS_ADDRESS, slot)
            .unwrap()
    }

    /// Read back the TIP-1060 storage credit balance stored for `owner` from the storage credits contract.
    fn storage_credit_balance(evm: &TempoEvm<CacheDB<EmptyDB>, ()>, owner: Address) -> u64 {
        u64::from_word(storage_credit_word(evm, owner)).unwrap()
    }

    fn tip1060_abi_mode(mode: CreditMode) -> Mode {
        match mode {
            CreditMode::Refund => Mode::Refund,
            CreditMode::Preserve => Mode::Preserve,
            CreditMode::Direct => Mode::Direct,
        }
    }

    fn append_tip1060_precompile_call(bytecode_bytes: &mut Vec<u8>, input_bytes: &[u8]) {
        append_tip1060_precompile_call_store_return(bytecode_bytes, input_bytes, None);
    }

    /// Appends bytecode that calls the TIP-1060 precompile and stores the returned word in `slot`.
    fn append_tip1060_precompile_call_store_return(
        bytecode_bytes: &mut Vec<u8>,
        input_bytes: &[u8],
        store_return_in_slot: Option<u8>,
    ) {
        for (i, &byte) in input_bytes.iter().enumerate() {
            assert!(i <= u8::MAX as usize);
            // PUSH1 <byte> PUSH1 <offset> MSTORE8  (write calldata byte at memory[offset])
            bytecode_bytes.extend_from_slice(&[
                opcode::PUSH1,
                byte,
                opcode::PUSH1,
                i as u8,
                opcode::MSTORE8,
            ]);
        }

        let ret_size = if store_return_in_slot.is_some() {
            0x20
        } else {
            0
        };

        // PUSH1 <retSize> PUSH1 0x00 PUSH1 <argsSize> PUSH1 0x00 PUSH1 0x00
        // (retOffset=0, argsOffset=0, value=0)
        bytecode_bytes.extend_from_slice(&[opcode::PUSH1, ret_size, opcode::PUSH1, 0x00]);
        bytecode_bytes.extend_from_slice(&[opcode::PUSH1, input_bytes.len() as u8]);
        bytecode_bytes.extend_from_slice(&bytes!("60006000"));
        // PUSH20 <STORAGE_CREDITS_ADDRESS>
        bytecode_bytes.push(opcode::PUSH20);
        bytecode_bytes.extend_from_slice(STORAGE_CREDITS_ADDRESS.as_slice());
        // PUSH3 0x0f4240 CALL POP  (call with 1_000_000 gas and discard success flag)
        bytecode_bytes.extend_from_slice(&bytes!("620f4240f150"));

        if let Some(slot) = store_return_in_slot {
            // Store returned word: MLOAD(0) -> SSTORE(slot, value).
            bytecode_bytes.extend_from_slice(&[
                opcode::PUSH1,
                0x00,
                opcode::MLOAD,
                opcode::PUSH1,
                slot,
            ]);
            bytecode_bytes.push(opcode::SSTORE);
        }
    }

    /// Appends bytecode that calls TIP-1060 precompile's `setMode(mode)` as the executing contract.
    fn append_tip1060_set_mode_call(bytecode_bytes: &mut Vec<u8>, mode: CreditMode) {
        let input_bytes = IStorageCredits::setModeCall {
            newMode: tip1060_abi_mode(mode),
        }
        .abi_encode();

        append_tip1060_precompile_call(bytecode_bytes, &input_bytes);
    }

    fn bytecode_with_tip1060_mode(mode: CreditMode, body: &[u8]) -> Bytecode {
        let mut bytecode = Vec::new();
        if mode != CreditMode::Refund {
            append_tip1060_set_mode_call(&mut bytecode, mode);
        }
        bytecode.extend_from_slice(body);
        Bytecode::new_raw(bytecode.into())
    }

    fn run_tx_on_tip1060_contract(
        mode: CreditMode,
        contract: Address,
        bytecode: &[u8],
    ) -> eyre::Result<(u64, TempoEvm<CacheDB<EmptyDB>, ()>)> {
        run_tx_on_tip1060_contract_with_setup(mode, contract, bytecode, |_, _| Ok(()))
    }

    fn run_tx_on_tip1060_contract_with_setup(
        mode: CreditMode,
        contract: Address,
        bytecode: &[u8],
        setup: impl FnOnce(&mut TempoEvm<CacheDB<EmptyDB>, ()>, Address) -> eyre::Result<()>,
    ) -> eyre::Result<(u64, TempoEvm<CacheDB<EmptyDB>, ()>)> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let mut evm = create_funded_evm_t7(caller);

        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(bytecode_with_tip1060_mode(mode, bytecode)),
                ..Default::default()
            },
        );
        setup(&mut evm, contract)?;

        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(2_000_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;
        let result = evm.transact_commit(TempoTxEnv::from_recovered_tx(&signed_tx, caller))?;
        assert!(result.is_success(), "test transaction should succeed");

        Ok((result.tx_gas_used(), evm))
    }

    fn mint_storage_credits_with_clears(
        evm: &mut TempoEvm<CacheDB<EmptyDB>, ()>,
        key_pair: &P256KeyPair,
        caller: Address,
        contract: Address,
        nonce: u64,
        credits: u64,
    ) -> eyre::Result<u64> {
        if credits == 0 {
            return Ok(nonce);
        }

        let mut body = Vec::new();
        for credit in 0..credits {
            let slot = 0xf0 + credit;
            assert!(slot <= u64::from(u8::MAX));
            evm.ctx
                .db_mut()
                .insert_account_storage(contract, U256::from(slot), U256::ONE)?;
            body.extend_from_slice(&[opcode::PUSH1, 0, opcode::PUSH1, slot as u8, opcode::SSTORE]);
        }
        body.push(opcode::STOP);

        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(Bytecode::new_raw(body.into())),
                ..Default::default()
            },
        );

        let tx = TxBuilder::new()
            .call(contract, &[])
            .nonce(nonce)
            .gas_limit(2_000_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;
        let result = evm.transact_commit(TempoTxEnv::from_recovered_tx(&signed_tx, caller))?;
        assert!(result.is_success(), "credit-minting prelude should succeed");
        assert_eq!(
            storage_credit_balance(evm, contract),
            credits,
            "prelude should mint the requested storage credits"
        );

        Ok(nonce + 1)
    }

    fn branching_bytecode_with_tip1060_mode(mode: CreditMode) -> Bytecode {
        let mut bytecode = Vec::new();
        if mode != CreditMode::Refund {
            append_tip1060_set_mode_call(&mut bytecode, mode);
        }

        let create_only_dest = bytecode.len() + 15;
        assert!(create_only_dest <= u8::MAX as usize);

        bytecode.extend_from_slice(&[
            opcode::CALLDATASIZE,
            opcode::PUSH1,
            create_only_dest as u8,
            opcode::JUMPI,
        ]);
        bytecode.extend_from_slice(&bytes!("6001600055600060005500"));
        bytecode.push(opcode::JUMPDEST);
        bytecode.extend_from_slice(&bytes!("600160005500"));
        Bytecode::new_raw(bytecode.into())
    }

    #[test]
    fn test_tip1060_storage_credits_delegatecall_rejected() -> eyre::Result<()> {
        let calldata = IStorageCredits::setModeCall {
            newMode: Mode::Direct,
        }
        .abi_encode();

        for (call_opcode, contract) in [
            (opcode::DELEGATECALL, Address::repeat_byte(0x61)),
            (opcode::CALLCODE, Address::repeat_byte(0x62)),
        ] {
            let key_pair = P256KeyPair::random();
            let caller = key_pair.address;
            let mut bytecode = Vec::new();
            for (i, &byte) in calldata.iter().enumerate() {
                assert!(i <= u8::MAX as usize);
                bytecode.extend_from_slice(&[
                    opcode::PUSH1,
                    byte,
                    opcode::PUSH1,
                    i as u8,
                    opcode::MSTORE8,
                ]);
            }

            // DELEGATECALL/CALLCODE into the storage credits precompile, then bubble the returned
            // custom error.
            // PUSH1 0x00 PUSH1 0x00 PUSH1 <argsSize> PUSH1 0x00
            bytecode.extend_from_slice(&bytes!("60006000"));
            bytecode.extend_from_slice(&[opcode::PUSH1, calldata.len() as u8]);
            bytecode.extend_from_slice(&bytes!("6000"));
            if call_opcode == opcode::CALLCODE {
                // CALLCODE also takes a value argument.
                bytecode.extend_from_slice(&bytes!("6000"));
            }
            bytecode.push(opcode::PUSH20);
            bytecode.extend_from_slice(STORAGE_CREDITS_ADDRESS.as_slice());
            // PUSH3 0x0f4240 <DELEGATECALL|CALLCODE> POP
            bytecode.extend_from_slice(&bytes!("620f4240"));
            bytecode.push(call_opcode);
            bytecode.push(opcode::POP);
            // RETURNDATASIZE PUSH1 0x00 PUSH1 0x00 RETURNDATACOPY RETURNDATASIZE PUSH1 0x00 REVERT
            bytecode.extend_from_slice(&bytes!("3d600060003e3d6000fd"));

            let mut evm = create_funded_evm_t7(caller);
            evm.ctx.db_mut().insert_account_info(
                contract,
                AccountInfo {
                    code: Some(Bytecode::new_raw(bytecode.into())),
                    ..Default::default()
                },
            );

            let tx = TxBuilder::new()
                .call(contract, &[])
                .gas_limit(1_000_000)
                .build();
            let signed_tx = key_pair.sign_tx(tx)?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            if let ExecutionResult::Revert { output, .. } = evm.transact_commit(tx_env)? {
                assert_eq!(
                    output.as_ref(),
                    DelegateCallNotAllowed {}.abi_encode().as_slice()
                );
            } else {
                panic!("expected DelegateCallNotAllowed revert");
            }
        }

        Ok(())
    }

    /// TIP-1060: mode changes must not overwrite the pending-refund counter or persist mode state.
    ///
    /// The tx first creates a slot in default Refund mode, then calls `setMode`. Settlement must
    /// read only `pending_refunds`, not confuse the transient mode bits with a credit balance.
    #[test]
    fn test_tip1060_refund_settlement_uses_pending_field_not_mode() -> eyre::Result<()> {
        for mode in [CreditMode::Refund, CreditMode::Preserve, CreditMode::Direct] {
            let key_pair = P256KeyPair::random();
            let caller = key_pair.address;
            let contract = Address::repeat_byte(0x62);

            // Bytecode starts with a 0->1 create in Refund mode:
            // PUSH1 0x01 PUSH1 0x00 SSTORE  (store 0x01 at slot 0)
            let mut bytecode = bytes!("6001600055").to_vec();
            append_tip1060_set_mode_call(&mut bytecode, mode);
            bytecode.push(opcode::STOP);

            let mut evm = create_funded_evm_t7(caller);
            evm.ctx.db_mut().insert_account_info(
                contract,
                AccountInfo {
                    code: Some(Bytecode::new_raw(bytecode.into())),
                    ..Default::default()
                },
            );

            let tx = TxBuilder::new()
                .call(contract, &[])
                .gas_limit(2_000_000)
                .build();
            let signed_tx = key_pair.sign_tx(tx)?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact_commit(tx_env)?;
            assert!(result.is_success());

            assert_eq!(
                storage_credit_balance(&evm, contract),
                0,
                "settlement must not consume the transient mode field as storage credit balance in {mode:?} mode"
            );
            assert_eq!(
                storage_credit_word(&evm, contract),
                U256::ZERO,
                "mode is transient and must not persist in the storage credit state word in {mode:?} mode"
            );
        }

        Ok(())
    }

    /// TIP-1060: `setMode` only updates transient state and must not touch persistent credits.
    ///
    /// A low gas limit proves `setMode` does not pay TIP-1000 storage creation gas. The pre-seeded
    /// self-credit sentinel proves TIP-1060 bookkeeping does not recursively consume itself.
    #[test]
    fn test_tip1060_set_mode_uses_transient_state_only() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let mut evm = create_funded_evm_t7(caller);
        evm.ctx.db_mut().insert_account_info(
            caller,
            AccountInfo {
                balance: U256::from(DEFAULT_BALANCE),
                nonce: 1,
                ..Default::default()
            },
        );

        // Sentinel: recursive TIP-1060 accounting would consume this pre-seeded self credit.
        seed_storage_credit_balance(&mut evm, STORAGE_CREDITS_ADDRESS, 1);

        let calldata = IStorageCredits::setModeCall {
            newMode: Mode::Preserve,
        }
        .abi_encode();

        let tx = TxBuilder::new()
            .call(STORAGE_CREDITS_ADDRESS, &calldata)
            .nonce(1)
            // should succeed because setMode is a transient write with no TIP-1000 component.
            .gas_limit(50_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(
            result.is_success(),
            "setMode should not need the 250k TIP-1000 storage-creation charge"
        );
        assert!(
            result.tx_gas_used() < 50_000,
            "setMode should fit under the low gas limit as a transient write"
        );

        assert_eq!(
            storage_credit_balance(&evm, caller),
            0,
            "setMode must not mint caller credits"
        );
        assert_eq!(
            storage_credit_word(&evm, caller),
            U256::ZERO,
            "setMode must not create or update persistent caller state"
        );

        // Sentinel: setMode must not consume the precompile's own pre-seeded credit.
        assert_eq!(
            storage_credit_balance(&evm, STORAGE_CREDITS_ADDRESS),
            1,
            "storage-credits bookkeeping must not recursively consume its own storage credits"
        );

        Ok(())
    }

    /// TIP-1060: clearing a nonzero slot mints one credit and disables legacy SSTORE refunds.
    ///
    /// Slot 0 is seeded non-zero before the tx. The clear should mint a storage credit instead of
    /// using the legacy EVM refund counter.
    #[test]
    fn test_tip1060_sstore_clear_mints_storage_credit_without_legacy_refund() -> eyre::Result<()> {
        // PUSH1 0x00 PUSH1 0x00 SSTORE STOP: clear slot 0.
        let clear_bytecode = Bytecode::new_raw(bytes!("600060005500"));

        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let contract = Address::repeat_byte(0x63);

        let mut evm = create_funded_evm_t7(caller);
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(clear_bytecode),
                ..Default::default()
            },
        );
        evm.ctx
            .db_mut()
            .insert_account_storage(contract, U256::ZERO, U256::ONE)?;

        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(2_000_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success(), "clear tx should succeed");
        assert_eq!(
            result.gas().inner_refunded(),
            0,
            "TIP-1060 removes the legacy SSTORE clearing refund"
        );
        assert_eq!(
            storage_credit_balance(&evm, contract),
            1,
            "clearing a nonzero slot should mint one storage credit"
        );

        Ok(())
    }

    /// TIP-1060: `0->1->0` pays creation cost, then mints/settles according to mode.
    ///
    /// Preserve/Direct keep the clear-minted credit. Refund consumes it against the deferred
    /// creation refund at end-of-tx.
    #[test]
    fn test_tip1060_sstore_create_then_clear_modes() -> eyre::Result<()> {
        // PUSH1 0x00 PUSH1 0x00 SSTORE STOP: no-op write to an empty slot.
        let noop_body = bytes!("600060005500");
        let (noop_gas, _) =
            run_tx_on_tip1060_contract(CreditMode::Refund, Address::repeat_byte(0x60), &noop_body)?;

        // PUSH1 0x01 PUSH1 0x00 SSTORE  PUSH1 0x00 PUSH1 0x00 SSTORE  STOP
        let create_clear_body = bytes!("6001600055600060005500");

        // (mode, gas used, final credit balance).
        // The 0->1->0 clear restores slot 0 to its transaction-original value (0), so T7 refunds
        // only the 5k residual set charge. The 245k credit depends on the TIP-1060 credit mode.
        let cases = [
            (CreditMode::Refund, 285_968u64, 0u64),
            (CreditMode::Preserve, 534_133u64, 1u64),
            (CreditMode::Direct, 534_133u64, 1u64),
        ];

        for (case_id, (mode, expected_gas, expected_balance)) in cases.into_iter().enumerate() {
            let contract = Address::repeat_byte(0x60 + case_id as u8);
            let (gas_used, evm) = run_tx_on_tip1060_contract(mode, contract, &create_clear_body)?;

            assert!(
                gas_used >= noop_gas,
                "0->x->0 storage churn must not reduce tx gas below no-op: noop={noop_gas}, create_clear={gas_used}"
            );

            assert_eq!(
                gas_used, expected_gas,
                "TIP-1060 create+clear gas should be exact in {mode:?} mode"
            );

            assert_eq!(
                storage_credit_balance(&evm, contract),
                expected_balance,
                "TIP-1060 post-tx storage credit balance should be exact in {mode:?} mode"
            );
        }

        Ok(())
    }

    /// TIP-1060: the spec transition table classifies every zero-crossing exactly once.
    #[test]
    fn test_tip1060_spec_transition_classes_credit_accounting_table() -> eyre::Result<()> {
        fn append_sstore(body: &mut Vec<u8>, slot: u8, value: u8) {
            body.extend_from_slice(&[opcode::PUSH1, value, opcode::PUSH1, slot, opcode::SSTORE]);
        }

        fn transition_body(setup_value: Option<u8>, new_value: u8) -> Bytes {
            let mut body = Vec::new();
            if let Some(value) = setup_value {
                append_sstore(&mut body, 0, value);
            }
            append_sstore(&mut body, 0, new_value);
            body.push(opcode::STOP);
            body.into()
        }

        #[derive(Clone, Copy)]
        struct ModeExpectation {
            mode: CreditMode,
            expected_gas: u64,
            expected_credits: u64,
        }

        struct CreditCase {
            name: &'static str,
            initial_credits: u64,
            expectations: [ModeExpectation; 3],
        }

        struct TransitionClass {
            name: &'static str,
            original: u8,
            setup_value: Option<u8>,
            new_value: u8,
            expected_slot: u64,
            credit_cases: Vec<CreditCase>,
        }

        fn expectations(
            refund: (u64, u64),
            preserve: (u64, u64),
            direct: (u64, u64),
        ) -> [ModeExpectation; 3] {
            [
                ModeExpectation {
                    mode: CreditMode::Refund,
                    expected_gas: refund.0,
                    expected_credits: refund.1,
                },
                ModeExpectation {
                    mode: CreditMode::Preserve,
                    expected_gas: preserve.0,
                    expected_credits: preserve.1,
                },
                ModeExpectation {
                    mode: CreditMode::Direct,
                    expected_gas: direct.0,
                    expected_credits: direct.1,
                },
            ]
        }

        const SET_MODE_GAS: u64 = 3_165;

        fn same_storage_accounting(refund_gas: u64, expected_credits: u64) -> [ModeExpectation; 3] {
            expectations(
                (refund_gas, expected_credits),
                (refund_gas + SET_MODE_GAS, expected_credits),
                (refund_gas + SET_MODE_GAS, expected_credits),
            )
        }

        fn no_initial_credits(expectations: [ModeExpectation; 3]) -> Vec<CreditCase> {
            vec![CreditCase {
                name: "no initial credits",
                initial_credits: 0,
                expectations,
            }]
        }

        let transition_classes = [
            TransitionClass {
                name: "O=0 P=0 N=0 no-op",
                original: 0,
                setup_value: None,
                new_value: 0,
                expected_slot: 0,
                credit_cases: no_initial_credits(same_storage_accounting(30_862, 0)),
            },
            TransitionClass {
                name: "O=0 P=Y N=Y same-tx no-op",
                original: 0,
                setup_value: Some(2),
                new_value: 2,
                expected_slot: 2,
                credit_cases: no_initial_credits(same_storage_accounting(283_068, 0)),
            },
            TransitionClass {
                name: "O=0 P=Y N=Z dirty overwrite",
                original: 0,
                setup_value: Some(2),
                new_value: 3,
                expected_slot: 3,
                credit_cases: no_initial_credits(same_storage_accounting(283_068, 0)),
            },
            TransitionClass {
                name: "O=X P=X N=X no-op",
                original: 1,
                setup_value: None,
                new_value: 1,
                expected_slot: 1,
                credit_cases: no_initial_credits(same_storage_accounting(30_862, 0)),
            },
            TransitionClass {
                name: "O=X P=X N=Y clean overwrite",
                original: 1,
                setup_value: None,
                new_value: 2,
                expected_slot: 2,
                credit_cases: no_initial_credits(same_storage_accounting(33_662, 0)),
            },
            TransitionClass {
                name: "O=X P=Y N=X dirty restore to original",
                original: 1,
                setup_value: Some(2),
                new_value: 1,
                expected_slot: 1,
                credit_cases: no_initial_credits(same_storage_accounting(30_968, 0)),
            },
            TransitionClass {
                name: "O=X P=Y N=Z dirty overwrite",
                original: 1,
                setup_value: Some(2),
                new_value: 3,
                expected_slot: 3,
                credit_cases: no_initial_credits(same_storage_accounting(33_768, 0)),
            },
            TransitionClass {
                name: "O=0 P=Y N=0 clear of same-tx creation",
                original: 0,
                setup_value: Some(2),
                new_value: 0,
                expected_slot: 0,
                credit_cases: no_initial_credits(expectations(
                    (35_968, 0),
                    (284_133, 1),
                    (284_133, 1),
                )),
            },
            TransitionClass {
                name: "O=X P=X N=0 clean clear",
                original: 1,
                setup_value: None,
                new_value: 0,
                expected_slot: 0,
                credit_cases: no_initial_credits(same_storage_accounting(38_562, 1)),
            },
            TransitionClass {
                name: "O=X P=Y N=0 dirty clear",
                original: 1,
                setup_value: Some(2),
                new_value: 0,
                expected_slot: 0,
                credit_cases: no_initial_credits(same_storage_accounting(38_668, 1)),
            },
            TransitionClass {
                name: "O=0 P=0 N=Y clean creation",
                original: 0,
                setup_value: None,
                new_value: 2,
                expected_slot: 2,
                credit_cases: vec![
                    CreditCase {
                        name: "no initial credits",
                        initial_credits: 0,
                        expectations: same_storage_accounting(282_962, 0),
                    },
                    CreditCase {
                        name: "one initial credit",
                        initial_credits: 1,
                        expectations: expectations(
                            (37_962, 0),
                            (37_962 + SET_MODE_GAS + STORAGE_CREDIT_VALUE, 1),
                            (43_927, 0),
                        ),
                    },
                    CreditCase {
                        name: "surplus initial credits",
                        initial_credits: 2,
                        expectations: expectations(
                            (37_962, 1),
                            (37_962 + SET_MODE_GAS + STORAGE_CREDIT_VALUE, 2),
                            (43_927, 1),
                        ),
                    },
                ],
            },
            TransitionClass {
                name: "O=X P=0 N=X recreation to original",
                original: 1,
                setup_value: Some(0),
                new_value: 1,
                expected_slot: 1,
                credit_cases: vec![
                    CreditCase {
                        name: "no initial credits",
                        initial_credits: 0,
                        expectations: expectations(
                            (35_968, 0),
                            (35_968 + SET_MODE_GAS + STORAGE_CREDIT_VALUE, 1),
                            (35_968 + SET_MODE_GAS, 0),
                        ),
                    },
                    CreditCase {
                        name: "surplus initial credits",
                        initial_credits: 2,
                        expectations: expectations(
                            (35_968, 2),
                            (35_968 + SET_MODE_GAS + STORAGE_CREDIT_VALUE, 3),
                            (35_968 + SET_MODE_GAS, 2),
                        ),
                    },
                ],
            },
            TransitionClass {
                name: "O=X P=0 N=Y recreation to other value",
                original: 1,
                setup_value: Some(0),
                new_value: 2,
                expected_slot: 2,
                credit_cases: vec![
                    CreditCase {
                        name: "no initial credits",
                        initial_credits: 0,
                        expectations: expectations(
                            (38_768, 0),
                            (38_768 + SET_MODE_GAS + STORAGE_CREDIT_VALUE, 1),
                            (38_768 + SET_MODE_GAS, 0),
                        ),
                    },
                    CreditCase {
                        name: "surplus initial credits",
                        initial_credits: 2,
                        expectations: expectations(
                            (38_768, 2),
                            (38_768 + SET_MODE_GAS + STORAGE_CREDIT_VALUE, 3),
                            (38_768 + SET_MODE_GAS, 2),
                        ),
                    },
                ],
            },
        ];

        let mut case_id = 0u8;
        for scenario in transition_classes {
            for credit_case in &scenario.credit_cases {
                for expectation in credit_case.expectations {
                    let mode = expectation.mode;
                    let key_pair = P256KeyPair::random();
                    let caller = key_pair.address;
                    let contract = Address::repeat_byte(0x80 + case_id);
                    case_id += 1;
                    let body = transition_body(scenario.setup_value, scenario.new_value);

                    let mut evm = create_funded_evm_t7(caller);
                    fund_account_with_nonce(&mut evm, caller, 1);
                    if scenario.original != 0 {
                        evm.ctx.db_mut().insert_account_storage(
                            contract,
                            U256::ZERO,
                            U256::from(scenario.original),
                        )?;
                    }
                    let nonce = mint_storage_credits_with_clears(
                        &mut evm,
                        &key_pair,
                        caller,
                        contract,
                        1,
                        credit_case.initial_credits,
                    )?;

                    evm.ctx.db_mut().insert_account_info(
                        contract,
                        AccountInfo {
                            code: Some(bytecode_with_tip1060_mode(mode, &body)),
                            ..Default::default()
                        },
                    );

                    let tx = TxBuilder::new()
                        .call(contract, &[])
                        .nonce(nonce)
                        .gas_limit(2_000_000)
                        .build();
                    let signed_tx = key_pair.sign_tx(tx)?;
                    let result =
                        evm.transact_commit(TempoTxEnv::from_recovered_tx(&signed_tx, caller))?;
                    assert!(
                        result.is_success(),
                        "{} / {} in {mode:?} should succeed",
                        scenario.name,
                        credit_case.name
                    );

                    assert_eq!(
                        result.tx_gas_used(),
                        expectation.expected_gas,
                        "{} / {} gas should stay exact in {mode:?}",
                        scenario.name,
                        credit_case.name
                    );
                    assert_eq!(
                        storage_credit_balance(&evm, contract),
                        expectation.expected_credits,
                        "{} / {} final persistent credit balance should stay exact in {mode:?}",
                        scenario.name,
                        credit_case.name
                    );
                    assert_eq!(
                        evm.ctx.db().storage_ref(contract, U256::ZERO)?,
                        U256::from(scenario.expected_slot),
                        "{} / {} should leave the expected slot value in {mode:?}",
                        scenario.name,
                        credit_case.name
                    );
                }
            }
        }

        Ok(())
    }

    /// TIP-1060: Preserve churn of a pre-existing slot cannot subsidize fresh Direct creates.
    ///
    /// Each clear mints a credit, but in Preserve mode the matching recreation pays the 245k
    /// creditable portion as gas, so accumulating churned credits costs full price per credit and
    /// cannot fund cheaper Direct creates. Here the 500-cycle Preserve churn exhausts gas (each
    /// recreation costs 245k) before the Direct phase runs, so the transaction reverts.
    #[test]
    fn test_tip1060_preserve_churn_attack() -> eyre::Result<()> {
        use alloy_primitives::{Address, Bytes, TxKind, U256, hex};
        use revm::{
            Context, Database, ExecuteCommitEvm, MainContext,
            context::{CfgEnv, TxEnv},
            database::{CacheDB, EmptyDB},
            state::AccountInfo,
        };
        use tempo_chainspec::hardfork::TempoHardfork;
        use tempo_precompiles::{STORAGE_CREDITS_ADDRESS, storage_credits::StorageCredits};

        use crate::{TempoBlockEnv, TempoEvm, gas_params::tempo_gas_params};

        // Initcode:
        //   constructor: SSTORE(0, 1)
        //   runtime: setMode(Preserve); 500x clear/restore slot0; setMode(Direct); 500x create
        // Selector 0x21175b4a = setMode(uint8); precompile = 0x1060...0000.
        let init = Bytes::from(
            hex!(
                "60016000556100a660136000396100a66000f3\
                60216000536017600153605b600253604a6003536001602353\
                6000600060246000600073106000000000000000000000000000000000000\
                05af1506101f45b60006000556002600055600190038061003e5750\
                60216000536017600153605b600253604a6003536002602353\
                6000600060246000600073106000000000000000000000000000000000000\
                05af1506101f45b8061010001600190556001900380610091575000"
            )
            .to_vec(),
        );

        let caller = Address::repeat_byte(0x11);
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = TempoHardfork::T7;
        cfg.gas_params = tempo_gas_params(TempoHardfork::T7);
        const GAS_LIMIT: u64 = 16_777_216;
        let mut block = TempoBlockEnv::default();
        block.inner.gas_limit = GAS_LIMIT;
        let ctx = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::new()))
            .with_block(block)
            .with_cfg(cfg)
            .with_tx(Default::default());
        let mut evm = TempoEvm::new(ctx, ());
        evm.ctx.db_mut().insert_account_info(
            caller,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u128),
                ..Default::default()
            },
        );

        // tx#1: deploy; constructor pays the one-time bootstrap creation.
        let deploy = evm.transact_commit(
            TxEnv {
                caller,
                kind: TxKind::Create,
                data: init,
                gas_limit: GAS_LIMIT,
                ..Default::default()
            }
            .into(),
        )?;
        assert!(deploy.is_success(), "deploy reverted/halted: {deploy:?}");
        let contract = deploy
            .created_address()
            .expect("CREATE should yield an address");

        // tx#2: churn in Preserve, then try to spend credits in Direct.
        let call = evm.transact_commit(
            TxEnv {
                caller,
                nonce: 1,
                kind: TxKind::Call(contract),
                gas_limit: GAS_LIMIT,
                ..Default::default()
            }
            .into(),
        )?;

        let balance = evm
            .ctx
            .db_mut()
            .storage(STORAGE_CREDITS_ADDRESS, StorageCredits::slot(contract))?
            .as_limbs()[0];
        let slots = evm
            .ctx
            .db_mut()
            .cache
            .accounts
            .get(&contract)
            .map(|a| a.storage.iter().filter(|(_, v)| !v.is_zero()).count())
            .unwrap_or(0);
        eprintln!(
            "tx#2 success/gas: {}/{}  slots: {slots}  bal: {balance}",
            call.is_success(),
            call.tx_gas_used()
        );

        // Each Preserve recreation costs the full 245k creditable portion, so the churn loop
        // exhausts gas and reverts before any churned credit can subsidize a Direct create.
        assert!(!call.is_success());
        assert_eq!(slots, 1);
        assert_eq!(balance, 0);
        Ok(())
    }

    /// TIP-1060: Preserve clear+restore churn mints one credit per clear.
    ///
    /// Slot 0 starts non-zero. TIP-1060 keys minting on the present -> new transition, so every
    /// `nonzero -> 0` clear mints a credit regardless of the slot's original value. In Preserve
    /// mode the matching `0 -> nonzero` recreation pays the 245k creditable portion as gas and does
    /// not consume a credit, so three churn cycles accumulate three credits — each paid for in full,
    /// so the balance growth is not a subsidy.
    #[test]
    fn test_tip1060_preserve_churn_mints_one_credit_per_clear() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let contract = Address::repeat_byte(0x6c);

        // Bytecode body: (SSTORE(0, 0); SSTORE(0, 2)) x 3; STOP.
        let mut body = Vec::new();
        for _ in 0..3 {
            body.extend_from_slice(&bytes!("6000600055")); // SSTORE(0, 0)  clear
            body.extend_from_slice(&bytes!("6002600055")); // SSTORE(0, 2)  dirty restore
        }
        body.push(opcode::STOP);

        let mut evm = create_funded_evm_t7(caller);
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(bytecode_with_tip1060_mode(CreditMode::Preserve, &body)),
                ..Default::default()
            },
        );
        // Slot 0 starts non-zero.
        evm.ctx
            .db_mut()
            .insert_account_storage(contract, U256::ZERO, U256::from(1))
            .unwrap();
        seed_storage_credit_balance(&mut evm, contract, 0);

        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(2_000_000)
            .build();
        let result = evm.transact_commit(TempoTxEnv::from_recovered_tx(
            &key_pair.sign_tx(tx)?,
            caller,
        ))?;
        assert!(result.is_success(), "preserve churn tx should succeed");
        assert_eq!(
            result.tx_gas_used(),
            1_027_757,
            "three Preserve churn cycles pay the full 245k creditable portion per recreation"
        );

        assert_eq!(
            storage_credit_balance(&evm, contract),
            3,
            "each clear mints a credit and Preserve recreations pay 245k without consuming, so \
             three churn cycles accumulate three credits"
        );
        Ok(())
    }

    /// TIP-1060: if a churn credit is spent before restore, the restore repays its value.
    ///
    /// This exercises the reordered case: clear slot 0, spend the credit on a fresh Direct create,
    /// then restore slot 0. With no credit left to burn, the dirty restore must charge repayment.
    #[test]
    fn test_tip1060_dirty_restore_after_direct_spend_repays_credit_value() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let contract = Address::repeat_byte(0x6d);

        // Bytecode body: SSTORE(0,0); SSTORE(1,1); SSTORE(0,2); STOP.
        let mut body = Vec::new();
        body.extend_from_slice(&bytes!("6000600055")); // SSTORE(0, 0)  clear, mints
        body.extend_from_slice(&bytes!("6001600155")); // SSTORE(1, 1)  fresh create, Direct spend
        body.extend_from_slice(&bytes!("6002600055")); // SSTORE(0, 2)  dirty restore, repays
        body.push(opcode::STOP);

        let mut evm = create_funded_evm_t7(caller);
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(bytecode_with_tip1060_mode(CreditMode::Direct, &body)),
                ..Default::default()
            },
        );
        evm.ctx
            .db_mut()
            .insert_account_storage(contract, U256::ZERO, U256::from(1))
            .unwrap();
        seed_storage_credit_balance(&mut evm, contract, 0);

        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(2_000_000)
            .build();
        let result = evm.transact_commit(TempoTxEnv::from_recovered_tx(
            &key_pair.sign_tx(tx)?,
            caller,
        ))?;
        assert!(result.is_success(), "direct reorder tx should succeed");

        // The fresh slot exists, the original slot is restored, and the credit balance nets to zero.
        assert_eq!(
            evm.ctx.db().storage_ref(contract, U256::from(1)).unwrap(),
            U256::from(1),
            "the genuinely new slot must be created"
        );
        assert_eq!(
            evm.ctx.db().storage_ref(contract, U256::ZERO).unwrap(),
            U256::from(2),
            "the churned slot must be restored"
        );
        assert_eq!(
            storage_credit_balance(&evm, contract),
            0,
            "balance must net to zero after mint + Direct spend + dirty-restore repay"
        );
        assert!(
            result.tx_gas_used() > STORAGE_CREDIT_VALUE,
            "the dirty restore must repay the {STORAGE_CREDIT_VALUE} credit value, so the new slot \
             costs full price; got {} gas",
            result.tx_gas_used()
        );
        Ok(())
    }

    /// TIP-1060: credits minted in one tx affect later creates according to the selected mode.
    ///
    /// Empty calldata runs create+clear to mint a credit. Non-empty calldata runs create-only;
    /// Direct spends the prior credit, while Preserve/Refund pay the full creation path.
    #[test]
    fn test_tip1060_minted_storage_credits_affect_second_tx() -> eyre::Result<()> {
        // Branching bytecode: empty calldata -> create+clear; non-empty -> create-only.
        // (mode, tx2 gas, balance after tx1/tx2).
        let cases = [
            (CreditMode::Refund, 282_994u64, 0u64, 0u64),
            (CreditMode::Preserve, 286_159u64, 1u64, 1u64),
            (CreditMode::Direct, 43_959u64, 1u64, 0u64),
        ];

        for (mode, expected_second_gas, expected_credit_tx1, expected_credit_tx2) in cases {
            let key_pair = P256KeyPair::random();
            let caller = key_pair.address;
            let contract = Address::repeat_byte(0x61);

            let mut evm = create_funded_evm_t7(caller);

            evm.ctx.db_mut().insert_account_info(
                contract,
                AccountInfo {
                    code: Some(branching_bytecode_with_tip1060_mode(mode)),
                    ..Default::default()
                },
            );
            seed_storage_credit_balance(&mut evm, contract, 0);

            // First tx: create+clear to mint.
            let tx1 = TxBuilder::new()
                .call(contract, &[])
                .nonce(0)
                .gas_limit(2_000_000)
                .build();
            let signed_tx1 = key_pair.sign_tx(tx1)?;
            let tx_env1 = TempoTxEnv::from_recovered_tx(&signed_tx1, caller);
            let result1 = evm.transact_commit(tx_env1)?;
            assert!(
                result1.is_success(),
                "minting tx should succeed in {mode:?} mode"
            );
            assert_eq!(
                storage_credit_balance(&evm, contract),
                expected_credit_tx1,
                "storage credit balance after the minting tx should be exact in {mode:?} mode"
            );

            // Second transaction: create one slot; only Direct spends the prior credit.
            let tx2 = TxBuilder::new()
                .call(contract, &[0x01])
                .nonce(1)
                .gas_limit(2_000_000)
                .build();
            let signed_tx2 = key_pair.sign_tx(tx2)?;
            let tx_env2 = TempoTxEnv::from_recovered_tx(&signed_tx2, caller);
            let result2 = evm.transact_commit(tx_env2)?;
            assert!(
                result2.is_success(),
                "create-only tx should succeed in {mode:?} mode"
            );

            let second_gas = result2.tx_gas_used();
            assert_eq!(
                second_gas, expected_second_gas,
                "TIP-1060 second-tx create gas should be exact in {mode:?} mode"
            );

            assert_eq!(
                storage_credit_balance(&evm, contract),
                expected_credit_tx2,
                "storage credit balance after the create-only tx should be exact in {mode:?} mode"
            );
        }

        Ok(())
    }

    /// TIP-1060: `setBudget(n)` caps Direct credit spending.
    ///
    /// Both contracts start with two credits and create two slots. `setBudget(1)` should discount
    /// only the first create; after the budget is exhausted, Direct stays selected but charges like
    /// Preserve. Plain `setMode(Direct)` has unlimited budget and discounts both.
    #[test]
    fn test_tip1060_direct_budget_caps_credit_consumption() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let budgeted_contract = Address::repeat_byte(0x86);
        let unlimited_contract = Address::repeat_byte(0x87);

        let mut budgeted_bytecode = Vec::new();
        let set_budget_input = IStorageCredits::setBudgetCall { credits: 1 }.abi_encode();
        append_tip1060_precompile_call(&mut budgeted_bytecode, &set_budget_input);
        budgeted_bytecode.extend_from_slice(&bytes!("6001600055600160015500"));

        let unlimited_bytecode =
            bytecode_with_tip1060_mode(CreditMode::Direct, &bytes!("6001600055600160015500"));

        let mut evm = create_funded_evm_t7(caller);
        evm.ctx.db_mut().insert_account_info(
            budgeted_contract,
            AccountInfo {
                code: Some(Bytecode::new_raw(budgeted_bytecode.into())),
                ..Default::default()
            },
        );
        evm.ctx.db_mut().insert_account_info(
            unlimited_contract,
            AccountInfo {
                code: Some(unlimited_bytecode),
                ..Default::default()
            },
        );
        seed_storage_credit_balance(&mut evm, budgeted_contract, 2);
        seed_storage_credit_balance(&mut evm, unlimited_contract, 2);

        let budgeted_tx = TxBuilder::new()
            .call(budgeted_contract, &[])
            .nonce(0)
            .gas_limit(2_000_000)
            .build();
        let budgeted_result = evm.transact_commit(TempoTxEnv::from_recovered_tx(
            &key_pair.sign_tx(budgeted_tx)?,
            caller,
        ))?;
        assert!(budgeted_result.is_success());
        assert_eq!(
            storage_credit_balance(&evm, budgeted_contract),
            1,
            "budget 1 must consume exactly one of the two available credits"
        );

        let unlimited_tx = TxBuilder::new()
            .call(unlimited_contract, &[])
            .nonce(1)
            .gas_limit(2_000_000)
            .build();
        let unlimited_result = evm.transact_commit(TempoTxEnv::from_recovered_tx(
            &key_pair.sign_tx(unlimited_tx)?,
            caller,
        ))?;
        assert!(unlimited_result.is_success());
        assert_eq!(
            storage_credit_balance(&evm, unlimited_contract),
            0,
            "setMode(Direct) has unlimited budget and must consume both available credits"
        );
        assert!(
            budgeted_result.tx_gas_used() > unlimited_result.tx_gas_used(),
            "the budgeted second create should pay full creation gas after the Direct budget is exhausted"
        );

        Ok(())
    }

    #[test]
    fn test_tip1060_exhausted_direct_budget_stays_direct() -> eyre::Result<()> {
        const MODE_SLOT: u8 = 3;
        const EXHAUSTED_GAS: (u8, u8) = (4, 5);
        const AFTER_CLEAR_GAS: (u8, u8) = (6, 7);

        let store_gas = |bytecode: &mut Vec<u8>, slot: u8| {
            bytecode.extend_from_slice(&[opcode::GAS, opcode::PUSH1, slot, opcode::SSTORE]);
        };
        let contract = Address::repeat_byte(0x88);
        let mut bytecode = Vec::new();

        append_tip1060_precompile_call(
            &mut bytecode,
            &IStorageCredits::setBudgetCall { credits: 1 }.abi_encode(),
        );
        bytecode.extend_from_slice(&bytes!("6001600055")); // budgeted create
        append_tip1060_precompile_call_store_return(
            &mut bytecode,
            &IStorageCredits::modeOfCall { account: contract }.abi_encode(),
            Some(MODE_SLOT),
        );
        store_gas(&mut bytecode, EXHAUSTED_GAS.0);
        bytecode.extend_from_slice(&bytes!("6001600155")); // create while exhausted
        store_gas(&mut bytecode, EXHAUSTED_GAS.1);
        bytecode.extend_from_slice(&bytes!("6000600155")); // clear: mint credit, not budget
        store_gas(&mut bytecode, AFTER_CLEAR_GAS.0);
        bytecode.extend_from_slice(&bytes!("6001600255")); // still exhausted after clear
        store_gas(&mut bytecode, AFTER_CLEAR_GAS.1);
        bytecode.push(opcode::STOP);

        let (_, evm) = run_tx_on_tip1060_contract_with_setup(
            CreditMode::Refund,
            contract,
            &bytecode,
            |evm, contract| {
                seed_storage_credit_balance(evm, contract, 2);
                for slot in MODE_SLOT..=AFTER_CLEAR_GAS.1 {
                    evm.ctx.db_mut().insert_account_storage(
                        contract,
                        U256::from(slot),
                        U256::ONE,
                    )?;
                }
                Ok(())
            },
        )?;

        let word = |slot: u8| {
            evm.ctx
                .db()
                .storage_ref(contract, U256::from(slot))
                .unwrap()
        };
        let delta = |slots: (u8, u8)| word(slots.0).as_limbs()[0] - word(slots.1).as_limbs()[0];

        assert!(
            delta(EXHAUSTED_GAS) > STORAGE_CREDIT_VALUE
                && delta(AFTER_CLEAR_GAS) > STORAGE_CREDIT_VALUE,
            "both exhausted creates must pay full creditable gas"
        );
        let expected = (U256::from(CreditMode::Direct as u8), U256::ZERO, U256::ONE);
        assert_eq!((word(MODE_SLOT), word(1), word(2)), expected);
        assert_eq!(storage_credit_balance(&evm, contract), 2);

        Ok(())
    }

    #[test]
    fn test_tip1060_reverted_scopes_unwind_credit_accounting() -> eyre::Result<()> {
        struct RevertedCase {
            name: &'static str,
            callee: Address,
            bytecode: Bytecode,
            initial_slot: U256,
            initial_credits: u64,
            expected_slot: U256,
            expected_credits: u64,
        }

        fn caller_ignoring_reverted_callee(callee: Address) -> Bytecode {
            let mut bytecode = bytes!("60006000600060006000").to_vec();
            bytecode.push(opcode::PUSH20);
            bytecode.extend_from_slice(callee.as_slice());
            bytecode.extend_from_slice(&bytes!("620f4240f15000"));
            Bytecode::new_raw(bytecode.into())
        }

        let mut direct_create_revert = Vec::new();
        append_tip1060_set_mode_call(&mut direct_create_revert, CreditMode::Direct);
        direct_create_revert.extend_from_slice(&bytes!("600160005560006000fd"));

        let cases = [
            RevertedCase {
                name: "clear mint",
                callee: Address::repeat_byte(0x89),
                // SSTORE(0, 0); REVERT(0, 0)
                bytecode: Bytecode::new_raw(bytes!("600060005560006000fd")),
                initial_slot: U256::ONE,
                initial_credits: 0,
                expected_slot: U256::ONE,
                expected_credits: 0,
            },
            RevertedCase {
                name: "Refund pending creation",
                callee: Address::repeat_byte(0x8a),
                // SSTORE(0, 1); REVERT(0, 0)
                bytecode: Bytecode::new_raw(bytes!("600160005560006000fd")),
                initial_slot: U256::ZERO,
                initial_credits: 1,
                expected_slot: U256::ZERO,
                expected_credits: 1,
            },
            RevertedCase {
                name: "Direct debit",
                callee: Address::repeat_byte(0x8b),
                bytecode: Bytecode::new_raw(direct_create_revert.into()),
                initial_slot: U256::ZERO,
                initial_credits: 1,
                expected_slot: U256::ZERO,
                expected_credits: 1,
            },
        ];

        for case in cases {
            let key_pair = P256KeyPair::random();
            let caller = key_pair.address;
            let caller_contract = Address::repeat_byte(case.callee[0] ^ 0xff);
            let mut evm = create_funded_evm_t7(caller);

            evm.ctx.db_mut().insert_account_info(
                caller_contract,
                AccountInfo {
                    code: Some(caller_ignoring_reverted_callee(case.callee)),
                    ..Default::default()
                },
            );
            evm.ctx.db_mut().insert_account_info(
                case.callee,
                AccountInfo {
                    code: Some(case.bytecode.clone()),
                    ..Default::default()
                },
            );
            if !case.initial_slot.is_zero() {
                evm.ctx.db_mut().insert_account_storage(
                    case.callee,
                    U256::ZERO,
                    case.initial_slot,
                )?;
            }
            seed_storage_credit_balance(&mut evm, case.callee, case.initial_credits);

            let tx = TxBuilder::new()
                .call(caller_contract, &[])
                .gas_limit(2_000_000)
                .build();
            let result = evm.transact_commit(TempoTxEnv::from_recovered_tx(
                &key_pair.sign_tx(tx)?,
                caller,
            ))?;
            assert!(
                result.is_success(),
                "top-level caller should ignore the reverted {} subcall",
                case.name
            );

            assert_eq!(
                evm.ctx.db().storage_ref(case.callee, U256::ZERO)?,
                case.expected_slot,
                "reverted {} storage write must unwind",
                case.name
            );
            assert_eq!(
                storage_credit_balance(&evm, case.callee),
                case.expected_credits,
                "reverted {} credit accounting must unwind",
                case.name
            );
        }

        Ok(())
    }

    /// TIP-1060: Refund settlement consumes exactly `min(pending_creations, balance)`.
    ///
    /// End-of-tx settlement may consume no more credits than either pending creations or starting
    /// balance.
    #[test]
    fn test_tip1060_refund_settlement_min_pending_balance() -> eyre::Result<()> {
        // (creates, starting balance, final balance).
        let cases = [(2u8, 1u64, 0u64), (1u8, 2u64, 1u64)];

        for (creates, starting_balance, expected_balance) in cases {
            let contract = Address::repeat_byte(0x70 + creates);

            // Write 0x01 to `creates` fresh slots, then STOP.
            let mut bytecode = Vec::new();
            for slot in 0..creates {
                bytecode.extend_from_slice(&[
                    opcode::PUSH1,
                    0x01,
                    opcode::PUSH1,
                    slot,
                    opcode::SSTORE,
                ]);
            }
            bytecode.push(opcode::STOP);

            let (_, evm) = run_tx_on_tip1060_contract_with_setup(
                CreditMode::Refund,
                contract,
                &bytecode,
                |evm, contract| {
                    seed_storage_credit_balance(evm, contract, starting_balance);
                    Ok(())
                },
            )?;

            assert_eq!(
                storage_credit_balance(&evm, contract),
                expected_balance,
                "settlement must consume exactly min(pending, balance) storage credits"
            );
        }

        Ok(())
    }

    /// TIP-1060: Refund settlement is per-account, including across nested calls.
    ///
    /// A creates one slot and calls B, which creates one slot too. A's surplus credits must not be
    /// used to settle B's pending Refund creation.
    #[test]
    fn test_tip1060_refund_settlement_is_per_account() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let account_a = Address::repeat_byte(0xa0);
        let account_b = Address::repeat_byte(0xb0);

        // A bytecode: SSTORE(0,1), then CALL B.
        let mut account_a_bytecode = bytes!("600160005560006000600060006000").to_vec();
        account_a_bytecode.push(opcode::PUSH20);
        account_a_bytecode.extend_from_slice(account_b.as_slice());
        account_a_bytecode.extend_from_slice(&bytes!("620f4240f15000"));

        // B bytecode: SSTORE(0,1); STOP.
        let account_b_bytecode = Bytecode::new_raw(bytes!("600160005500"));

        let mut evm = create_funded_evm_t7(caller);
        evm.ctx.db_mut().insert_account_info(
            account_a,
            AccountInfo {
                code: Some(Bytecode::new_raw(account_a_bytecode.into())),
                ..Default::default()
            },
        );
        evm.ctx.db_mut().insert_account_info(
            account_b,
            AccountInfo {
                code: Some(account_b_bytecode),
                ..Default::default()
            },
        );
        seed_storage_credit_balance(&mut evm, account_a, 2);
        seed_storage_credit_balance(&mut evm, account_b, 0);

        let tx = TxBuilder::new()
            .call(account_a, &[])
            .gas_limit(2_000_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);
        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success(), "multi-account tx should succeed");

        assert_eq!(
            storage_credit_balance(&evm, account_a),
            1,
            "A consumes its own storage credits"
        );
        assert_eq!(
            storage_credit_balance(&evm, account_b),
            0,
            "B cannot consume A's extra storage credits"
        );

        Ok(())
    }

    /// TIP-1060: same-tx clear can settle an earlier Refund create on another slot.
    ///
    /// The tx creates slot 0 in Refund mode, then clears pre-existing slot 1. Settlement should use
    /// the later clear-minted credit to refund the earlier creation.
    #[test]
    fn test_tip1060_same_tx_create_before_delete_different_slots() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let contract = Address::repeat_byte(0x64);

        // Bytecode: SSTORE(0,1); SSTORE(1,0); STOP.
        let bytecode = Bytecode::new_raw(bytes!("6001600055600060015500"));

        let mut evm = create_funded_evm_t7(caller);
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(bytecode),
                ..Default::default()
            },
        );
        evm.ctx
            .db_mut()
            .insert_account_storage(contract, U256::from(1), U256::ONE)?;
        seed_storage_credit_balance(&mut evm, contract, 0);

        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(1_000_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);
        let result = evm.transact_commit(tx_env)?;
        assert!(
            result.is_success(),
            "create-before-delete tx should succeed"
        );

        assert_eq!(storage_credit_balance(&evm, contract), 0);
        assert_eq!(
            result.tx_gas_used(),
            295_868,
            "one 245k deferred storage credit is applied"
        );

        Ok(())
    }

    /// TIP-1060: Direct spends synchronously and must not also get Refund settlement.
    ///
    /// Direct and Refund each create one slot. Direct starts with a surplus credit so an accidental
    /// deferred settlement would consume an observable extra credit.
    #[test]
    fn test_tip1060_direct_storage_credits_no_end_of_tx_double_benefit() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let direct_contract = Address::repeat_byte(0x65);
        let refund_contract = Address::repeat_byte(0x66);

        // Bytecode body: SSTORE(0,1); STOP.
        let create_body = bytes!("600160005500");

        let mut evm = create_funded_evm_t7(caller);
        evm.ctx.db_mut().insert_account_info(
            direct_contract,
            AccountInfo {
                code: Some(bytecode_with_tip1060_mode(CreditMode::Direct, &create_body)),
                ..Default::default()
            },
        );
        evm.ctx.db_mut().insert_account_info(
            refund_contract,
            AccountInfo {
                code: Some(bytecode_with_tip1060_mode(CreditMode::Refund, &create_body)),
                ..Default::default()
            },
        );
        // Start with a surplus credit so accidental settlement would be observable.
        seed_storage_credit_balance(&mut evm, direct_contract, 2);
        seed_storage_credit_balance(&mut evm, refund_contract, 1);

        let direct_tx = TxBuilder::new()
            .call(direct_contract, &[])
            .nonce(0)
            .gas_limit(1_000_000)
            .build();
        let signed_direct = key_pair.sign_tx(direct_tx)?;
        let direct = evm.transact_commit(TempoTxEnv::from_recovered_tx(&signed_direct, caller))?;
        assert!(direct.is_success());
        assert_eq!(
            storage_credit_balance(&evm, direct_contract),
            1,
            "Direct must not consume the surplus storage credit at settlement"
        );

        let refund_tx = TxBuilder::new()
            .call(refund_contract, &[])
            .nonce(1)
            .gas_limit(1_000_000)
            .build();
        let signed_refund = key_pair.sign_tx(refund_tx)?;
        let refund = evm.transact_commit(TempoTxEnv::from_recovered_tx(&signed_refund, caller))?;
        assert!(refund.is_success());
        assert_eq!(storage_credit_balance(&evm, refund_contract), 0);

        assert_eq!(
            direct.tx_gas_used(),
            293_927,
            "Direct gets the synchronous discount without an additional settlement refund"
        );
        assert_eq!(
            refund.tx_gas_used(),
            37_962,
            "Refund applies the deferred 245k settlement refund for comparison"
        );

        Ok(())
    }

    /// TIP-1060: clear-mint saturates at `u64::MAX`.
    ///
    /// Slot 0 starts non-zero and the credit balance starts at max. Clearing the slot must keep the
    /// balance pinned at `u64::MAX` rather than overflowing.
    #[test]
    fn test_tip1060_sstore_clear_mint_saturates_at_u64_max() -> eyre::Result<()> {
        let contract = Address::repeat_byte(0x67);

        // Bytecode: SSTORE(0,0); STOP.
        let clear_bytecode = bytes!("600060005500");

        let (_, evm) = run_tx_on_tip1060_contract_with_setup(
            CreditMode::Refund,
            contract,
            &clear_bytecode,
            |evm, contract| {
                evm.ctx
                    .db_mut()
                    .insert_account_storage(contract, U256::ZERO, U256::ONE)?;
                seed_storage_credit_balance(evm, contract, u64::MAX);
                Ok(())
            },
        )?;
        assert_eq!(storage_credit_balance(&evm, contract), u64::MAX);

        Ok(())
    }

    /// Expiring nonce writes are charged manually by intrinsic gas and must not use TIP-1060 accounting.
    #[test]
    fn test_expiring_nonce_indexed_path_does_not_settle_storage_credits() -> eyre::Result<()> {
        use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let timestamp = 1000u64;
        let valid_before = timestamp + 30;

        let tx = TxBuilder::new()
            .call_identity(&[])
            .nonce_key(TEMPO_EXPIRING_NONCE_KEY)
            .valid_before(Some(valid_before))
            .gas_limit(500_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;
        let unindexed_tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let mut indexed_tx_env = unindexed_tx_env.clone();
        indexed_tx_env
            .tempo_tx_env
            .as_mut()
            .expect("expiring nonce tx must be AA")
            .expiring_nonce_idx = Some(1);

        let mut unindexed_evm = create_funded_evm_t7_with_timestamp(caller, timestamp);
        let unindexed_result = unindexed_evm.transact_commit(unindexed_tx_env)?;
        assert!(
            unindexed_result.is_success(),
            "unindexed expiring nonce tx should succeed"
        );

        let mut indexed_evm = create_funded_evm_t7_with_timestamp(caller, timestamp);
        let indexed_result = indexed_evm.transact_commit(indexed_tx_env)?;
        assert!(
            indexed_result.is_success(),
            "indexed expiring nonce tx should succeed"
        );

        assert_eq!(
            indexed_result.tx_gas_used(),
            unindexed_result.tx_gas_used(),
            "pointer restore must not create a TIP-1060 settlement discount"
        );
        assert_eq!(
            storage_credit_balance(&indexed_evm, NONCE_PRECOMPILE_ADDRESS),
            0,
            "expiring nonce bookkeeping must not accrue storage credits"
        );

        Ok(())
    }

    /// 2D nonce writes are charged manually by intrinsic gas and must not use TIP-1060 accounting.
    #[test]
    fn test_2d_nonce_preexecution_does_not_settle_nonce_storage_credits() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let nonce_key = U256::from(42_u64);

        let tx = TxBuilder::new()
            .call_identity(&[])
            .nonce_key(nonce_key)
            .gas_limit(1_000_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let mut baseline_evm = create_funded_evm_t7(caller);
        let baseline_result = baseline_evm.transact_commit(tx_env.clone())?;
        assert!(
            baseline_result.is_success(),
            "baseline 2D nonce tx should succeed"
        );

        let mut credited_evm = create_funded_evm_t7(caller);
        seed_storage_credit_balance(&mut credited_evm, NONCE_PRECOMPILE_ADDRESS, 1);
        let credited_result = credited_evm.transact_commit(tx_env)?;
        assert!(
            credited_result.is_success(),
            "preseeded-credit 2D nonce tx should succeed"
        );

        assert_eq!(
            credited_result.tx_gas_used(),
            baseline_result.tx_gas_used(),
            "2D nonce bookkeeping must not consume nonce storage credits for a gas discount"
        );
        assert_eq!(
            storage_credit_balance(&credited_evm, NONCE_PRECOMPILE_ADDRESS),
            1,
            "2D nonce bookkeeping must not consume pre-existing nonce storage credits"
        );

        Ok(())
    }

    /// Test AA transaction gas for contract creation (CREATE).
    /// TIP-1000 increases TX create cost to 500,000 and new account cost to 250,000.
    /// Uses T1 hardfork for TIP-1000 gas costs.
    #[test]
    fn test_aa_tx_gas_create_contract() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        let mut evm = create_funded_evm_t1(caller);

        // Simple initcode: PUSH1 0x00 PUSH1 0x00 RETURN (deploys empty contract)
        let initcode = vec![0x60, 0x00, 0x60, 0x00, 0xF3];

        // T1 costs: CREATE cost (500k, fixed upfront contract creation cost) + new account for sender (250k) + base costs
        let tx = TxBuilder::new()
            .create(&initcode)
            .gas_limit(1_000_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success(), "CREATE transaction should succeed");

        // With TIP-1000: CREATE cost (500k) + new account for sender (250k) + base costs
        let gas_used = result.tx_gas_used();
        assert_eq!(gas_used, 778720, "T1 CREATE contract gas should be exact");

        Ok(())
    }

    /// TIP-1016: generic EVM CREATE charges deployed-bytecode HASH_COST(L)
    /// in addition to CREATE base gas and code deposit gas on the success path.
    #[test]
    fn test_t4_create_tx_charges_hash_cost() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Initcode that returns a 1-byte runtime (`STOP`), so HASH_COST(L) = 6.
        let tx = TxBuilder::new()
            .create(&hex!("6001600c60003960016000f300"))
            .gas_limit(1_000_000)
            .build();
        let signed_tx = key_pair.sign_tx(tx)?;

        let run_create = |without_word_cost: bool| -> eyre::Result<u64> {
            let mut evm = create_funded_evm_t4(caller);
            if without_word_cost {
                evm.ctx.cfg.gas_params.override_gas(vec![(
                    revm::context_interface::cfg::GasId::keccak256_per_word(),
                    0,
                )]);
            }

            let result = evm.transact_commit(TempoTxEnv::from_recovered_tx(&signed_tx, caller))?;
            assert!(
                result.is_success(),
                "T4 CREATE transaction should succeed with keccak256_per_word={without_word_cost:?}"
            );
            Ok(result.tx_gas_used())
        };

        assert_eq!(
            run_create(false)? - run_create(true)?, // gas_with_hash - gas_without_hash (test fixture)
            tempo_gas_params(TempoHardfork::T4).keccak256_cost(1),
            "generic CREATE should add HASH_COST(L) on top of the non-hash baseline"
        );
        Ok(())
    }

    /// Test AA transaction gas for CREATE with 2D nonce (nonce_key != 0).
    /// When caller account nonce is 0, an additional 250k gas is charged for account creation.
    /// Uses T1 hardfork for TIP-1000 gas costs.
    #[test]
    fn test_aa_tx_gas_create_with_2d_nonce() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        let mut evm = create_funded_evm_t1(caller);

        // Simple initcode: PUSH1 0x00 PUSH1 0x00 RETURN (deploys empty contract)
        let initcode = vec![0x60, 0x00, 0x60, 0x00, 0xF3];
        let nonce_key_2d = U256::from(42);

        // Test 1: CREATE tx with 2D nonce, caller account nonce = 0
        // Should include: CREATE cost (500k) + new account for sender (250k) + 2D nonce sender creation (250k)
        let tx1 = TxBuilder::new()
            .create(&initcode)
            .nonce_key(nonce_key_2d)
            .gas_limit(2_000_000)
            .build();

        // Verify that account nonce is 0 before transaction
        assert_eq!(
            evm.ctx
                .db()
                .basic_ref(caller)
                .ok()
                .flatten()
                .map(|a| a.nonce)
                .unwrap_or(0),
            0,
            "Caller account nonce should be 0 before first tx"
        );

        let signed_tx1 = key_pair.sign_tx(tx1)?;
        let tx_env1 = TempoTxEnv::from_recovered_tx(&signed_tx1, caller);

        let result1 = evm.transact_commit(tx_env1)?;
        assert!(result1.is_success(), "CREATE with 2D nonce should succeed");

        // With TIP-1000: CREATE cost (500k) + new account (250k) + 2D nonce sender creation (250k) + base
        assert_eq!(
            result1.tx_gas_used(),
            1028720,
            "T1 CREATE with 2D nonce (caller.nonce=0) gas should be exact"
        );

        // Test 2: Second CREATE tx with 2D nonce (different nonce_key)
        // Caller account nonce is now 1, so no extra 250k for caller account creation
        // Should include: CREATE cost (500k) + new account for sender (250k from nonce==0 check)
        // but NOT the extra 250k for 2D nonce caller creation since account.nonce != 0
        let nonce_key_2d_2 = U256::from(43);
        let tx2 = TxBuilder::new()
            .create(&initcode)
            .nonce_key(nonce_key_2d_2)
            .nonce(0) // 2D nonce = 0 (new key, starts at 0)
            .gas_limit(2_000_000)
            .build();

        let signed_tx2 = key_pair.sign_tx(tx2)?;
        let tx_env2 = TempoTxEnv::from_recovered_tx(&signed_tx2, caller);

        let result2 = evm.transact_commit(tx_env2)?;
        assert!(
            result2.is_success(),
            "Second CREATE with 2D nonce should succeed"
        );

        // With TIP-1000: CREATE cost (500k) + new account (250k) + base (no extra 250k since caller.nonce != 0)
        assert_eq!(
            result2.tx_gas_used(),
            778720,
            "T1 CREATE with 2D nonce (caller.nonce=1) gas should be exact"
        );

        // Verify the gas difference is exactly 250,000 (new_account_cost)
        let gas_difference = result1.tx_gas_used() - result2.tx_gas_used();
        assert_eq!(
            gas_difference, 250_000,
            "Gas difference should be exactly new_account_cost (250,000), got {gas_difference:?}",
        );

        Ok(())
    }

    /// Test that CREATE with expiring nonce charges 250k new_account_cost when caller.nonce == 0.
    /// This validates the fix for audit issue #182.
    #[test]
    fn test_aa_tx_gas_create_with_expiring_nonce() -> eyre::Result<()> {
        use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let initcode = vec![0x60, 0x00, 0x60, 0x00, 0xF3]; // PUSH0 PUSH0 RETURN
        let timestamp = 1000u64;
        let valid_before = timestamp + 30;

        // CREATE with caller.nonce == 0 (should charge extra 250k)
        let mut evm1 = create_funded_evm_t1_with_timestamp(caller, timestamp);
        let tx1 = TxBuilder::new()
            .create(&initcode)
            .nonce_key(TEMPO_EXPIRING_NONCE_KEY)
            .valid_before(Some(valid_before))
            .gas_limit(2_000_000)
            .build();
        let result1 = evm1.transact_commit(TempoTxEnv::from_recovered_tx(
            &key_pair.sign_tx(tx1)?,
            caller,
        ))?;
        assert!(result1.is_success());
        let gas_nonce_zero = result1.tx_gas_used();

        // CREATE with caller.nonce == 1 (no extra 250k)
        let mut evm2 = create_funded_evm_t1_with_timestamp(caller, timestamp);
        evm2.ctx.db_mut().insert_account_info(
            caller,
            AccountInfo {
                balance: U256::from(DEFAULT_BALANCE),
                nonce: 1,
                ..Default::default()
            },
        );
        let tx2 = TxBuilder::new()
            .create(&initcode)
            .nonce_key(TEMPO_EXPIRING_NONCE_KEY)
            .valid_before(Some(valid_before))
            .gas_limit(2_000_000)
            .build();
        let result2 = evm2.transact_commit(TempoTxEnv::from_recovered_tx(
            &key_pair.sign_tx(tx2)?,
            caller,
        ))?;
        assert!(result2.is_success());
        let gas_nonce_one = result2.tx_gas_used();

        // The fix adds 250k when caller.nonce == 0 for CREATE with non-zero nonce_key
        assert_eq!(
            gas_nonce_zero - gas_nonce_one,
            250_000,
            "new_account_cost not charged"
        );

        Ok(())
    }

    /// Test gas comparison between single call and multiple calls.
    /// Uses T1 hardfork for TIP-1000 gas costs.
    #[test]
    fn test_aa_tx_gas_single_vs_multiple_calls() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Test 1: Single call
        // T1 costs: new account (250k) + base costs
        let mut evm1 = create_funded_evm_t1(caller);
        let tx1 = TxBuilder::new()
            .call_identity(&[0x01, 0x02, 0x03, 0x04])
            .gas_limit(500_000)
            .build();

        let signed_tx1 = key_pair.sign_tx(tx1)?;
        let tx_env1 = TempoTxEnv::from_recovered_tx(&signed_tx1, caller);
        let result1 = evm1.transact_commit(tx_env1)?;
        assert!(result1.is_success());
        let gas_single = result1.tx_gas_used();

        // Test 2: Three calls
        // T1 costs: new account (250k) + 3 calls overhead
        let mut evm2 = create_funded_evm_t1(caller);
        let tx2 = TxBuilder::new()
            .call_identity(&[0x01, 0x02, 0x03, 0x04])
            .call_identity(&[0x05, 0x06, 0x07, 0x08])
            .call_identity(&[0x09, 0x0A, 0x0B, 0x0C])
            .gas_limit(500_000)
            .build();

        let signed_tx2 = key_pair.sign_tx(tx2)?;
        let tx_env2 = TempoTxEnv::from_recovered_tx(&signed_tx2, caller);
        let result2 = evm2.transact_commit(tx_env2)?;
        assert!(result2.is_success());
        let gas_triple = result2.tx_gas_used();

        // Three calls should cost more than single call
        assert_eq!(gas_single, 278738, "T1 single call gas should be exact");
        assert_eq!(gas_triple, 284102, "T1 triple call gas should be exact");
        assert!(
            gas_triple > gas_single,
            "3 calls should cost more than 1 call"
        );
        assert!(
            gas_triple < gas_single * 3,
            "3 calls should cost less than 3x single call (base costs shared)"
        );

        Ok(())
    }

    /// Test AA transaction gas with SLOAD operation (cold vs warm access).
    /// Uses T1 hardfork for TIP-1000 gas costs.
    #[test]
    fn test_aa_tx_gas_sload_cold_vs_warm() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let contract = Address::repeat_byte(0x58);

        let mut evm = create_funded_evm_t1(caller);

        // Deploy contract that does 2 SLOADs from the same slot:
        // PUSH1 0x00 SLOAD POP  (cold SLOAD from slot 0)
        // PUSH1 0x00 SLOAD POP  (warm SLOAD from slot 0)
        // STOP
        let sload_bytecode = Bytecode::new_raw(bytes!("6000545060005450"));
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(sload_bytecode),
                ..Default::default()
            },
        );

        // Pre-populate storage
        evm.ctx
            .db_mut()
            .insert_account_storage(contract, U256::ZERO, U256::from(0x1234))
            .unwrap();

        // T1 costs: new account (250k) + SLOAD costs + base costs
        let tx = TxBuilder::new()
            .call(contract, &[])
            .gas_limit(500_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success(), "SLOAD transaction should succeed");

        // T1 costs: new account (250k) + cold SLOAD (2100) + warm SLOAD (100) + cold account (~2.6k)
        let gas_used = result.tx_gas_used();
        assert_eq!(gas_used, 280866, "T1 SLOAD cold/warm gas should be exact");

        Ok(())
    }

    // ==================== End TIP-1000 Tests ====================

    /// Test system call functions and inspector management.
    /// Tests `system_call_one_with_caller`, `inspect_one_system_call_with_caller`, and `set_inspector`.
    #[test]
    fn test_system_call_and_inspector() -> eyre::Result<()> {
        let caller = Address::repeat_byte(0x01);
        let contract = Address::repeat_byte(0x42);

        // Deploy a simple contract that returns success
        // DIFFICULTY NUMBER PUSH1 0x00 PUSH1 0x00 RETURN (returns empty data)
        let bytecode = Bytecode::new_raw(bytes!("444360006000F3"));

        // Test system_call_one_with_caller (no inspector needed)
        {
            let mut evm = create_evm();
            evm.ctx.db_mut().insert_account_info(
                contract,
                AccountInfo {
                    code: Some(bytecode.clone()),
                    ..Default::default()
                },
            );

            let result = evm.system_call_one_with_caller(caller, contract, Bytes::new())?;
            assert!(result.is_success());
        }

        // Test set_inspector and inspect_one_system_call_with_caller
        {
            let mut evm = create_evm_with_inspector(CountInspector::new());
            evm.ctx.db_mut().insert_account_info(
                contract,
                AccountInfo {
                    code: Some(bytecode),
                    ..Default::default()
                },
            );

            // Test inspect_one_system_call_with_caller
            let result = evm.inspect_one_system_call_with_caller(caller, contract, Bytes::new())?;
            assert!(result.is_success());

            // Verify inspector was called
            assert!(evm.inspector.call_count() > 0,);

            // Test set_inspector - replace with a fresh CountInspector
            evm.set_inspector(CountInspector::new());

            // Verify the new inspector starts fresh
            assert_eq!(evm.inspector.call_count(), 0,);

            // Run another system call and verify new inspector records it
            let result = evm.inspect_one_system_call_with_caller(caller, contract, Bytes::new())?;
            assert!(result.is_success());
            assert!(evm.inspector.call_count() > 0);
        }

        Ok(())
    }

    /// Test that key_authorization works correctly with T1 hardfork.
    ///
    /// This test verifies the key_authorization flow works in the T1 EVM.
    /// It ensures that:
    /// 1. Keys are NOT authorized when transaction fails due to insufficient gas
    /// 2. Keys ARE authorized when transaction succeeds with sufficient gas
    ///
    /// Related fix: The handler creates a checkpoint before key_authorization
    /// precompile execution and reverts it on OOG. This ensures storage consistency.
    #[test]
    fn test_key_authorization_t1() -> eyre::Result<()> {
        use tempo_precompiles::account_keychain::AccountKeychain;

        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;

        // Create a T1 EVM (the fix only applies to T1)
        let mut evm = create_funded_evm_t1(caller);

        // Set up TIP20 for fee payment
        let block = TempoBlockEnv::default();
        {
            let ctx = &mut evm.ctx;
            let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
            let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

            StorageCtx::enter(&mut provider, || {
                TIP20Setup::path_usd(caller)
                    .with_issuer(caller)
                    .with_mint(caller, U256::from(10_000_000))
                    .apply()
            })?;
        }

        // ==================== Test 1: INSUFFICIENT gas ====================
        // First, try with insufficient gas - key should NOT be authorized

        let access_key = P256KeyPair::random();
        let key_auth =
            KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, access_key.address);
        let key_auth_sig = key_pair.sign_webauthn(key_auth.signature_hash().as_slice())?;
        let signed_key_auth = key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_sig));

        // Verify key does NOT exist before the transaction
        {
            let ctx = &mut evm.ctx;
            let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
            let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

            let key_exists = StorageCtx::enter(&mut provider, || {
                let keychain = AccountKeychain::default();
                keychain.keys[caller][access_key.address].read()
            })?;
            assert_eq!(
                key_exists.expiry, 0,
                "Key should not exist before transaction"
            );
        }

        let signed_auth = key_pair.create_signed_authorization(Address::repeat_byte(0x42))?;

        // Insufficient gas - will cause OOG during key_authorization processing
        let tx_low_gas = TxBuilder::new()
            .call_identity(&[0x01])
            .authorization(signed_auth)
            .key_authorization(signed_key_auth)
            .gas_limit(589_000)
            .build();

        let signed_tx_low = key_pair.sign_tx(tx_low_gas)?;
        let tx_env_low = TempoTxEnv::from_recovered_tx(&signed_tx_low, caller);

        // Execute the transaction - it should fail due to insufficient gas
        let result_low = evm.transact_commit(tx_env_low);

        // Transaction should fail (either rejected or OOG).
        // Track whether the nonce was incremented (committed OOG vs validation rejection).
        let nonce_incremented = match &result_low {
            Ok(result) => {
                assert_eq!(
                    result.tx_gas_used(),
                    589_000,
                    "Gas used should be gas limit"
                );
                assert!(
                    !result.is_success(),
                    "Transaction with insufficient gas should fail"
                );
                true // OOG: tx committed, nonce incremented
            }
            Err(e) => {
                // Transaction rejected during validation - must be CallGasCostMoreThanGasLimit
                assert!(
                    matches!(
                        e,
                        revm::context::result::EVMError::Transaction(
                            TempoInvalidTransaction::EthInvalidTransaction(
                                revm::context::result::InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                            )
                        )
                    ),
                    "Expected CallGasCostMoreThanGasLimit, got: {e:?}"
                );
                false // Validation rejection: nonce NOT incremented
            }
        };

        // CRITICAL: Verify the key was NOT authorized
        // This tests that storage changes are properly reverted on failure
        {
            let ctx = &mut evm.ctx;
            let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
            let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

            let key_after_fail = StorageCtx::enter(&mut provider, || {
                let keychain = AccountKeychain::default();
                keychain.keys[caller][access_key.address].read()
            })?;

            assert_eq!(
                key_after_fail,
                AuthorizedKey::default(),
                "Key should NOT be authorized when transaction fails due to insufficient gas"
            );
        }

        // ==================== Test 2: SUFFICIENT gas ====================
        // Now try with sufficient gas - key should be authorized

        let access_key2 = P256KeyPair::random();
        let key_auth2 =
            KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, access_key2.address);
        let key_auth_sig2 = key_pair.sign_webauthn(key_auth2.signature_hash().as_slice())?;
        let signed_key_auth2 = key_auth2.into_signed(PrimitiveSignature::WebAuthn(key_auth_sig2));

        let signed_auth2 = key_pair.create_signed_authorization(Address::repeat_byte(0x43))?;

        // Execute transaction with sufficient gas
        let next_nonce = if nonce_incremented { 1 } else { 0 };
        let tx = TxBuilder::new()
            .call_identity(&[0x01])
            .authorization(signed_auth2)
            .key_authorization(signed_key_auth2)
            .nonce(next_nonce)
            .gas_limit(1_000_000)
            .build();

        let signed_tx = key_pair.sign_tx(tx)?;
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success(), "Transaction should succeed");

        // Verify the key was authorized
        {
            let ctx = &mut evm.ctx;
            let internals = EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
            let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

            let key_after_success = StorageCtx::enter(&mut provider, || {
                let keychain = AccountKeychain::default();
                keychain.keys[caller][access_key2.address].read()
            })?;

            assert_eq!(
                key_after_success.expiry,
                u64::MAX,
                "Key should be authorized after successful transaction"
            );
        }

        Ok(())
    }

    /// Regression: CREATE nonce replay vulnerability — demonstrates the T1
    /// bug and verifies the T1B fix.
    ///
    /// **The bug (T1):** An AA CREATE transaction with a KeyAuthorization runs
    /// `authorize_key` in a gas-metered precompile call. TIP-1000 SSTORE costs
    /// (250k) easily exceed the remaining gas after intrinsic deduction, causing
    /// OutOfGas. The handler then sets `evm.initial_gas = u64::MAX`, which
    /// short-circuits execution before `make_create_frame` bumps the protocol
    /// nonce. The nonce stays at 0, making the signed transaction replayable.
    ///
    /// **The fix (T1B):** The precompile runs with `gas_limit = u64::MAX`,
    /// eliminating the OOG path. Gas is accounted for solely in intrinsic gas.
    /// The CREATE frame is always constructed, the nonce is always bumped, and
    /// replay is impossible.
    #[test]
    fn test_create_nonce_replay_regression() -> eyre::Result<()> {
        use tempo_precompiles::account_keychain::AccountKeychain;

        /// Run a CREATE+KeyAuth transaction on the given hardfork and return
        /// (caller_nonce_after, key_expiry).
        fn run_create_with_key_auth(
            spec: TempoHardfork,
            gas_limit: u64,
        ) -> eyre::Result<(u64, u64)> {
            let key_pair = P256KeyPair::random();
            let caller = key_pair.address;

            let db = CacheDB::new(EmptyDB::new());
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.spec = spec;
            cfg.gas_params = tempo_gas_params(spec);

            let ctx = Context::mainnet()
                .with_db(db)
                .with_block(Default::default())
                .with_cfg(cfg)
                .with_tx(Default::default());

            let mut evm = TempoEvm::new(ctx, ());
            fund_account(&mut evm, caller);

            let block = TempoBlockEnv::default();
            {
                let ctx = &mut evm.ctx;
                let internals =
                    EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
                // Use default cfg for TIP20 setup — the test infrastructure's
                // `is_initialized` check uses an unsafe `as_hashmap()` cast that
                // only works with default gas params.
                let mut provider =
                    EvmPrecompileStorageProvider::new_max_gas(internals, &Default::default());
                StorageCtx::enter(&mut provider, || {
                    TIP20Setup::path_usd(caller)
                        .with_issuer(caller)
                        .with_mint(caller, U256::from(100_000_000))
                        .apply()
                })?;
            }

            let access_key = P256KeyPair::random();
            let key_auth =
                KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, access_key.address);
            let key_auth_sig = key_pair.sign_webauthn(key_auth.signature_hash().as_slice())?;
            let signed_key_auth = key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_sig));

            let tx = TxBuilder::new()
                .create(&[0x60, 0x00, 0x60, 0x00, 0xF3])
                .key_authorization(signed_key_auth)
                .gas_limit(gas_limit)
                .build();

            let signed_tx = key_pair.sign_tx(tx)?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);
            let _result = evm.transact_commit(tx_env);

            let nonce = evm
                .ctx
                .db()
                .basic_ref(caller)
                .ok()
                .flatten()
                .map(|a| a.nonce)
                .unwrap_or(0);

            let key_expiry = {
                let ctx = &mut evm.ctx;
                let internals =
                    EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
                let mut provider =
                    EvmPrecompileStorageProvider::new_max_gas(internals, &Default::default());
                let key = StorageCtx::enter(&mut provider, || {
                    AccountKeychain::default().keys[caller][access_key.address].read()
                })?;
                key.expiry
            };

            Ok((nonce, key_expiry))
        }

        // --- T1: demonstrate the bug ---
        // T1 intrinsic gas for this tx is ~560k (21k base + 500k CREATE + 35k
        // KeyAuth heuristic). Gas limit 780k leaves ~220k for the precompile,
        // which is below the 250k SSTORE cost → OOG → nonce NOT bumped.
        let (t1_nonce, t1_key_expiry) = run_create_with_key_auth(TempoHardfork::T1, 780_000)?;
        assert_eq!(
            t1_nonce, 0,
            "T1 bug: nonce must NOT be bumped when keychain OOGs"
        );
        assert_eq!(
            t1_key_expiry, 0,
            "T1 bug: key must NOT be authorized when keychain OOGs"
        );

        // --- T1B: verify the fix ---
        // T1B intrinsic gas is ~1.04M (21k base + 500k CREATE + 260k KeyAuth
        // + calldata + sig). Gas limit 1.05M is just enough to pass intrinsic
        // validation. The precompile runs with unlimited gas, so the nonce is
        // always bumped.
        let (t1b_nonce, t1b_key_expiry) = run_create_with_key_auth(TempoHardfork::T1B, 1_050_000)?;
        assert_eq!(
            t1b_nonce, 1,
            "T1B fix: nonce must be bumped after CREATE+KeyAuth"
        );
        assert_eq!(t1b_key_expiry, u64::MAX, "T1B fix: key must be authorized");

        Ok(())
    }

    /// Regression: double gas charging for KeyAuthorization — demonstrates the
    /// T1 bug and verifies the T1B fix.
    ///
    /// **The bug (T1):** The handler charges both a heuristic intrinsic gas
    /// estimate AND the metered precompile gas (`evm.initial_gas += gas_used`),
    /// resulting in a double charge. With TIP-1000 SSTORE at 250k, a simple
    /// KeyAuthorization (0 limits) costs ~530k on T1 instead of ~280k.
    ///
    /// **The fix (T1B):** Only the intrinsic gas is charged; the precompile runs
    /// with unlimited gas and its cost is NOT added to `initial_gas` afterward.
    #[test]
    fn test_double_charge_key_authorization_regression() -> eyre::Result<()> {
        /// Run a CALL+KeyAuth transaction and return gas_used.
        fn run_call_with_key_auth(spec: TempoHardfork) -> eyre::Result<u64> {
            let key_pair = P256KeyPair::random();
            let caller = key_pair.address;

            let db = CacheDB::new(EmptyDB::new());
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.spec = spec;
            cfg.gas_params = tempo_gas_params(spec);

            let ctx = Context::mainnet()
                .with_db(db)
                .with_block(Default::default())
                .with_cfg(cfg)
                .with_tx(Default::default());

            let mut evm = TempoEvm::new(ctx, ());
            fund_account(&mut evm, caller);

            let block = TempoBlockEnv::default();
            {
                let ctx = &mut evm.ctx;
                let internals =
                    EvmInternals::new(&mut ctx.journaled_state, &block, &ctx.cfg, &ctx.tx);
                let mut provider =
                    EvmPrecompileStorageProvider::new_max_gas(internals, &Default::default());
                StorageCtx::enter(&mut provider, || {
                    TIP20Setup::path_usd(caller)
                        .with_issuer(caller)
                        .with_mint(caller, U256::from(100_000_000))
                        .apply()
                })?;
            }

            let access_key = P256KeyPair::random();
            let key_auth =
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, access_key.address);
            let key_auth_sig = key_pair.sign_webauthn(key_auth.signature_hash().as_slice())?;
            let signed_key_auth = key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_sig));

            let tx = TxBuilder::new()
                .call_identity(&[])
                .key_authorization(signed_key_auth)
                .gas_limit(2_000_000)
                .build();

            let signed_tx = key_pair.sign_tx(tx)?;
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);
            let result = evm.transact_commit(tx_env)?;
            assert!(result.is_success());
            Ok(result.tx_gas_used())
        }

        let t1_gas = run_call_with_key_auth(TempoHardfork::T1)?;
        let t1b_gas = run_call_with_key_auth(TempoHardfork::T1B)?;

        // T1 double-charges: intrinsic heuristic (~35k) + metered precompile
        // (~250k SSTORE) on top of base tx gas, resulting in >500k.
        assert!(
            t1_gas > 500_000,
            "T1 bug: should double-charge (got {t1_gas}, expected >500k)"
        );

        // T1B charges only once via accurate intrinsic gas (~255k for
        // sig+sload+sstore) + base tx. Total ~541k, well below the ~790k
        // that double-charging would produce.
        assert!(
            t1b_gas < t1_gas,
            "T1B fix: gas ({t1b_gas}) must be less than T1 double-charge ({t1_gas})"
        );

        Ok(())
    }

    /// Regression: `eth_estimateGas` must NOT add an extra 250k `new_account_cost` for AA
    /// token transfers using the `calls` format when `nonce_key != 0` and
    /// `caller.nonce == 0`.
    ///
    /// Root cause: `tx.kind()` reads `inner.to`, which is `None` for the
    /// `calls` format, causing it to return `TxKind::Create` for a plain
    /// transfer — incorrectly triggering a second 250k account-creation charge
    /// on top of the legitimate 250k already charged by `validate_aa_initial_tx_gas`.
    ///
    /// The fix inspects `aa_calls[0].to` directly for AA transactions instead
    /// of relying on `tx.kind()`.
    #[test]
    fn test_aa_tx_transfer_calls_format_no_extra_250k() -> eyre::Result<()> {
        let key_pair = P256KeyPair::random();
        let caller = key_pair.address;
        let recipient = Address::with_last_byte(0xff);

        // Baseline: calls-format transfer with nonce_key=0 (protocol nonce).
        // validate_aa_initial_tx_gas charges 250k (nonce==0 branch).
        // handler.rs does NOT fire because !nonce_key.is_zero() is false.
        let mut evm_baseline = create_funded_evm_t1(caller);
        let tx_baseline = TxBuilder::new()
            .call(recipient, &[])
            .nonce_key(U256::ZERO)
            .nonce(0)
            .gas_limit(500_000)
            .build();
        let result_baseline = evm_baseline.transact_commit(TempoTxEnv::from_recovered_tx(
            &key_pair.sign_tx(tx_baseline)?,
            caller,
        ))?;
        assert!(
            result_baseline.is_success(),
            "baseline transfer should succeed"
        );
        let gas_baseline = result_baseline.tx_gas_used();

        // Issue #3178 scenario: calls-format transfer with nonce_key != 0, caller.nonce == 0.
        // validate_aa_initial_tx_gas still charges the same 250k (nonce==0 branch).
        // Before fix: handler.rs also fired (tx.kind() wrongly returned Create) → extra 250k.
        // After fix:  handler.rs does NOT fire (aa_calls[0].to is Call) → no extra 250k.
        let nonce_key = U256::from(42);
        let mut evm_2d = create_funded_evm_t1(caller);
        let tx_2d = TxBuilder::new()
            .call(recipient, &[])
            .nonce_key(nonce_key)
            .nonce(0)
            .gas_limit(500_000)
            .build();
        let result_2d = evm_2d.transact_commit(TempoTxEnv::from_recovered_tx(
            &key_pair.sign_tx(tx_2d)?,
            caller,
        ))?;
        assert!(
            result_2d.is_success(),
            "calls-format transfer with 2D nonce should succeed"
        );
        let gas_2d = result_2d.tx_gas_used();

        // After the fix the gas should be nearly identical for both cases because
        // both go through the same validate_aa_initial_tx_gas branch and handler.rs
        // no longer fires for transfers.
        // Before the fix gas_2d would have been ~250k higher than gas_baseline.
        let diff = gas_2d.saturating_sub(gas_baseline);
        assert!(
            diff < 10_000,
            "calls-format transfer with nonceKey={nonce_key} (gas={gas_2d}) must not cost \
             ~250k more than baseline (gas={gas_baseline}, diff={diff}). \
             A diff near 250_000 means new_account_cost is incorrectly added for \
             transfers (issue #3178)."
        );

        Ok(())
    }
}
