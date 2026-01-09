use crate::{TempoBlockEnv, TempoTxEnv, instructions};
use alloy_evm::{Database, precompiles::PrecompilesMap};
use alloy_primitives::{Log, U256};
use revm::{
    Context, Inspector,
    context::{CfgEnv, ContextError, Evm, FrameStack},
    handler::{
        EthFrame, EthPrecompiles, EvmTr, FrameInitOrResult, FrameTr, ItemOrResult,
        instructions::EthInstructions,
    },
    inspector::InspectorEvmTr,
    interpreter::interpreter::EthInterpreter,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::extend_tempo_precompiles;

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
    /// Preserved logs from the last transaction
    pub logs: Vec<Log>,
    /// The fee collected in `collectFeePreTx` call.
    pub(crate) collected_fee: U256,
    /// 2D nonce gas cost calculated during validation.
    pub(crate) nonce_2d_gas: u64,
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Create a new Tempo EVM.
    pub fn new(ctx: TempoContext<DB>, inspector: I) -> Self {
        let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::default().precompiles);
        extend_tempo_precompiles(&mut precompiles, &ctx.cfg);

        Self::new_inner(Evm {
            ctx,
            inspector,
            instruction: instructions::tempo_instructions(),
            precompiles,
            frame_stack: FrameStack::new(),
        })
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
    ) -> Self {
        Self {
            inner,
            logs: Vec::new(),
            collected_fee: U256::ZERO,
            nonce_2d_gas: 0,
        }
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Consumed self and returns a new Evm type with given Inspector.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        TempoEvm::new_inner(self.inner.with_inspector(inspector))
    }

    /// Consumes self and returns a new Evm type with given Precompiles.
    pub fn with_precompiles(self, precompiles: PrecompilesMap) -> Self {
        Self::new_inner(self.inner.with_precompiles(precompiles))
    }

    /// Consumes self and returns the inner Inspector.
    pub fn into_inspector(self) -> I {
        self.inner.into_inspector()
    }

    /// Take logs from the EVM.
    #[inline]
    pub fn take_logs(&mut self) -> Vec<Log> {
        std::mem::take(&mut self.logs)
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
    use alloy_eips::eip7702::Authorization;
    use alloy_evm::{Evm, EvmFactory, FromRecoveredTx};
    use alloy_primitives::{Address, Bytes, TxKind, U256, bytes};
    use alloy_sol_types::SolCall;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        ecdsa::{SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::rand_core::OsRng,
    };
    use reth_evm::EvmInternals;
    use revm::{
        Context, DatabaseRef, ExecuteCommitEvm, ExecuteEvm, InspectEvm, MainContext,
        bytecode::opcode,
        context::{ContextTr, TxEnv},
        database::{CacheDB, EmptyDB},
        handler::system_call::SystemCallEvm,
        inspector::{CountInspector, InspectSystemCallEvm},
        state::{AccountInfo, Bytecode},
    };
    use sha2::{Digest, Sha256};
    use tempo_evm::TempoEvmFactory;
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS,
        nonce::NonceManager,
        storage::{StorageCtx, evm::EvmPrecompileStorageProvider},
        test_util::TIP20Setup,
        tip20::ITIP20,
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

    use crate::{TempoBlockEnv, TempoEvm, TempoInvalidTransaction, TempoTxEnv};

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
        evm.ctx.db_mut().insert_account_info(
            address,
            AccountInfo {
                balance: U256::from(DEFAULT_BALANCE),
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

    /// Create an EVM with a specific timestamp and a funded account.
    fn create_funded_evm_with_timestamp(
        address: Address,
        timestamp: u64,
    ) -> TempoEvm<CacheDB<EmptyDB>, ()> {
        let mut evm = create_evm_with_timestamp(timestamp);
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
            let pub_key_x =
                alloy_primitives::B256::from_slice(encoded_point.x().unwrap().as_slice());
            let pub_key_y =
                alloy_primitives::B256::from_slice(encoded_point.y().unwrap().as_slice());
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
                s: normalize_p256_s(&sig_bytes[32..64]),
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

        /// Sign a transaction with KeychainSignature wrapper.
        fn sign_tx_keychain(
            &self,
            tx: TempoTransaction,
        ) -> eyre::Result<tempo_primitives::AASigned> {
            let webauthn_sig = self.sign_webauthn(tx.signature_hash().as_slice())?;
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
                gas_limit: 100_000,
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
                max_priority_fee_per_gas: 0,
                max_fee_per_gas: 0,
                gas_limit: self.gas_limit,
                calls: self.calls,
                access_list: Default::default(),
                nonce_key: self.nonce_key,
                nonce: self.nonce,
                fee_payer_signature: None,
                valid_before: self.valid_before,
                valid_after: self.valid_after,
                key_authorization: self.key_authorization,
                tempo_authorization_list: self.authorization_list,
            }
        }
    }

    // ==================== End Test Utility Functions ====================

    #[test]
    fn test_access_millis_timestamp() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut tempo_evm = TempoEvmFactory::default().create_evm(db, Default::default());
        let ctx = tempo_evm.ctx_mut();
        ctx.block.timestamp = U256::from(1000);
        ctx.block.timestamp_millis_part = 100;
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(
            EvmInternals::new(&mut ctx.journaled_state, &ctx.block),
            &ctx.cfg,
        );
        StorageCtx::enter(&mut storage, || {
            TIP20Setup::create("USD", "USD", Address::ZERO).apply()
        })?;
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
        let res = tempo_evm.transact_raw(tx_env.into())?;
        assert!(res.result.is_success());
        assert_eq!(
            U256::from_be_slice(res.result.output().unwrap()),
            U256::from(1000100)
        );

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
            let mut storage = EvmPrecompileStorageProvider::new_max_gas(
                EvmInternals::new(&mut ctx.journaled_state, &ctx.block),
                &ctx.cfg,
            );
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

        // Create EVM and execute transaction
        let mut evm = create_funded_evm(caller);

        // Execute the transaction and commit state changes
        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success());

        // Test with KeychainSignature using key_authorization to provision the access key
        let key_auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::WebAuthn,
            key_id: caller,
            expiry: None,
            limits: None,
        };
        let key_auth_webauthn_sig = key_pair.sign_webauthn(key_auth.signature_hash().as_slice())?;
        let signed_key_auth =
            key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_webauthn_sig));

        // Create transaction with incremented nonce and key_authorization
        let tx2 = TxBuilder::new()
            .call_identity(&[0x01, 0x02, 0x03, 0x04])
            .call_identity(&[0xAA, 0xBB, 0xCC, 0xDD])
            .authorization(signed_auth)
            .nonce(1)
            .gas_limit(150_000)
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
                        TempoInvalidTransaction::ValidAfter { current: 100, valid_after: 200 }
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
                        TempoInvalidTransaction::ValidBefore { current: 200, valid_before: 200 }
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
                        TempoInvalidTransaction::ValidBefore { current: 300, valid_before: 200 }
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
                        TempoInvalidTransaction::ValidAfter { current: 50, valid_after: 100 }
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
                        TempoInvalidTransaction::ValidBefore { current: 200, valid_before: 200 }
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
    /// - InsufficientGasForIntrinsicCost: when gas_limit < intrinsic_gas
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

            let evm = create_evm_with_tx(
                TxBuilder::new()
                    .create(&oversized_initcode)
                    .gas_limit(10_000_000)
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&evm);
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
            let evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_with_value(IDENTITY_PRECOMPILE, &[0x01, 0x02], U256::from(1000))
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&evm);
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

        // Test 3: InsufficientGasForIntrinsicCost - gas_limit < intrinsic_gas
        {
            let evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_identity(&[0x01, 0x02, 0x03, 0x04])
                    .gas_limit(1000) // Way too low, intrinsic cost is at least 21000
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&evm);
            assert!(
                matches!(
                    result,
                    Err(EVMError::Transaction(
                        TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
                            gas_limit: 1000,
                            intrinsic_gas
                        }
                    )) if intrinsic_gas > 1000
                ),
                "Expected InsufficientGasForIntrinsicCost error, got: {result:?}"
            );
        }

        // Test 4: InsufficientGasForIntrinsicCost - gas_limit < floor_gas (EIP-7623)
        {
            let large_calldata = vec![0x42; 1000]; // 1000 non-zero bytes = 1000 tokens

            let evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_identity(&large_calldata)
                    .gas_limit(31_000) // Above initial_gas (~30600) but below floor_gas (~32500)
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&evm);

            // Should fail because gas_limit < floor_gas
            assert!(
                matches!(
                    result,
                    Err(EVMError::Transaction(
                        TempoInvalidTransaction::InsufficientGasForIntrinsicCost {
                            gas_limit: 31_000,
                            intrinsic_gas
                        }
                    )) if intrinsic_gas > 31_000
                ),
                "Expected InsufficientGasForIntrinsicCost (floor gas), got: {result:?}"
            );
        }

        // Test 5: Success when gas_limit >= both initial_gas and floor_gas
        // Verifies floor_gas > initial_gas for large calldata (EIP-7623 scenario)
        {
            let large_calldata = vec![0x42; 1000];

            let evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_identity(&large_calldata)
                    .gas_limit(100_000) // Plenty of gas for both initial and floor
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&evm);
            assert!(
                result.is_ok(),
                "Expected success with sufficient gas, got: {result:?}"
            );

            let gas = result.unwrap();
            // Verify floor_gas > initial_gas for this calldata (EIP-7623 scenario)
            assert!(
                gas.floor_gas > gas.initial_gas,
                "Expected floor_gas ({}) > initial_gas ({}) for large calldata",
                gas.floor_gas,
                gas.initial_gas
            );
        }

        // Test 6: Success case - sufficient gas provided (small calldata)
        {
            let evm = create_evm_with_tx(
                TxBuilder::new()
                    .call_identity(&[0x01, 0x02, 0x03, 0x04])
                    .gas_limit(100_000)
                    .build(),
            )?;

            let result = handler.validate_initial_tx_gas(&evm);
            assert!(result.is_ok(), "Expected success, got: {result:?}");

            let gas = result.unwrap();
            assert!(
                gas.initial_gas >= 21_000,
                "Initial gas should be at least 21k base"
            );
        }

        Ok(())
    }

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
}
