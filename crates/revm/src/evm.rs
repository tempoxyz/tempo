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

    #[doc = " Returns the result of the frame to the caller. Frame is popped from the frame stack."]
    #[doc = " Consumes the frame result or returns it if there is more frames to run."]
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
    use alloy_evm::{Evm, EvmFactory};
    use alloy_primitives::{Address, TxKind, U256, bytes};
    use reth_evm::EvmInternals;
    use revm::{
        Context, InspectEvm, MainContext,
        bytecode::opcode,
        context::{ContextTr, TxEnv},
        database::{CacheDB, EmptyDB},
        inspector::CountInspector,
        state::{AccountInfo, Bytecode},
    };
    use tempo_evm::TempoEvmFactory;
    use tempo_precompiles::{
        TIP20_FACTORY_ADDRESS,
        storage::{StorageCtx, evm::EvmPrecompileStorageProvider},
        test_util::TIP20Setup,
        tip20::ITIP20,
    };
    use tempo_primitives::transaction::KeychainSignature;

    use crate::TempoEvm;

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
        use alloy_sol_types::SolCall;
        use tempo_precompiles::PATH_USD_ADDRESS;

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
        let db = CacheDB::new(EmptyDB::new());

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(Default::default())
            .with_tx(Default::default());

        let mut evm: TempoEvm<CacheDB<EmptyDB>, _> = TempoEvm::new(ctx, CountInspector::new());
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
            gas_price: 0,
            gas_limit: 1_000_000,
            ..Default::default()
        };
        let result = evm
            .inspect_tx(tx_env.into())
            .expect("execution should succeed");

        assert!(
            result.result.is_success(),
            "Transaction should succeed: {:?}",
            result.result
        );

        // Verify that a SupplyCapUpdate log was emitted by the TIP20 precompile
        assert_eq!(
            result.result.logs().len(),
            2,
            "Should have emitted 1 log, result: {:?}",
            result.result
        );
        assert_eq!(
            result.result.logs()[0].address,
            TIP20_FACTORY_ADDRESS,
            "Log should be from TIP20_FACTORY"
        );

        // Get the inspector and verify counts
        let inspector = &evm.inspector;

        // Verify CALL opcode was executed (the call to PATH_USD)
        assert_eq!(
            inspector.get_count(opcode::CALL),
            1,
            "Should have 1 CALL opcode"
        );
        assert_eq!(
            inspector.get_count(opcode::STOP),
            1,
            "Should have 1 STOP opcode"
        );

        // Verify log count
        assert_eq!(inspector.log_count(), 1, "Should have 1 log");

        // Verify call count (initial tx + CALL to PATH_USD)
        assert_eq!(
            inspector.call_count(),
            2,
            "Should have 2 calls (initial tx + CALL)"
        );

        assert_eq!(inspector.call_end_count(), 2, "Should have 2 call ends");

        Ok(())
    }

    /// Test creating and executing a Tempo transaction with:
    /// - WebAuthn signature
    /// - Authorization list (aa_auth_list)
    /// - Two calls to the identity precompile (0x04)
    #[test]
    fn test_tempo_tx() -> eyre::Result<()> {
        use alloy_eips::eip7702::Authorization;
        use alloy_evm::FromRecoveredTx;
        use alloy_primitives::{B256, Bytes};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use p256::{
            ecdsa::{SigningKey, signature::hazmat::PrehashSigner},
            elliptic_curve::rand_core::OsRng,
        };
        use revm::{DatabaseRef, ExecuteCommitEvm, ExecuteEvm};
        use sha2::{Digest, Sha256};
        use tempo_primitives::{
            TempoTransaction,
            transaction::{
                KeyAuthorization, SignatureType, TempoSignedAuthorization,
                tempo_transaction::Call,
                tt_signature::{
                    PrimitiveSignature, TempoSignature, WebAuthnSignature, derive_p256_address,
                    normalize_p256_s,
                },
            },
        };

        use crate::TempoTxEnv;

        // Identity precompile address (0x04)
        let identity_precompile = Address::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04,
        ]);

        // Generate P256 key pair for WebAuthn signature
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = B256::from_slice(encoded_point.x().unwrap().as_slice());
        let pub_key_y = B256::from_slice(encoded_point.y().unwrap().as_slice());

        // Derive caller address from P256 public key
        let caller = derive_p256_address(&pub_key_x, &pub_key_y);

        // Create a delegate address for EIP-7702 authorization
        let delegate_address = Address::repeat_byte(0x42);

        // Create authorization (EIP-7702 style)
        let auth = Authorization {
            chain_id: U256::from(1),
            address: delegate_address,
            nonce: 0,
        };

        // Compute authorization signature hash
        let mut sig_buf = Vec::new();
        sig_buf.push(tempo_primitives::transaction::tt_authorization::MAGIC);
        alloy_rlp::Encodable::encode(&auth, &mut sig_buf);
        let auth_sig_hash = alloy_primitives::keccak256(&sig_buf);

        // Create WebAuthn authenticator data for authorization
        let mut auth_authenticator_data = vec![0u8; 37];
        auth_authenticator_data[0..32].copy_from_slice(&[0xAA; 32]); // rpIdHash
        auth_authenticator_data[32] = 0x01; // UP flag set
        auth_authenticator_data[33..37].copy_from_slice(&[0, 0, 0, 0]); // signCount

        let auth_challenge_b64url = URL_SAFE_NO_PAD.encode(auth_sig_hash.as_slice());
        let auth_client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{auth_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
        );

        // Compute WebAuthn message hash for authorization
        let auth_client_data_hash = Sha256::digest(auth_client_data_json.as_bytes());
        let mut auth_final_hasher = Sha256::new();
        auth_final_hasher.update(&auth_authenticator_data);
        auth_final_hasher.update(auth_client_data_hash);
        let auth_message_hash = auth_final_hasher.finalize();

        // Sign authorization with P256
        let auth_signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(&auth_message_hash)?;
        let auth_sig_bytes = auth_signature.to_bytes();

        // Construct WebAuthn data for authorization
        let mut auth_webauthn_data = Vec::new();
        auth_webauthn_data.extend_from_slice(&auth_authenticator_data);
        auth_webauthn_data.extend_from_slice(auth_client_data_json.as_bytes());

        let auth_aa_sig =
            TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
                webauthn_data: Bytes::from(auth_webauthn_data),
                r: B256::from_slice(&auth_sig_bytes[0..32]),
                s: normalize_p256_s(&auth_sig_bytes[32..64]),
                pub_key_x,
                pub_key_y,
            }));
        let signed_auth = TempoSignedAuthorization::new_unchecked(auth, auth_aa_sig);

        // Create Tempo transaction with two calls to identity precompile
        let tx = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 100_000,
            calls: vec![
                // First call to identity precompile
                Call {
                    to: TxKind::Call(identity_precompile),
                    value: U256::ZERO,
                    input: Bytes::from(vec![0x01, 0x02, 0x03, 0x04]), // Input data echoed back
                },
                // Second call to identity precompile
                Call {
                    to: TxKind::Call(identity_precompile),
                    value: U256::ZERO,
                    input: Bytes::from(vec![0xAA, 0xBB, 0xCC, 0xDD]), // Different input data
                },
            ],
            access_list: Default::default(),
            nonce_key: U256::ZERO,
            nonce: 0,
            fee_payer_signature: None,
            valid_before: Some(u64::MAX),
            valid_after: None,
            key_authorization: None,
            tempo_authorization_list: vec![signed_auth], // has_aa_auth_list
        };

        // Get signature hash for the transaction
        let tx_sig_hash = tx.signature_hash();

        // Create WebAuthn authenticator data for transaction signature
        let mut tx_authenticator_data = vec![0u8; 37];
        tx_authenticator_data[0..32].copy_from_slice(&[0xBB; 32]); // rpIdHash
        tx_authenticator_data[32] = 0x01; // UP flag set
        tx_authenticator_data[33..37].copy_from_slice(&[0, 0, 0, 0]); // signCount

        let tx_challenge_b64url = URL_SAFE_NO_PAD.encode(tx_sig_hash.as_slice());
        let tx_client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{tx_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
        );

        // Compute WebAuthn message hash for transaction
        let tx_client_data_hash = Sha256::digest(tx_client_data_json.as_bytes());
        let mut tx_final_hasher = Sha256::new();
        tx_final_hasher.update(&tx_authenticator_data);
        tx_final_hasher.update(tx_client_data_hash);
        let tx_message_hash = tx_final_hasher.finalize();

        // Sign transaction with P256
        let tx_signature: p256::ecdsa::Signature = signing_key.sign_prehash(&tx_message_hash)?;
        let tx_sig_bytes = tx_signature.to_bytes();

        // Construct WebAuthn data for transaction signature
        let mut tx_webauthn_data = Vec::new();
        tx_webauthn_data.extend_from_slice(&tx_authenticator_data);
        tx_webauthn_data.extend_from_slice(tx_client_data_json.as_bytes());

        let tx_webauthn_sig = WebAuthnSignature {
            webauthn_data: Bytes::from(tx_webauthn_data),
            r: B256::from_slice(&tx_sig_bytes[0..32]),
            s: normalize_p256_s(&tx_sig_bytes[32..64]),
            pub_key_x,
            pub_key_y,
        };

        // Create signed transaction with WebAuthn signature
        let signed_tx =
            tx.clone()
                .into_signed(TempoSignature::Primitive(PrimitiveSignature::WebAuthn(
                    tx_webauthn_sig.clone(),
                )));

        // Convert to TempoTxEnv for execution
        let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

        // Verify transaction has AA auth list
        assert!(
            tx_env.tempo_tx_env.is_some(),
            "Transaction should have tempo_tx_env"
        );
        let tempo_env = tx_env.tempo_tx_env.as_ref().unwrap();
        assert_eq!(
            tempo_env.tempo_authorization_list.len(),
            1,
            "Should have 1 authorization"
        );
        assert_eq!(tempo_env.aa_calls.len(), 2, "Should have 2 calls");

        // Create EVM and execute transaction
        let db = CacheDB::new(EmptyDB::new());
        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(Default::default())
            .with_tx(Default::default());

        let mut evm: TempoEvm<CacheDB<EmptyDB>, ()> = TempoEvm::new(ctx, ());

        // Fund the caller account with some balance for gas
        evm.ctx.db_mut().insert_account_info(
            caller,
            AccountInfo {
                balance: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
                ..Default::default()
            },
        );

        // Execute the transaction and commit state changes
        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success());

        // Test with KeychainSignature using key_authorization to provision the access key
        // The key_id for a WebAuthn signature is the same as the caller (derived from P256 public key)
        let key_id = caller;

        // Create KeyAuthorization to provision the access key
        let key_auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::WebAuthn,
            key_id,
            expiry: None, // Never expires
            limits: None, // Unlimited spending
        };

        // Sign the KeyAuthorization with WebAuthn (same P256 key)
        let key_auth_sig_hash = key_auth.signature_hash();
        let key_auth_challenge_b64url = URL_SAFE_NO_PAD.encode(key_auth_sig_hash.as_slice());
        let key_auth_client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{key_auth_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
        );

        let key_auth_client_data_hash = Sha256::digest(key_auth_client_data_json.as_bytes());
        let mut key_auth_final_hasher = Sha256::new();
        key_auth_final_hasher.update(&tx_authenticator_data);
        key_auth_final_hasher.update(key_auth_client_data_hash);
        let key_auth_message_hash = key_auth_final_hasher.finalize();

        let key_auth_signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(&key_auth_message_hash)?;
        let key_auth_sig_bytes = key_auth_signature.to_bytes();

        let mut key_auth_webauthn_data = Vec::new();
        key_auth_webauthn_data.extend_from_slice(&tx_authenticator_data);
        key_auth_webauthn_data.extend_from_slice(key_auth_client_data_json.as_bytes());

        let key_auth_webauthn_sig = WebAuthnSignature {
            webauthn_data: Bytes::from(key_auth_webauthn_data),
            r: B256::from_slice(&key_auth_sig_bytes[0..32]),
            s: normalize_p256_s(&key_auth_sig_bytes[32..64]),
            pub_key_x,
            pub_key_y,
        };

        let signed_key_auth =
            key_auth.into_signed(PrimitiveSignature::WebAuthn(key_auth_webauthn_sig));

        // Create transaction with incremented nonce and key_authorization
        // Note: gas_limit increased to account for key_authorization intrinsic gas cost (~30k)
        let tx2 = TempoTransaction {
            nonce: 1, // Increment nonce
            gas_limit: 150_000,
            key_authorization: Some(signed_key_auth),
            ..tx.clone()
        };

        // Create a new WebAuthn signature for the new transaction hash
        let tx2_sig_hash = tx2.signature_hash();

        let tx2_challenge_b64url = URL_SAFE_NO_PAD.encode(tx2_sig_hash.as_slice());
        let tx2_client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{tx2_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
        );

        let tx2_client_data_hash = Sha256::digest(tx2_client_data_json.as_bytes());
        let mut tx2_final_hasher = Sha256::new();
        tx2_final_hasher.update(&tx_authenticator_data);
        tx2_final_hasher.update(tx2_client_data_hash);
        let tx2_message_hash = tx2_final_hasher.finalize();

        let tx2_signature: p256::ecdsa::Signature = signing_key.sign_prehash(&tx2_message_hash)?;
        let tx2_sig_bytes = tx2_signature.to_bytes();

        let mut tx2_webauthn_data = Vec::new();
        tx2_webauthn_data.extend_from_slice(&tx_authenticator_data);
        tx2_webauthn_data.extend_from_slice(tx2_client_data_json.as_bytes());

        let tx2_webauthn_sig = WebAuthnSignature {
            webauthn_data: Bytes::from(tx2_webauthn_data),
            r: B256::from_slice(&tx2_sig_bytes[0..32]),
            s: normalize_p256_s(&tx2_sig_bytes[32..64]),
            pub_key_x,
            pub_key_y,
        };

        // Create KeychainSignature wrapping the new WebAuthn signature
        let keychain_signature =
            KeychainSignature::new(caller, PrimitiveSignature::WebAuthn(tx2_webauthn_sig));

        let signed_tx = tx2.into_signed(TempoSignature::Keychain(keychain_signature));

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
        assert_eq!(
            keychain_sig.user_address, caller,
            "KeychainSignature user_address should match the caller"
        );

        // Verify the inner signature is WebAuthn
        assert!(
            matches!(keychain_sig.signature, PrimitiveSignature::WebAuthn(_)),
            "Inner signature should be WebAuthn"
        );

        // Verify key_id recovery works correctly using the transaction signature hash
        let recovered_key_id = keychain_sig
            .key_id(&tempo_env_keychain.signature_hash)
            .expect("Key ID recovery should succeed");
        assert_eq!(
            recovered_key_id, caller,
            "Recovered key_id should match caller (P256 key derives to same address)"
        );

        // Execute the transaction with keychain signature and commit state changes
        let result = evm.transact_commit(tx_env)?;
        assert!(result.is_success());

        // Test a transaction with a failing call to TIP20 contract with wrong input
        // TIP20 requires at least 4 bytes for the function selector
        use tempo_precompiles::PATH_USD_ADDRESS;

        let tx_fail = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 100_000,
            calls: vec![
                // Call to TIP20 contract with invalid calldata (too short - missing function selector)
                Call {
                    to: TxKind::Call(PATH_USD_ADDRESS),
                    value: U256::ZERO,
                    input: Bytes::from(vec![0x01, 0x02]), // Only 2 bytes, but TIP20 requires 4+ bytes for selector
                },
            ],
            access_list: Default::default(),
            nonce_key: U256::ZERO,
            nonce: 2, // Increment nonce
            fee_payer_signature: None,
            valid_before: Some(u64::MAX),
            valid_after: None,
            key_authorization: None,
            tempo_authorization_list: vec![],
        };

        // Create WebAuthn signature for the failing transaction
        let tx_fail_sig_hash = tx_fail.signature_hash();

        let tx_fail_challenge_b64url = URL_SAFE_NO_PAD.encode(tx_fail_sig_hash.as_slice());
        let tx_fail_client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{tx_fail_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
        );

        let tx_fail_client_data_hash = Sha256::digest(tx_fail_client_data_json.as_bytes());
        let mut tx_fail_final_hasher = Sha256::new();
        tx_fail_final_hasher.update(&tx_authenticator_data);
        tx_fail_final_hasher.update(tx_fail_client_data_hash);
        let tx_fail_message_hash = tx_fail_final_hasher.finalize();

        let tx_fail_signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(&tx_fail_message_hash)?;
        let tx_fail_sig_bytes = tx_fail_signature.to_bytes();

        let mut tx_fail_webauthn_data = Vec::new();
        tx_fail_webauthn_data.extend_from_slice(&tx_authenticator_data);
        tx_fail_webauthn_data.extend_from_slice(tx_fail_client_data_json.as_bytes());

        let tx_fail_webauthn_sig = WebAuthnSignature {
            webauthn_data: Bytes::from(tx_fail_webauthn_data),
            r: B256::from_slice(&tx_fail_sig_bytes[0..32]),
            s: normalize_p256_s(&tx_fail_sig_bytes[32..64]),
            pub_key_x,
            pub_key_y,
        };

        // Use keychain signature for the failing transaction
        let keychain_signature_fail =
            KeychainSignature::new(caller, PrimitiveSignature::WebAuthn(tx_fail_webauthn_sig));

        let signed_tx_fail = tx_fail.into_signed(TempoSignature::Keychain(keychain_signature_fail));

        let tx_env_fail = TempoTxEnv::from_recovered_tx(&signed_tx_fail, caller);

        // Execute the transaction with failing call - should fail due to invalid TIP20 input
        let result_fail = evm.transact(tx_env_fail)?;
        assert!(
            !result_fail.result.is_success(),
            "Transaction with invalid TIP20 calldata should fail"
        );

        // Test 2D nonce transaction (nonce_key > 0)
        // 2D nonces are stored in the NonceManager precompile instead of account state
        use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, nonce::NonceManager};

        let nonce_key_2d = U256::from(42); // Use a non-zero nonce key for 2D nonce

        // Create a transaction with 2D nonce
        let tx_2d_nonce = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 100_000,
            calls: vec![Call {
                to: TxKind::Call(identity_precompile),
                value: U256::ZERO,
                input: Bytes::from(vec![0x2D, 0x2D, 0x2D, 0x2D]), // "2D" pattern
            }],
            access_list: Default::default(),
            nonce_key: nonce_key_2d, // Non-zero nonce key = 2D nonce
            nonce: 0,                // First transaction for this nonce key
            fee_payer_signature: None,
            valid_before: Some(u64::MAX),
            valid_after: None,
            key_authorization: None,
            tempo_authorization_list: vec![],
        };

        // Create WebAuthn signature for the 2D nonce transaction
        let tx_2d_sig_hash = tx_2d_nonce.signature_hash();

        let tx_2d_challenge_b64url = URL_SAFE_NO_PAD.encode(tx_2d_sig_hash.as_slice());
        let tx_2d_client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{tx_2d_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
        );

        let tx_2d_client_data_hash = Sha256::digest(tx_2d_client_data_json.as_bytes());
        let mut tx_2d_final_hasher = Sha256::new();
        tx_2d_final_hasher.update(&tx_authenticator_data);
        tx_2d_final_hasher.update(tx_2d_client_data_hash);
        let tx_2d_message_hash = tx_2d_final_hasher.finalize();

        let tx_2d_signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(&tx_2d_message_hash)?;
        let tx_2d_sig_bytes = tx_2d_signature.to_bytes();

        let mut tx_2d_webauthn_data = Vec::new();
        tx_2d_webauthn_data.extend_from_slice(&tx_authenticator_data);
        tx_2d_webauthn_data.extend_from_slice(tx_2d_client_data_json.as_bytes());

        let tx_2d_webauthn_sig = WebAuthnSignature {
            webauthn_data: Bytes::from(tx_2d_webauthn_data),
            r: B256::from_slice(&tx_2d_sig_bytes[0..32]),
            s: normalize_p256_s(&tx_2d_sig_bytes[32..64]),
            pub_key_x,
            pub_key_y,
        };

        // Use KeychainSignature for the 2D nonce transaction
        let keychain_signature_2d =
            KeychainSignature::new(caller, PrimitiveSignature::WebAuthn(tx_2d_webauthn_sig));

        let signed_tx_2d = tx_2d_nonce.into_signed(TempoSignature::Keychain(keychain_signature_2d));

        let tx_env_2d = TempoTxEnv::from_recovered_tx(&signed_tx_2d, caller);

        // Verify the transaction has the correct nonce_key
        assert!(
            tx_env_2d.tempo_tx_env.is_some(),
            "2D nonce transaction should have tempo_tx_env"
        );
        let tempo_env_2d = tx_env_2d.tempo_tx_env.as_ref().unwrap();
        assert_eq!(
            tempo_env_2d.nonce_key, nonce_key_2d,
            "Should have nonce_key = 42"
        );

        // Execute the 2D nonce transaction - should succeed
        let result_2d = evm.transact_commit(tx_env_2d)?;
        assert!(
            result_2d.is_success(),
            "2D nonce transaction should succeed"
        );

        // Verify that the 2D nonce was incremented in the NonceManager precompile storage
        let nonce_slot = NonceManager::new().nonces[caller][nonce_key_2d].slot();
        let stored_nonce = evm
            .ctx
            .db()
            .storage_ref(NONCE_PRECOMPILE_ADDRESS, nonce_slot)
            .unwrap_or_default();
        assert_eq!(
            stored_nonce,
            U256::from(1),
            "2D nonce should be incremented to 1 after transaction"
        );

        // Test second 2D nonce transaction with incremented nonce
        let tx_2d_nonce_2 = TempoTransaction {
            chain_id: 1,
            fee_token: None,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 100_000,
            calls: vec![Call {
                to: TxKind::Call(identity_precompile),
                value: U256::ZERO,
                input: Bytes::from(vec![0x2E, 0x2E, 0x2E, 0x2E]), // Different data
            }],
            access_list: Default::default(),
            nonce_key: nonce_key_2d, // Same nonce key
            nonce: 1,                // Incremented nonce
            fee_payer_signature: None,
            valid_before: Some(u64::MAX),
            valid_after: None,
            key_authorization: None,
            tempo_authorization_list: vec![],
        };

        // Sign and execute second 2D nonce transaction
        let tx_2d_2_sig_hash = tx_2d_nonce_2.signature_hash();
        let tx_2d_2_challenge_b64url = URL_SAFE_NO_PAD.encode(tx_2d_2_sig_hash.as_slice());
        let tx_2d_2_client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{tx_2d_2_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
        );

        let tx_2d_2_client_data_hash = Sha256::digest(tx_2d_2_client_data_json.as_bytes());
        let mut tx_2d_2_final_hasher = Sha256::new();
        tx_2d_2_final_hasher.update(&tx_authenticator_data);
        tx_2d_2_final_hasher.update(tx_2d_2_client_data_hash);
        let tx_2d_2_message_hash = tx_2d_2_final_hasher.finalize();

        let tx_2d_2_signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(&tx_2d_2_message_hash)?;
        let tx_2d_2_sig_bytes = tx_2d_2_signature.to_bytes();

        let mut tx_2d_2_webauthn_data = Vec::new();
        tx_2d_2_webauthn_data.extend_from_slice(&tx_authenticator_data);
        tx_2d_2_webauthn_data.extend_from_slice(tx_2d_2_client_data_json.as_bytes());

        let tx_2d_2_webauthn_sig = WebAuthnSignature {
            webauthn_data: Bytes::from(tx_2d_2_webauthn_data),
            r: B256::from_slice(&tx_2d_2_sig_bytes[0..32]),
            s: normalize_p256_s(&tx_2d_2_sig_bytes[32..64]),
            pub_key_x,
            pub_key_y,
        };

        let keychain_signature_2d_2 =
            KeychainSignature::new(caller, PrimitiveSignature::WebAuthn(tx_2d_2_webauthn_sig));

        let signed_tx_2d_2 =
            tx_2d_nonce_2.into_signed(TempoSignature::Keychain(keychain_signature_2d_2));

        let tx_env_2d_2 = TempoTxEnv::from_recovered_tx(&signed_tx_2d_2, caller);

        let result_2d_2 = evm.transact_commit(tx_env_2d_2)?;
        assert!(
            result_2d_2.is_success(),
            "Second 2D nonce transaction should succeed"
        );

        // Verify nonce incremented again
        let stored_nonce_2 = evm
            .ctx
            .db()
            .storage_ref(NONCE_PRECOMPILE_ADDRESS, nonce_slot)
            .unwrap_or_default();
        assert_eq!(
            stored_nonce_2,
            U256::from(2),
            "2D nonce should be incremented to 2 after second transaction"
        );

        Ok(())
    }

    /// Test that Tempo transaction time window validation works correctly.
    /// Tests `valid_after` and `valid_before` fields against block timestamp.
    #[test]
    fn test_tempo_tx_time_window() -> eyre::Result<()> {
        use alloy_eips::eip7702::Authorization;
        use alloy_evm::FromRecoveredTx;
        use alloy_primitives::{B256, Bytes};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use p256::{
            ecdsa::{SigningKey, signature::hazmat::PrehashSigner},
            elliptic_curve::rand_core::OsRng,
        };
        use revm::ExecuteEvm;
        use sha2::{Digest, Sha256};
        use tempo_primitives::{
            TempoTransaction,
            transaction::{
                TempoSignedAuthorization,
                tempo_transaction::Call,
                tt_signature::{
                    PrimitiveSignature, TempoSignature, WebAuthnSignature, derive_p256_address,
                    normalize_p256_s,
                },
            },
        };

        use crate::{TempoBlockEnv, TempoTxEnv};

        // Identity precompile address (0x04)
        let identity_precompile = Address::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04,
        ]);

        // Generate P256 key pair for WebAuthn signature
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = B256::from_slice(encoded_point.x().unwrap().as_slice());
        let pub_key_y = B256::from_slice(encoded_point.y().unwrap().as_slice());

        // Derive caller address from P256 public key
        let caller = derive_p256_address(&pub_key_x, &pub_key_y);

        // Create a delegate address for EIP-7702 authorization
        let delegate_address = Address::repeat_byte(0x42);

        // Create authorization (EIP-7702 style)
        let auth = Authorization {
            chain_id: U256::from(1),
            address: delegate_address,
            nonce: 0,
        };

        // Compute authorization signature hash
        let mut sig_buf = Vec::new();
        sig_buf.push(tempo_primitives::transaction::tt_authorization::MAGIC);
        alloy_rlp::Encodable::encode(&auth, &mut sig_buf);
        let auth_sig_hash = alloy_primitives::keccak256(&sig_buf);

        // Create WebAuthn authenticator data for authorization
        let mut auth_authenticator_data = vec![0u8; 37];
        auth_authenticator_data[0..32].copy_from_slice(&[0xAA; 32]); // rpIdHash
        auth_authenticator_data[32] = 0x01; // UP flag set
        auth_authenticator_data[33..37].copy_from_slice(&[0, 0, 0, 0]); // signCount

        let auth_challenge_b64url = URL_SAFE_NO_PAD.encode(auth_sig_hash.as_slice());
        let auth_client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{auth_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
        );

        // Compute WebAuthn message hash for authorization
        let auth_client_data_hash = Sha256::digest(auth_client_data_json.as_bytes());
        let mut auth_final_hasher = Sha256::new();
        auth_final_hasher.update(&auth_authenticator_data);
        auth_final_hasher.update(auth_client_data_hash);
        let auth_message_hash = auth_final_hasher.finalize();

        // Sign authorization with P256
        let auth_signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(&auth_message_hash)?;
        let auth_sig_bytes = auth_signature.to_bytes();

        // Construct WebAuthn data for authorization
        let mut auth_webauthn_data = Vec::new();
        auth_webauthn_data.extend_from_slice(&auth_authenticator_data);
        auth_webauthn_data.extend_from_slice(auth_client_data_json.as_bytes());

        let auth_aa_sig =
            TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
                webauthn_data: Bytes::from(auth_webauthn_data),
                r: B256::from_slice(&auth_sig_bytes[0..32]),
                s: normalize_p256_s(&auth_sig_bytes[32..64]),
                pub_key_x,
                pub_key_y,
            }));
        let signed_auth = TempoSignedAuthorization::new_unchecked(auth, auth_aa_sig);

        // Helper closure to create and sign a transaction
        let create_signed_tx = |nonce: u64, valid_after: Option<u64>, valid_before: Option<u64>| {
            let tx = TempoTransaction {
                chain_id: 1,
                fee_token: None,
                max_priority_fee_per_gas: 0,
                max_fee_per_gas: 0,
                gas_limit: 100_000,
                calls: vec![Call {
                    to: TxKind::Call(identity_precompile),
                    value: U256::ZERO,
                    input: Bytes::from(vec![0x01, 0x02, 0x03, 0x04]),
                }],
                access_list: Default::default(),
                nonce_key: U256::ZERO,
                nonce,
                fee_payer_signature: None,
                valid_before,
                valid_after,
                key_authorization: None,
                tempo_authorization_list: vec![signed_auth.clone()],
            };

            // Get signature hash for the transaction
            let tx_sig_hash = tx.signature_hash();

            // Create WebAuthn authenticator data for transaction signature
            let mut tx_authenticator_data = vec![0u8; 37];
            tx_authenticator_data[0..32].copy_from_slice(&[0xBB; 32]); // rpIdHash
            tx_authenticator_data[32] = 0x01; // UP flag set
            tx_authenticator_data[33..37].copy_from_slice(&[0, 0, 0, 0]); // signCount

            let tx_challenge_b64url = URL_SAFE_NO_PAD.encode(tx_sig_hash.as_slice());
            let tx_client_data_json = format!(
                r#"{{"type":"webauthn.get","challenge":"{tx_challenge_b64url}","origin":"https://example.com","crossOrigin":false}}"#
            );

            // Compute WebAuthn message hash for transaction
            let tx_client_data_hash = Sha256::digest(tx_client_data_json.as_bytes());
            let mut tx_final_hasher = Sha256::new();
            tx_final_hasher.update(&tx_authenticator_data);
            tx_final_hasher.update(tx_client_data_hash);
            let tx_message_hash = tx_final_hasher.finalize();

            // Sign transaction with P256
            let tx_signature: p256::ecdsa::Signature =
                signing_key.sign_prehash(&tx_message_hash).unwrap();
            let tx_sig_bytes = tx_signature.to_bytes();

            // Construct WebAuthn data for transaction signature
            let mut tx_webauthn_data = Vec::new();
            tx_webauthn_data.extend_from_slice(&tx_authenticator_data);
            tx_webauthn_data.extend_from_slice(tx_client_data_json.as_bytes());

            let tx_webauthn_sig = WebAuthnSignature {
                webauthn_data: Bytes::from(tx_webauthn_data),
                r: B256::from_slice(&tx_sig_bytes[0..32]),
                s: normalize_p256_s(&tx_sig_bytes[32..64]),
                pub_key_x,
                pub_key_y,
            };

            tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::WebAuthn(
                tx_webauthn_sig,
            )))
        };

        // Helper to create EVM with specific block timestamp
        let create_evm_with_timestamp = |timestamp: u64| {
            let db = CacheDB::new(EmptyDB::new());
            let mut block = TempoBlockEnv::default();
            block.inner.timestamp = U256::from(timestamp);

            let ctx = Context::mainnet()
                .with_db(db)
                .with_block(block)
                .with_cfg(Default::default())
                .with_tx(Default::default());

            let mut evm: TempoEvm<CacheDB<EmptyDB>, ()> = TempoEvm::new(ctx, ());

            // Fund the caller account with some balance for gas
            evm.ctx.db_mut().insert_account_info(
                caller,
                AccountInfo {
                    balance: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
                    ..Default::default()
                },
            );

            evm
        };

        // Test case 1: Transaction fails when block_timestamp < valid_after
        {
            let mut evm = create_evm_with_timestamp(100); // Block timestamp = 100
            let signed_tx = create_signed_tx(0, Some(200), None); // valid_after = 200
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(
                result.is_err(),
                "Transaction should fail when block_timestamp < valid_after"
            );
            let err = result.unwrap_err();
            let err_str = format!("{:?}", err);
            assert!(
                err_str.contains("ValidAfter"),
                "Error should be ValidAfter, got: {}",
                err_str
            );
        }

        // Test case 2: Transaction fails when block_timestamp >= valid_before
        {
            let mut evm = create_evm_with_timestamp(200); // Block timestamp = 200
            let signed_tx = create_signed_tx(0, None, Some(200)); // valid_before = 200
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(
                result.is_err(),
                "Transaction should fail when block_timestamp >= valid_before"
            );
            let err = result.unwrap_err();
            let err_str = format!("{:?}", err);
            assert!(
                err_str.contains("ValidBefore"),
                "Error should be ValidBefore, got: {}",
                err_str
            );
        }

        // Test case 3: Transaction fails when block_timestamp > valid_before
        {
            let mut evm = create_evm_with_timestamp(300); // Block timestamp = 300
            let signed_tx = create_signed_tx(0, None, Some(200)); // valid_before = 200
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(
                result.is_err(),
                "Transaction should fail when block_timestamp > valid_before"
            );
            let err = result.unwrap_err();
            let err_str = format!("{:?}", err);
            assert!(
                err_str.contains("ValidBefore"),
                "Error should be ValidBefore, got: {}",
                err_str
            );
        }

        // Test case 4: Transaction succeeds when exactly at valid_after boundary
        {
            let mut evm = create_evm_with_timestamp(200); // Block timestamp = 200
            let signed_tx = create_signed_tx(0, Some(200), None); // valid_after = 200
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env)?;
            assert!(
                result.result.is_success(),
                "Transaction should succeed when block_timestamp == valid_after"
            );
        }

        // Test case 5: Transaction succeeds when within time window
        {
            let mut evm = create_evm_with_timestamp(150); // Block timestamp = 150
            let signed_tx = create_signed_tx(0, Some(100), Some(200)); // 100 <= 150 < 200
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env)?;
            assert!(
                result.result.is_success(),
                "Transaction should succeed when within time window"
            );
        }

        // Test case 6: Transaction fails when block_timestamp is before valid_after in a window
        {
            let mut evm = create_evm_with_timestamp(50); // Block timestamp = 50
            let signed_tx = create_signed_tx(0, Some(100), Some(200)); // valid_after = 100
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(
                result.is_err(),
                "Transaction should fail when block_timestamp < valid_after in a window"
            );
            let err = result.unwrap_err();
            let err_str = format!("{:?}", err);
            assert!(
                err_str.contains("ValidAfter"),
                "Error should be ValidAfter, got: {}",
                err_str
            );
        }

        // Test case 7: Transaction fails when block_timestamp is at/after valid_before in a window
        {
            let mut evm = create_evm_with_timestamp(200); // Block timestamp = 200
            let signed_tx = create_signed_tx(0, Some(100), Some(200)); // valid_before = 200
            let tx_env = TempoTxEnv::from_recovered_tx(&signed_tx, caller);

            let result = evm.transact(tx_env);
            assert!(
                result.is_err(),
                "Transaction should fail when block_timestamp >= valid_before in a window"
            );
            let err = result.unwrap_err();
            let err_str = format!("{:?}", err);
            assert!(
                err_str.contains("ValidBefore"),
                "Error should be ValidBefore, got: {}",
                err_str
            );
        }

        Ok(())
    }
}
