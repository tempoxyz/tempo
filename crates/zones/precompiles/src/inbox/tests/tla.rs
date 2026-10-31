//! Measured native-state observations for zones/formal/Replay.tla.

use super::*;

use crate::tx_context;

impl Harness {
    fn trace(&mut self, scenario: &str, action: &str) -> eyre::Result<()> {
        let pending = self.pending_withdrawals()?.len();
        let output = call_precompile(
            &mut self.ctx,
            &self.outbox_precompile,
            Address::ZERO,
            &IZoneOutbox::lastFallbackNonceCall {}.abi_encode(),
            GAS,
            true,
            ZONE_OUTBOX_ADDRESS,
            ZONE_OUTBOX_ADDRESS,
        )?;
        assert!(output.is_success());
        let nonce = IZoneOutbox::lastFallbackNonceCall::abi_decode_returns(&output.bytes)?;
        let mut storage = test_storage_provider(&mut self.ctx, u64::MAX, false);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let inbox = ZoneInbox::new();
            let outbox = ZoneOutbox::new();
            let supply = TIP20Token::from_address(PATH_USD_ADDRESS)?.total_supply()?;
            let processed = inbox.processed_deposit_number()?;
            let refund = inbox.withdrawal_bounce_backs[PATH_USD_ADDRESS][ALICE].read()?;
            let finalized = outbox.last_batch()?.withdrawalBatchIndex;
            let mut fallback_count = 0;
            for index in 1..=nonce {
                fallback_count += usize::from(!outbox.fallback_recipient(index)?.is_zero());
            }
            println!(
                "ZONES_TLA {{\"scenario\":\"{scenario}\",\"action\":\"{action}\",\"state\":{{\"supply\":{supply},\"processed\":{processed},\"zoneRefund\":{refund},\"pendingCount\":{pending},\"finalized\":{finalized},\"nextNonce\":{nonce},\"fallbackCount\":{fallback_count}}}}}"
            );
            Ok(())
        })
    }

    fn trace_outbox(&mut self, caller: Address, data: impl AsRef<[u8]>) -> eyre::Result<Bytes> {
        self.l1_state.reset_transaction_state();
        let _guard = tx_context::set_current_transaction(B256::repeat_byte(1), caller);
        let output = call_precompile(
            &mut self.ctx,
            &self.outbox_precompile,
            caller,
            data.as_ref(),
            GAS,
            false,
            ZONE_OUTBOX_ADDRESS,
            ZONE_OUTBOX_ADDRESS,
        )?;
        assert!(output.is_success(), "outbox reverted: {:?}", output.bytes);
        Ok(output.bytes)
    }

    fn trace_finalize(&mut self) -> eyre::Result<()> {
        let count = self.pending_withdrawals()?.len();
        let output = self.trace_outbox(
            Address::ZERO,
            IZoneOutbox::finalizeWithdrawalBatchCall {
                count: U256::from(count),
                blockNumber: self.ctx.block.inner.number.to(),
                encryptedSenders: vec![Bytes::new(); count],
            }
            .abi_encode(),
        )?;
        let hash = IZoneOutbox::finalizeWithdrawalBatchCall::abi_decode_returns(&output)?;
        assert_eq!(hash.is_zero(), count == 0);
        Ok(())
    }
}

/// Executes the real ECIES Inbox, TIP-20, Outbox, and refund paths. The portal
/// queue and Tempo headers are L1 fixtures, not a running second chain.
#[test]
fn tla_native_lifecycle_traces() -> eyre::Result<()> {
    for (scenario, deposit_ok, bounce, bounce_ok) in [
        ("native-success", true, false, true),
        ("native-deposit-refund", false, false, true),
        ("native-bounce-mint", true, true, true),
        ("native-bounce-refund", true, true, false),
    ] {
        let mut harness = Harness::new()?;
        harness.trace(scenario, "init")?;
        let fixture = EncryptedDepositFixture::new();
        let decrypted = fixture.decrypt().expect("fixture decrypts");
        let info = crate::ecies::hkdf_info(&PORTAL, &fixture.key_index, &fixture.eph_pub_x, &ALICE);
        let key =
            crate::ecies::hkdf_sha256(&decrypted.proof.shared_secret.0, b"ecies-aes-key", &info);
        let plaintext = build_plaintext(&ALICE, &fixture.memo);
        let (ciphertext, nonce, tag) = encrypt_plaintext(&key, &plaintext);
        let (sequencer_x, parity) = compressed_x_and_parity(&fixture.seq_pub);
        let base: U256 = keccak256(B256::from(portal::slots::ENCRYPTION_KEYS)).into();
        let slot = base + fixture.key_index * U256::from(2);
        harness.l1.insert(PORTAL, slot, 1, sequencer_x.into());
        harness
            .l1
            .insert(PORTAL, slot + U256::ONE, 1, U256::from(parity));
        harness.l1.with_storage(1, || {
            ZonePortalStorage::new(PORTAL).token_configs[PATH_USD_ADDRESS]
                .enabled
                .write(true)
        })?;
        let deposit = Deposit {
            token: PATH_USD_ADDRESS,
            sender: ALICE,
            amount: 1,
            tempoRefundRecipient: ALICE,
            keyIndex: fixture.key_index,
            encrypted: tempo_contracts::zones::DepositPayload {
                ephemeralPubkeyX: fixture.eph_pub_x,
                ephemeralPubkeyYParity: fixture.eph_pub_y_parity,
                ciphertext: ciphertext.into(),
                nonce: nonce.into(),
                tag: tag.into(),
            },
        };
        let deposit_hash =
            keccak256((DepositType::Deposit, deposit.clone(), B256::ZERO).abi_encode_params());
        harness.set_queue_hash(deposit_hash);
        harness.trace(scenario, "fund")?; // L1 fixture: funds are not minted on the zone yet.
        if !deposit_ok {
            set_receive_policy(&mut harness, false)?;
        }
        let output = harness.call_atomic(
            Address::ZERO,
            harness
                .advance_call(
                    vec![QueuedDeposit {
                        depositType: DepositType::Deposit,
                        rejected: false,
                        depositData: deposit.abi_encode().into(),
                    }],
                    vec![DecryptionData {
                        sharedSecret: decrypted.proof.shared_secret,
                        sharedSecretYParity: decrypted.proof.shared_secret_y_parity,
                        cpProof: decrypted.proof.cp_proof,
                    }],
                )
                .abi_encode(),
        )?;
        assert!(output.is_success(), "advance reverted: {:?}", output.bytes);
        harness.trace(
            scenario,
            if deposit_ok {
                "advance_ok"
            } else {
                "advance_fail"
            },
        )?;
        if deposit_ok {
            let mut storage = test_storage_provider(&mut harness.ctx, u64::MAX, false);
            StorageCtx::enter(&mut storage, || {
                TIP20Token::from_address(PATH_USD_ADDRESS)?.approve(
                    ALICE,
                    ITIP20::approveCall {
                        spender: ZONE_OUTBOX_ADDRESS,
                        amount: U256::ONE,
                    },
                )
            })?;
            drop(storage);
            let output = harness.trace_outbox(
                ALICE,
                IZoneOutbox::requestWithdrawalCall {
                    token: PATH_USD_ADDRESS,
                    to: BOB,
                    amount: 1,
                    memo: B256::ZERO,
                    gasLimit: 0,
                    zoneFallbackRecipient: ALICE,
                    data: Bytes::new(),
                    revealTo: Bytes::new(),
                }
                .abi_encode(),
            )?;
            assert!(output.is_empty());
            harness.trace(scenario, "request")?;
        }
        harness.trace_finalize()?;
        harness.trace(scenario, "finalize")?;
        harness.trace(scenario, "submit")?; // L1 fixture: accept the finalized batch.
        harness.trace(scenario, if bounce { "deliver_fail" } else { "deliver_ok" })?;
        if bounce {
            let deposit = WithdrawalBounceBackDeposit {
                token: PATH_USD_ADDRESS,
                to: Address::with_last_byte(1),
                amount: 1,
            };
            let hash = keccak256(
                (
                    DepositType::WithdrawalBounceBack,
                    deposit.clone(),
                    deposit_hash,
                )
                    .abi_encode_params(),
            );
            let header = TempoHeader {
                inner: alloy_consensus::Header {
                    parent_hash: keccak256(alloy_rlp::encode(harness.child_header())),
                    number: 2,
                    ..Default::default()
                },
                ..Default::default()
            };
            harness.l1.seed_active_sequencer(PORTAL, 2, SEQUENCER);
            harness.l1.with_storage(2, || {
                ZonePortalStorage::new(PORTAL)
                    .current_deposit_queue_hash
                    .write(hash)
            })?;
            if !bounce_ok {
                set_receive_policy(&mut harness, false)?;
            }
            harness.l1_state.reset_transaction_state();
            let output = harness.call_atomic(
                Address::ZERO,
                IZoneInbox::advanceTempoCall {
                    header: alloy_rlp::encode(header).into(),
                    deposits: vec![QueuedDeposit {
                        depositType: DepositType::WithdrawalBounceBack,
                        rejected: false,
                        depositData: deposit.abi_encode().into(),
                    }],
                    decryptions: Vec::new(),
                    enabledTokens: Vec::new(),
                }
                .abi_encode(),
            )?;
            assert!(
                output.is_success(),
                "bounce advance reverted: {:?}",
                output.bytes
            );
            harness.trace(
                scenario,
                if bounce_ok {
                    "advance_ok"
                } else {
                    "advance_fail"
                },
            )?;
            if !bounce_ok {
                set_receive_policy(&mut harness, true)?;
                let output = harness.call_atomic(
                    ALICE,
                    IZoneInbox::claimRefundCall {
                        token: PATH_USD_ADDRESS,
                    }
                    .abi_encode(),
                )?;
                assert!(output.is_success());
                assert_eq!(
                    IZoneInbox::claimRefundCall::abi_decode_returns(&output.bytes)?,
                    1
                );
                harness.trace(scenario, "claim_zone")?;
                let repeated = harness.call_atomic(
                    ALICE,
                    IZoneInbox::claimRefundCall {
                        token: PATH_USD_ADDRESS,
                    }
                    .abi_encode(),
                )?;
                assert!(repeated.is_revert());
                assert_eq!(repeated.bytes, IZoneInbox::NoRefund {}.abi_encode());
                harness.trace(scenario, "retry")?;
            }
        } else {
            harness.trace_finalize()?; // Empty batches still advance the zone batch index.
            harness.trace(scenario, "finalize")?;
            harness.trace(scenario, "submit")?;
        }
        harness.trace(scenario, "complete")?;
    }
    Ok(())
}

fn set_receive_policy(harness: &mut Harness, allowed: bool) -> eyre::Result<()> {
    let mut storage = test_storage_provider(&mut harness.ctx, u64::MAX, false);
    StorageCtx::enter(&mut storage, || {
        TIP403Registry::new().set_receive_policy(
            ALICE,
            ITIP403Registry::setReceivePolicyCall {
                senderPolicyId: if allowed {
                    ALLOW_ALL_POLICY_ID
                } else {
                    REJECT_ALL_POLICY_ID
                },
                tokenFilterId: ALLOW_ALL_POLICY_ID,
                recoveryAuthority: Address::ZERO,
            },
        )
    })?;
    Ok(())
}
