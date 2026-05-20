use std::collections::BTreeMap;

use alloy::{
    eips::Encodable2718,
    network::ReceiptResponse,
    primitives::{Address, FixedBytes, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    sol_types::{SolCall, SolEvent},
};
use reth_primitives_traits::transaction::TxHashRef;
use tempo_alloy::rpc::TempoTransactionReceipt;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, IAddressRegistry, ITIP20, ITIP403Registry};
use tempo_precompiles::{
    ADDRESS_REGISTRY_ADDRESS, TIP403_REGISTRY_ADDRESS,
    test_util::{VIRTUAL_MASTER, VIRTUAL_SALT},
    tip20::ITIP20::transferCall,
};
use tempo_primitives::{
    TempoAddressExt, TempoTxEnvelope,
    transaction::{TokenLimit, tempo_transaction::Call},
};

use crate::{
    tempo_transaction::helpers::{
        create_basic_aa_tx, create_key_authorization, sign_aa_tx_secp256k1,
        sign_aa_tx_with_secp256k1_access_key,
    },
    utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token},
};

const GAS_LIMIT: u64 = 3_000_000;
const MINT_AMOUNT: u64 = 1_000_000;
const TRANSFER_AMOUNT: u64 = 10_000;

#[derive(Clone, Copy)]
enum RewardRecipient {
    OptedOut,
    Self_,
    ThirdParty(Address),
}

struct DirectCase {
    name: &'static str,
    sender_reward: RewardRecipient,
    recipient_reward: RewardRecipient,
    reward: Option<U256>,
}

fn test_signer(index: u32) -> eyre::Result<PrivateKeySigner> {
    Ok(MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(index)?
        .build()?)
}

fn transfer_call(token: Address, to: Address, amount: U256) -> Call {
    Call {
        to: token.into(),
        value: U256::ZERO,
        input: transferCall { to, amount }.abi_encode().into(),
    }
}

async fn mint_admin<P: Provider + Clone>(
    provider: P,
    token_addr: Address,
    to: Address,
    amount: U256,
    admin_nonce: &mut u64,
) -> eyre::Result<()> {
    let receipt = ITIP20::new(token_addr, provider)
        .mint(to, amount)
        .nonce(*admin_nonce)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "mint failed");
    *admin_nonce += 1;
    Ok(())
}

async fn set_reward_recipient(
    http_url: alloy::transports::http::reqwest::Url,
    token: Address,
    signer: PrivateKeySigner,
    recipient: Address,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new().wallet(signer).connect_http(http_url);
    let receipt = ITIP20::new(token, provider)
        .setRewardRecipient(recipient)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "setRewardRecipient failed");
    Ok(())
}

async fn set_admin_reward_recipient<P: Provider + Clone>(
    provider: P,
    token_addr: Address,
    recipient: Address,
    admin_nonce: &mut u64,
) -> eyre::Result<()> {
    let receipt = ITIP20::new(token_addr, provider)
        .setRewardRecipient(recipient)
        .nonce(*admin_nonce)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "setRewardRecipient failed");
    *admin_nonce += 1;
    Ok(())
}

async fn reset_transfer_policy<P: Provider + Clone>(
    provider: P,
    token_addr: Address,
    admin_nonce: &mut u64,
) -> eyre::Result<()> {
    let receipt = ITIP20::new(token_addr, provider)
        .changeTransferPolicyId(1)
        .nonce(*admin_nonce)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "reset transfer policy failed");
    *admin_nonce += 1;
    Ok(())
}

async fn distribute_reward<P: Provider + Clone>(
    provider: P,
    token_addr: Address,
    reward: U256,
    admin_nonce: &mut u64,
) -> eyre::Result<()> {
    let receipt = ITIP20::new(token_addr, provider)
        .distributeReward(reward)
        .nonce(*admin_nonce)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "distributeReward failed");
    *admin_nonce += 1;
    Ok(())
}

async fn direct_transfer(
    http_url: alloy::transports::http::reqwest::Url,
    token: Address,
    signer: PrivateKeySigner,
    to: Address,
    amount: U256,
) -> eyre::Result<u64> {
    let provider = ProviderBuilder::new().wallet(signer).connect_http(http_url);
    let receipt = ITIP20::new(token, provider)
        .transfer(to, amount)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "transfer failed");
    Ok(receipt.gas_used)
}

async fn create_whitelist_policy<P: Provider + Clone>(
    provider: P,
    token_addr: Address,
    admin: Address,
    accounts: &[Address],
    admin_nonce: &mut u64,
) -> eyre::Result<()> {
    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider.clone());
    let receipt = registry
        .createPolicy(admin, ITIP403Registry::PolicyType::WHITELIST)
        .nonce(*admin_nonce)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    *admin_nonce += 1;
    let policy_id = receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP403Registry::PolicyCreated::decode_log(&log.inner).ok())
        .next()
        .expect("PolicyCreated event should be emitted")
        .policyId;

    for account in accounts.iter().copied().chain([admin, token_addr]) {
        let receipt = registry
            .modifyPolicyWhitelist(policy_id, account, true)
            .nonce(*admin_nonce)
            .gas(GAS_LIMIT)
            .gas_price(TEMPO_T1_BASE_FEE as u128)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status(), "modifyPolicyWhitelist failed");
        *admin_nonce += 1;
    }

    let receipt = ITIP20::new(token_addr, provider)
        .changeTransferPolicyId(policy_id)
        .nonce(*admin_nonce)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "changeTransferPolicyId failed");
    *admin_nonce += 1;
    Ok(())
}

async fn register_virtual_recipient<P: Provider + Clone>(
    provider: P,
    admin_nonce: &mut u64,
) -> eyre::Result<Address> {
    let receipt = IAddressRegistry::new(ADDRESS_REGISTRY_ADDRESS, provider)
        .registerVirtualMaster(VIRTUAL_SALT.into())
        .nonce(*admin_nonce)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    *admin_nonce += 1;
    let master = receipt
        .logs()
        .iter()
        .filter_map(|log| IAddressRegistry::MasterRegistered::decode_log(&log.inner).ok())
        .next()
        .expect("MasterRegistered event should be emitted");
    assert_eq!(master.masterAddress, VIRTUAL_MASTER);
    Ok(Address::new_virtual(master.masterId, FixedBytes::random()))
}

async fn access_key_transfer(
    provider: &RootProvider,
    chain_id: u64,
    nonce: u64,
    token: Address,
    root: &PrivateKeySigner,
    to: Address,
    amount: U256,
    spending_limit: Option<U256>,
) -> eyre::Result<u64> {
    let access = PrivateKeySigner::random();
    let limits = spending_limit.map(|limit| {
        vec![
            TokenLimit {
                token,
                limit,
                period: 0,
            },
            TokenLimit {
                token: DEFAULT_FEE_TOKEN,
                limit,
                period: 0,
            },
        ]
    });
    let key_auth = create_key_authorization(
        root,
        access.address(),
        sign_aa_tx_secp256k1(
            &create_basic_aa_tx(chain_id, nonce, vec![], GAS_LIMIT),
            &access,
        )?,
        chain_id,
        None,
        limits,
    )?;
    let mut tx = create_basic_aa_tx(
        chain_id,
        nonce,
        vec![transfer_call(token, to, amount)],
        GAS_LIMIT,
    );
    tx.key_authorization = Some(key_auth);
    let sig = sign_aa_tx_with_secp256k1_access_key(&tx, &access, root.address())?;
    let envelope: TempoTxEnvelope = tx.into_signed(sig).into();
    let hash = *envelope.tx_hash();
    provider
        .raw_request::<_, alloy::primitives::B256>(
            "eth_sendRawTransaction".into(),
            [envelope.encoded_2718()],
        )
        .await?;
    let mut receipt = None;
    for _ in 0..100 {
        receipt = provider
            .raw_request::<_, Option<TempoTransactionReceipt>>(
                "eth_getTransactionReceipt".into(),
                (hash,),
            )
            .await?;
        if receipt.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let receipt = receipt.expect("access-key transfer receipt should exist");
    assert!(receipt.status(), "access-key transfer failed");
    Ok(receipt.gas_used)
}

struct TransferGasEnv<P> {
    http_url: alloy::transports::http::reqwest::Url,
    admin_provider: P,
    token_addr: Address,
    admin: Address,
    admin_nonce: u64,
    next_user: u32,
}

impl<P: Provider + Clone> TransferGasEnv<P> {
    fn user(&mut self) -> eyre::Result<PrivateKeySigner> {
        let signer = test_signer(self.next_user)?;
        self.next_user += 1;
        Ok(signer)
    }

    async fn mint(&mut self, to: Address, amount: U256) -> eyre::Result<()> {
        mint_admin(
            self.admin_provider.clone(),
            self.token_addr,
            to,
            amount,
            &mut self.admin_nonce,
        )
        .await
    }

    async fn distribute_reward(&mut self, reward: U256) -> eyre::Result<()> {
        distribute_reward(
            self.admin_provider.clone(),
            self.token_addr,
            reward,
            &mut self.admin_nonce,
        )
        .await
    }

    async fn set_reward_recipient(
        &self,
        signer: PrivateKeySigner,
        recipient: Address,
    ) -> eyre::Result<()> {
        set_reward_recipient(self.http_url.clone(), self.token_addr, signer, recipient).await
    }

    async fn whitelist(&mut self, accounts: &[Address]) -> eyre::Result<()> {
        create_whitelist_policy(
            self.admin_provider.clone(),
            self.token_addr,
            self.admin,
            accounts,
            &mut self.admin_nonce,
        )
        .await
    }

    async fn reset_policy(&mut self) -> eyre::Result<()> {
        reset_transfer_policy(
            self.admin_provider.clone(),
            self.token_addr,
            &mut self.admin_nonce,
        )
        .await
    }

    async fn virtual_recipient(&mut self) -> eyre::Result<Address> {
        register_virtual_recipient(self.admin_provider.clone(), &mut self.admin_nonce).await
    }

    async fn record_transfer(
        &self,
        gas: &mut BTreeMap<&'static str, u64>,
        name: &'static str,
        signer: PrivateKeySigner,
        to: Address,
        amount: U256,
    ) -> eyre::Result<()> {
        gas.insert(
            name,
            direct_transfer(self.http_url.clone(), self.token_addr, signer, to, amount).await?,
        );
        Ok(())
    }

    async fn run_direct_case(
        &mut self,
        gas: &mut BTreeMap<&'static str, u64>,
        case: DirectCase,
    ) -> eyre::Result<()> {
        let sender = self.user()?;
        let recipient = self.user()?;
        self.mint(sender.address(), U256::from(MINT_AMOUNT)).await?;
        self.mint(recipient.address(), U256::from(1u64)).await?;

        let sender_reward = match case.sender_reward {
            RewardRecipient::OptedOut => None,
            RewardRecipient::Self_ => Some(sender.address()),
            RewardRecipient::ThirdParty(recipient) => Some(recipient),
        };
        let recipient_reward = match case.recipient_reward {
            RewardRecipient::OptedOut => None,
            RewardRecipient::Self_ => Some(recipient.address()),
            RewardRecipient::ThirdParty(recipient) => Some(recipient),
        };
        if let Some(reward_recipient) = sender_reward {
            self.set_reward_recipient(sender.clone(), reward_recipient)
                .await?;
        }
        if let Some(reward_recipient) = recipient_reward {
            self.set_reward_recipient(recipient.clone(), reward_recipient)
                .await?;
        }
        if let Some(reward) = case.reward {
            self.distribute_reward(reward).await?;
        }

        self.record_transfer(
            gas,
            case.name,
            sender,
            recipient.address(),
            U256::from(TRANSFER_AMOUNT),
        )
        .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer_gas_snapshots() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;
    let provider = RootProvider::new_http(http_url.clone());
    let chain_id = provider.get_chain_id().await?;

    let admin_wallet = test_signer(0)?;
    let admin = admin_wallet.address();
    let admin_provider = ProviderBuilder::new()
        .wallet(admin_wallet.clone())
        .connect_http(http_url.clone());
    let token = setup_test_token(admin_provider.clone(), admin).await?;
    let token_addr = *token.address();
    let admin_nonce = admin_provider.get_transaction_count(admin).await?;
    let mut env = TransferGasEnv {
        http_url: http_url.clone(),
        admin_provider,
        token_addr,
        admin,
        admin_nonce,
        next_user: 1,
    };
    env.mint(admin, U256::from(MINT_AMOUNT * 100)).await?;
    set_admin_reward_recipient(
        env.admin_provider.clone(),
        env.token_addr,
        admin,
        &mut env.admin_nonce,
    )
    .await?;

    let mut gas = BTreeMap::new();

    let delegate_a = test_signer(90)?.address();
    let delegate_b = test_signer(91)?.address();
    let direct_matrix = [
        DirectCase {
            name: "direct_open_policy_sender_opted_out_recipient_opted_out_no_reward_delta",
            sender_reward: RewardRecipient::OptedOut,
            recipient_reward: RewardRecipient::OptedOut,
            reward: None,
        },
        DirectCase {
            name: "direct_open_policy_sender_opted_out_recipient_opted_out_with_reward_delta",
            sender_reward: RewardRecipient::OptedOut,
            recipient_reward: RewardRecipient::OptedOut,
            reward: Some(U256::from(1_000u64)),
        },
        DirectCase {
            name: "direct_sender_self_recipient_opted_out_with_reward_delta",
            sender_reward: RewardRecipient::Self_,
            recipient_reward: RewardRecipient::OptedOut,
            reward: Some(U256::from(1_000u64)),
        },
        DirectCase {
            name: "direct_sender_opted_out_recipient_self_with_reward_delta",
            sender_reward: RewardRecipient::OptedOut,
            recipient_reward: RewardRecipient::Self_,
            reward: Some(U256::from(1_000u64)),
        },
        DirectCase {
            name: "direct_sender_self_recipient_self_with_reward_delta",
            sender_reward: RewardRecipient::Self_,
            recipient_reward: RewardRecipient::Self_,
            reward: Some(U256::from(1_000u64)),
        },
        DirectCase {
            name: "direct_sender_self_recipient_self_no_reward_delta",
            sender_reward: RewardRecipient::Self_,
            recipient_reward: RewardRecipient::Self_,
            reward: None,
        },
        DirectCase {
            name: "direct_sender_delegates_third_party_recipient_opted_out_with_reward_delta",
            sender_reward: RewardRecipient::ThirdParty(delegate_a),
            recipient_reward: RewardRecipient::OptedOut,
            reward: Some(U256::from(1_000u64)),
        },
        DirectCase {
            name: "direct_sender_opted_out_recipient_delegates_third_party_with_reward_delta",
            sender_reward: RewardRecipient::OptedOut,
            recipient_reward: RewardRecipient::ThirdParty(delegate_a),
            reward: Some(U256::from(1_000u64)),
        },
        DirectCase {
            name: "direct_sender_delegates_third_party_recipient_delegates_same_third_party_with_reward_delta",
            sender_reward: RewardRecipient::ThirdParty(delegate_a),
            recipient_reward: RewardRecipient::ThirdParty(delegate_a),
            reward: Some(U256::from(1_000u64)),
        },
        DirectCase {
            name: "direct_sender_delegates_third_party_a_recipient_delegates_third_party_b_with_reward_delta",
            sender_reward: RewardRecipient::ThirdParty(delegate_a),
            recipient_reward: RewardRecipient::ThirdParty(delegate_b),
            reward: Some(U256::from(1_000u64)),
        },
        DirectCase {
            name: "direct_sender_delegates_third_party_recipient_delegates_third_party_no_reward_delta",
            sender_reward: RewardRecipient::ThirdParty(delegate_a),
            recipient_reward: RewardRecipient::ThirdParty(delegate_b),
            reward: None,
        },
        DirectCase {
            name: "direct_reward_delta_rounds_to_zero",
            sender_reward: RewardRecipient::Self_,
            recipient_reward: RewardRecipient::Self_,
            reward: Some(U256::ONE),
        },
    ];

    for case in direct_matrix {
        env.run_direct_case(&mut gas, case).await?;
    }

    let custom_sender = env.user()?;
    let custom_recipient = env.user()?;
    env.mint(custom_sender.address(), U256::from(MINT_AMOUNT))
        .await?;
    env.mint(custom_recipient.address(), U256::from(1u64))
        .await?;
    env.whitelist(&[custom_sender.address(), custom_recipient.address()])
        .await?;
    env.record_transfer(
        &mut gas,
        "direct_custom_policy_sender_authorized_recipient_authorized_both_opted_out_no_reward_delta",
        custom_sender.clone(),
        custom_recipient.address(),
        U256::from(TRANSFER_AMOUNT),
    )
    .await?;
    env.distribute_reward(U256::from(1_000u64)).await?;
    env.record_transfer(
        &mut gas,
        "direct_custom_policy_sender_authorized_recipient_authorized_both_opted_out_with_reward_delta",
        custom_sender,
        custom_recipient.address(),
        U256::from(TRANSFER_AMOUNT),
    )
    .await?;
    env.reset_policy().await?;

    let full_sender = env.user()?;
    let full_recipient = env.user()?;
    env.mint(full_sender.address(), U256::from(TRANSFER_AMOUNT))
        .await?;
    env.record_transfer(
        &mut gas,
        "direct_full_sender_balance",
        full_sender,
        full_recipient.address(),
        U256::from(TRANSFER_AMOUNT),
    )
    .await?;

    let zero_sender = env.user()?;
    let zero_recipient = env.user()?;
    env.mint(zero_sender.address(), U256::from(MINT_AMOUNT))
        .await?;
    env.record_transfer(
        &mut gas,
        "direct_zero_amount",
        zero_sender,
        zero_recipient.address(),
        U256::ZERO,
    )
    .await?;

    let virtual_addr = env.virtual_recipient().await?;
    let virtual_sender = env.user()?;
    env.mint(virtual_sender.address(), U256::from(MINT_AMOUNT))
        .await?;
    env.record_transfer(
        &mut gas,
        "virtual_open_policy_sender_opted_out_resolved_recipient_opted_out_no_reward_delta",
        virtual_sender,
        virtual_addr,
        U256::from(TRANSFER_AMOUNT),
    )
    .await?;

    let virtual_reward_sender = env.user()?;
    env.mint(virtual_reward_sender.address(), U256::from(MINT_AMOUNT))
        .await?;
    env.set_reward_recipient(
        virtual_reward_sender.clone(),
        virtual_reward_sender.address(),
    )
    .await?;
    env.distribute_reward(U256::from(1_000u64)).await?;
    env.record_transfer(
        &mut gas,
        "virtual_open_policy_sender_self_resolved_recipient_self_with_reward_delta",
        virtual_reward_sender,
        virtual_addr,
        U256::from(TRANSFER_AMOUNT),
    )
    .await?;

    let virtual_custom_sender = env.user()?;
    env.mint(virtual_custom_sender.address(), U256::from(MINT_AMOUNT))
        .await?;
    env.whitelist(&[virtual_custom_sender.address(), VIRTUAL_MASTER])
        .await?;
    env.record_transfer(
        &mut gas,
        "virtual_custom_policy_authorizes_sender_and_resolved_recipient_both_opted_out_no_reward_delta",
        virtual_custom_sender,
        virtual_addr,
        U256::from(TRANSFER_AMOUNT),
    )
    .await?;
    env.reset_policy().await?;

    env.distribute_reward(U256::from(1_000u64)).await?;
    env.record_transfer(
        &mut gas,
        "virtual_resolves_to_same_sender_sender_self_with_reward_delta",
        admin_wallet.clone(),
        virtual_addr,
        U256::from(1u64),
    )
    .await?;
    env.admin_nonce += 1;

    let main_key_sender = env.user()?;
    let main_key_recipient = env.user()?;
    env.mint(main_key_sender.address(), U256::from(MINT_AMOUNT))
        .await?;
    env.record_transfer(
        &mut gas,
        "main_key_open_policy_both_opted_out_no_reward_delta",
        main_key_sender,
        main_key_recipient.address(),
        U256::from(TRANSFER_AMOUNT),
    )
    .await?;

    let access_root = env.user()?;
    let access_recipient = env.user()?;
    env.mint(access_root.address(), U256::from(MINT_AMOUNT * 3))
        .await?;
    gas.insert(
        "access_key_unlimited_spending_open_policy_both_opted_out_no_reward_delta",
        access_key_transfer(
            &provider,
            chain_id,
            0,
            env.token_addr,
            &access_root,
            access_recipient.address(),
            U256::from(TRANSFER_AMOUNT),
            None,
        )
        .await?,
    );
    gas.insert(
        "access_key_finite_spending_open_policy_both_opted_out_no_reward_delta",
        access_key_transfer(
            &provider,
            chain_id,
            1,
            env.token_addr,
            &access_root,
            access_recipient.address(),
            U256::from(TRANSFER_AMOUNT),
            Some(U256::from(10u128.pow(30))),
        )
        .await?,
    );

    eprintln!("\nTIP20 transfer gas snapshot:");
    for (name, gas_used) in &gas {
        eprintln!("{name}: {gas_used}");
    }

    insta::assert_yaml_snapshot!(gas);

    Ok(())
}
