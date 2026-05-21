use alloy::{
    primitives::{Address, FixedBytes, U256},
    providers::Provider,
    sol_types::SolEvent,
};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{
    IAddressRegistry, ITIP20, ITIP403Registry, ITIPFeeAMM, TIP_FEE_MANAGER_ADDRESS,
};
use tempo_precompiles::{
    ADDRESS_REGISTRY_ADDRESS, PATH_USD_ADDRESS, TIP403_REGISTRY_ADDRESS,
    test_util::{VIRTUAL_MASTER, VIRTUAL_SALT},
};
use tempo_primitives::TempoAddressExt;

use super::helpers::{
    GAS_LIMIT, GasSnapshot, TempoCalls, TempoTxSender, fixed_signer, print_gas_snapshot,
    test_signer,
};
use crate::{
    gas::helpers::Receipt,
    utils::{TestNodeBuilder, setup_test_token},
};

const MINT_AMOUNT: u64 = 1_000_000;
const TRANSFER_AMOUNT: u64 = 10_000;
const STANDARD_REWARD: u64 = 1_000;

#[derive(Clone, Copy)]
enum RewardMode {
    OptedOut,
    Own,
    Delegate(bool),
}

#[derive(Clone, Copy)]
enum RecipientKind {
    Direct { reward: RewardMode },
    Virtual,
}

#[derive(Clone, Copy)]
enum TransferAmount {
    Some,
    Full,
    Zero,
}

#[derive(Clone, Copy)]
struct TransferScenario {
    custom_policy: bool,
    sender_reward: RewardMode,
    recipient: RecipientKind,
    reward_delta: bool,
    amount: TransferAmount,
}

impl TransferScenario {
    fn name(&self) -> String {
        join_name([
            self.recipient.name().into(),
            policy_name(self.custom_policy).into(),
            self.amount.name().into(),
            self.rewards_name(),
        ])
    }

    fn rewards_name(&self) -> String {
        let mut parts = vec!["rewards"];
        let sender = self.sender_reward.sender_name();
        if !sender.is_empty() {
            parts.push(sender);
        }
        if let RecipientKind::Direct { reward } = self.recipient {
            let recipient = reward.recipient_name();
            if !recipient.is_empty() {
                parts.push(recipient);
            }
        }
        if self.reward_delta {
            parts.push("with_delta");
        }

        if parts.len() == 1 {
            String::new()
        } else {
            parts.join("_")
        }
    }

    fn sender_balance(&self) -> U256 {
        match self.amount {
            TransferAmount::Full => U256::from(TRANSFER_AMOUNT),
            _ => U256::from(MINT_AMOUNT),
        }
    }

    fn amount(&self) -> U256 {
        match self.amount {
            TransferAmount::Some | TransferAmount::Full => U256::from(TRANSFER_AMOUNT),
            TransferAmount::Zero => U256::ZERO,
        }
    }
}

fn policy_name(custom_policy: bool) -> &'static str {
    if custom_policy {
        "policy:needs_whitelist"
    } else {
        "policy:all_whitelisted"
    }
}

impl RecipientKind {
    fn name(self) -> &'static str {
        match self {
            Self::Direct { .. } => "",
            Self::Virtual => "virtual_address",
        }
    }
}

impl TransferAmount {
    fn name(self) -> &'static str {
        match self {
            Self::Some => "amount:some",
            Self::Full => "amount:full",
            Self::Zero => "amount:zero",
        }
    }
}

impl RewardMode {
    fn sender_name(self) -> &'static str {
        match self {
            Self::OptedOut => "sender_opted_out",
            Self::Own => "",
            Self::Delegate(true) => "sender_delegates_a",
            Self::Delegate(false) => "sender_delegates_b",
        }
    }

    fn recipient_name(self) -> &'static str {
        match self {
            Self::OptedOut => "recipient_opted_out",
            Self::Own => "",
            Self::Delegate(true) => "recipient_delegates_a",
            Self::Delegate(false) => "recipient_delegates_b",
        }
    }
}

fn join_name<const N: usize>(parts: [String; N]) -> String {
    parts
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("::")
}

async fn create_whitelist_policy<P: Provider + Clone>(
    provider: P,
    admin: Address,
    accounts: Vec<Address>,
    admin_nonce: &mut u64,
) -> eyre::Result<u64> {
    let receipt = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider)
        .createPolicyWithAccounts(admin, ITIP403Registry::PolicyType::WHITELIST, accounts)
        .nonce(*admin_nonce)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .send()
        .await?
        .get_receipt()
        .await?;
    *admin_nonce += 1;
    Ok(receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP403Registry::PolicyCreated::decode_log(&log.inner).ok())
        .next()
        .expect("PolicyCreated event should be emitted")
        .policyId)
}

async fn register_virtual_master<P: Provider + Clone>(
    provider: P,
    admin_nonce: &mut u64,
) -> eyre::Result<FixedBytes<4>> {
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
    Ok(master.masterId)
}

struct TransferGasEnv<P> {
    token_addr: Address,
    admin: TempoTxSender<P>,
    next_user: u32,
    virtual_master_id: Option<FixedBytes<4>>,
    reward_sender: TempoTxSender<P>,
    reward_recipient: Address,
}

impl<P: Provider + Clone> TransferGasEnv<P> {
    fn admin_address(&self) -> Address {
        self.admin.address()
    }

    fn user(&mut self) -> eyre::Result<TempoTxSender<P>> {
        let signer = test_signer(self.next_user)?;
        self.next_user += 1;
        Ok(TempoTxSender::with_zero_nonce(
            self.admin.provider.clone(),
            self.admin.chain_id,
            signer,
        ))
    }

    async fn set_reward_recipient(
        &self,
        signer: &mut TempoTxSender<P>,
        recipient: Address,
    ) -> eyre::Result<Receipt> {
        signer
            .send_call(
                self.token_addr,
                ITIP20::setRewardRecipientCall { recipient },
            )
            .await
    }

    async fn prepare_reward_delta_hook(&mut self) -> eyre::Result<()> {
        TempoCalls::new()
            .push(
                self.token_addr,
                ITIP20::mintCall {
                    to: self.reward_sender.address(),
                    amount: U256::from(MINT_AMOUNT),
                },
            )
            .push(
                PATH_USD_ADDRESS,
                ITIP20::transferCall {
                    to: self.reward_sender.address(),
                    amount: U256::from(MINT_AMOUNT),
                },
            )
            .send(&mut self.admin)
            .await?;
        self.reward_sender
            .send_call(
                self.token_addr,
                ITIP20::setRewardRecipientCall {
                    recipient: self.reward_sender.address(),
                },
            )
            .await?;
        Ok(())
    }

    async fn accrue_reward_delta(&mut self) -> eyre::Result<()> {
        TempoCalls::new()
            .push(
                self.token_addr,
                ITIP20::distributeRewardCall {
                    amount: U256::from(STANDARD_REWARD),
                },
            )
            .send(&mut self.admin)
            .await?;
        self.reward_sender
            .send_call(
                self.token_addr,
                ITIP20::transferCall {
                    to: self.reward_recipient,
                    amount: U256::from(1),
                },
            )
            .await?;
        Ok(())
    }

    async fn whitelist(&mut self, accounts: &[Address]) -> eyre::Result<Receipt> {
        let accounts = accounts
            .iter()
            .copied()
            .chain([
                self.admin_address(),
                self.token_addr,
                TIP_FEE_MANAGER_ADDRESS,
            ])
            .collect::<Vec<_>>();
        let policy_id = create_whitelist_policy(
            self.admin.provider.clone(),
            self.admin_address(),
            accounts,
            &mut self.admin.nonce,
        )
        .await?;

        TempoCalls::new()
            .push(
                self.token_addr,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )
            .send(&mut self.admin)
            .await
    }

    async fn reset_policy(&mut self) -> eyre::Result<Receipt> {
        TempoCalls::new()
            .push(
                self.token_addr,
                ITIP20::changeTransferPolicyIdCall { newPolicyId: 1 },
            )
            .send(&mut self.admin)
            .await
    }

    async fn virtual_recipient(&mut self) -> eyre::Result<Address> {
        let master_id = match self.virtual_master_id {
            Some(master_id) => master_id,
            None => {
                let master_id =
                    register_virtual_master(self.admin.provider.clone(), &mut self.admin.nonce)
                        .await?;
                self.virtual_master_id = Some(master_id);
                master_id
            }
        };
        Ok(Address::new_virtual(master_id, FixedBytes::random()))
    }

    async fn transfer(
        &self,
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        signer: &mut TempoTxSender<P>,
        to: Address,
        amount: U256,
    ) -> eyre::Result<Receipt> {
        gas.call(
            name,
            signer,
            self.token_addr,
            ITIP20::transferCall { to, amount },
        )
        .await
    }

    async fn apply_reward_mode(
        &self,
        signer: &mut TempoTxSender<P>,
        mode: RewardMode,
        shared_delegate: Address,
        unique_delegate: Address,
    ) -> eyre::Result<()> {
        let recipient = match mode {
            RewardMode::OptedOut => return Ok(()),
            RewardMode::Own => signer.address(),
            RewardMode::Delegate(true) => shared_delegate,
            RewardMode::Delegate(false) => unique_delegate,
        };
        self.set_reward_recipient(signer, recipient).await?;
        Ok(())
    }

    async fn run_transfer_scenario(
        &mut self,
        gas: &mut GasSnapshot,
        name: String,
        scenario: TransferScenario,
    ) -> eyre::Result<Receipt> {
        self.reset_policy().await?;

        let mut sender = self.user()?;
        let mut recipient = match scenario.recipient {
            RecipientKind::Direct { .. } => Some(self.user()?),
            RecipientKind::Virtual => None,
        };
        let mut funded_accounts = vec![(sender.address(), scenario.sender_balance())];
        if let Some(recipient) = &recipient {
            funded_accounts.push((recipient.address(), U256::from(MINT_AMOUNT)));
        }
        let token_addr = self.token_addr;
        TempoCalls::new()
            .extend(funded_accounts.iter().copied(), |(to, amount)| {
                (token_addr, ITIP20::mintCall { to, amount })
            })
            .extend(funded_accounts.iter().map(|(to, _)| *to), |to| {
                (
                    PATH_USD_ADDRESS,
                    ITIP20::transferCall {
                        to,
                        amount: U256::from(MINT_AMOUNT),
                    },
                )
            })
            .send(&mut self.admin)
            .await?;

        let to = match &recipient {
            Some(recipient) => recipient.address(),
            None => self.virtual_recipient().await?,
        };
        let shared_delegate = Address::random();
        let unique_delegate = Address::random();

        self.apply_reward_mode(
            &mut sender,
            scenario.sender_reward,
            shared_delegate,
            unique_delegate,
        )
        .await?;
        if let (Some(recipient), RecipientKind::Direct { reward }) =
            (&mut recipient, scenario.recipient)
        {
            self.apply_reward_mode(recipient, reward, shared_delegate, unique_delegate)
                .await?;
        }
        if scenario.reward_delta {
            self.accrue_reward_delta().await?;
        }
        if scenario.custom_policy {
            let policy_recipient = match scenario.recipient {
                RecipientKind::Direct { .. } => to,
                RecipientKind::Virtual => VIRTUAL_MASTER,
            };
            let mut accounts = vec![
                sender.address(),
                policy_recipient,
                shared_delegate,
                unique_delegate,
                Address::ZERO,
            ];
            if matches!(scenario.recipient, RecipientKind::Direct { .. }) {
                accounts.push(to);
            }
            self.whitelist(&accounts).await?;
        }

        let transfer_result = self
            .transfer(gas, name, &mut sender, to, scenario.amount())
            .await;
        if scenario.custom_policy {
            self.reset_policy().await?;
        }
        transfer_result
    }
}

fn tip20_transfer_gas_cases() -> Vec<TransferScenario> {
    use RewardMode::*;

    const REWARD_DELTAS: [bool; 2] = [false, true];
    const POLICIES: [bool; 2] = [false, true];
    const REWARD_MODES: [RewardMode; 4] = [Own, OptedOut, Delegate(true), Delegate(false)];
    const RECIPIENTS: [RecipientKind; 2] = [
        RecipientKind::Direct { reward: OptedOut },
        RecipientKind::Virtual,
    ];
    const AMOUNTS: [TransferAmount; 3] = [
        TransferAmount::Some,
        TransferAmount::Full,
        TransferAmount::Zero,
    ];

    let mut cases = Vec::new();

    // Virtual-address matrix on the normal amount path.
    for recipient in RECIPIENTS {
        for custom_policy in POLICIES {
            for sender_reward in REWARD_MODES {
                for reward_delta in REWARD_DELTAS {
                    for amount in AMOUNTS {
                        if (custom_policy && matches!(sender_reward, Own) && reward_delta)
                            || (matches!(recipient, RecipientKind::Virtual)
                                && !matches!(amount, TransferAmount::Some))
                        {
                            continue;
                        }

                        cases.push(TransferScenario {
                            custom_policy,
                            sender_reward,
                            recipient,
                            reward_delta,
                            amount,
                        });
                    }
                }
            }
        }
    }

    // Full rewards matrix on the custom-policy, regular-recipient, non-edge amount path.
    for sender_reward in REWARD_MODES {
        for recipient_reward in REWARD_MODES {
            for reward_delta in REWARD_DELTAS {
                cases.push(TransferScenario {
                    custom_policy: true,
                    sender_reward,
                    recipient: RecipientKind::Direct {
                        reward: recipient_reward,
                    },
                    reward_delta,
                    amount: TransferAmount::Some,
                });
            }
        }
    }

    cases.sort_by_key(|case| case.name());
    cases.dedup_by_key(|case| case.name());
    cases
}

async fn run_tip20_transfer_gas_cases<P: Provider + Clone>(
    env: &mut TransferGasEnv<P>,
    cases: Vec<TransferScenario>,
) -> eyre::Result<GasSnapshot> {
    let mut gas = GasSnapshot::new();
    let total = cases.len();

    eprintln!("\n=== TIP20 transfer gas matrix ===");
    eprintln!("Running {total} cases...");

    for (index, case) in cases.into_iter().enumerate() {
        let name = case.name();
        eprintln!("[{}/{}] {name}", index + 1, total);
        env.run_transfer_scenario(&mut gas, name, case).await?;
    }

    Ok(gas)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_transfer_gas_snapshots() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let mut admin = TempoTxSender::connect(setup.http_url.clone(), test_signer(0)?).await?;
    let token = setup_test_token(admin.provider.clone(), admin.address()).await?;
    admin.sync_nonce().await?;
    let token_addr = *token.address();
    TempoCalls::new()
        .push(
            token_addr,
            ITIP20::mintCall {
                to: admin.address(),
                amount: U256::from(MINT_AMOUNT * 100),
            },
        )
        .push(
            token_addr,
            ITIP20::setRewardRecipientCall {
                recipient: admin.address(),
            },
        )
        .send(&mut admin)
        .await?;

    TempoCalls::new()
        .push(
            TIP_FEE_MANAGER_ADDRESS,
            ITIPFeeAMM::mintCall {
                userToken: token_addr,
                validatorToken: PATH_USD_ADDRESS,
                amountValidatorToken: U256::from(MINT_AMOUNT * 100),
                to: admin.address(),
            },
        )
        .send(&mut admin)
        .await?;

    let reward_sender =
        TempoTxSender::with_zero_nonce(admin.provider.clone(), admin.chain_id, fixed_signer(0x21));
    let reward_recipient = fixed_signer(0x22).address();
    let mut env = TransferGasEnv {
        token_addr,
        admin,
        next_user: 1,
        virtual_master_id: None,
        reward_sender,
        reward_recipient,
    };
    env.prepare_reward_delta_hook().await?;

    let gas = run_tip20_transfer_gas_cases(&mut env, tip20_transfer_gas_cases()).await?;

    print_gas_snapshot("TIP20 transfer gas snapshot", &gas);
    insta::assert_yaml_snapshot!(gas);

    Ok(())
}
