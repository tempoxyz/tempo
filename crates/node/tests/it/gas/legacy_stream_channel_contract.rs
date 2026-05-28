use std::{fs, path::Path, process::Command};

use alloy::{
    hex,
    primitives::{Address, B256, Bytes, U256},
    providers::Provider,
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::{CREATEX_ADDRESS, CreateX, precompiles::ITIP20};
use tempo_precompiles::PATH_USD_ADDRESS;

use super::helpers::{
    GAS_LIMIT, GasSnapshot, Receipt, TempoTxSender, fixed_signer, print_gas_snapshot, test_signer,
};
use crate::utils::TestNodeBuilder;

const DEPOSIT: u64 = 1_000_000;
const FUNDING: u64 = 20_000_000;
const LEGACY_STREAM_CHANNEL_SOURCE: &str =
    include_str!("../../../../../tips/verify/src/LegacyTempoStreamChannel.sol");
const ITIP20_SOURCE: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITIP20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"#;
const I_TEMPO_STREAM_CHANNEL_SOURCE: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITempoStreamChannel {
    struct Channel {
        bool finalized;
        uint64 closeRequestedAt;
        address payer;
        address payee;
        address token;
        address authorizedSigner;
        uint128 deposit;
        uint128 settled;
    }

    error AmountExceedsDeposit();
    error AmountNotIncreasing();
    error ChannelAlreadyExists();
    error ChannelFinalized();
    error ChannelNotFound();
    error CloseNotReady();
    error InvalidSignature();
    error NotPayee();
    error NotPayer();
    error TransferFailed();

    event ChannelOpened(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        address token,
        address authorizedSigner,
        bytes32 salt,
        uint256 deposit
    );
    event Settled(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 cumulativeAmount,
        uint256 deltaPaid,
        uint256 newSettled
    );
    event TopUp(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 additionalDeposit,
        uint256 newDeposit
    );
    event CloseRequested(
        bytes32 indexed channelId, address indexed payer, address indexed payee, uint256 closeGraceEnd
    );
    event CloseRequestCancelled(bytes32 indexed channelId, address indexed payer, address indexed payee);
    event ChannelClosed(
        bytes32 indexed channelId,
        address indexed payer,
        address indexed payee,
        uint256 settledToPayee,
        uint256 refundedToPayer
    );
    event ChannelExpired(bytes32 indexed channelId, address indexed payer, address indexed payee);
}
"#;

sol! {
    #[sol(rpc)]
    interface ITempoStreamChannel {
        function open(
            address payee,
            address token,
            uint128 deposit,
            bytes32 salt,
            address authorizedSigner
        ) external returns (bytes32 channelId);
        function settle(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;
        function topUp(bytes32 channelId, uint256 additionalDeposit) external;
        function close(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;
        function requestClose(bytes32 channelId) external;
        function computeChannelId(
            address payer,
            address payee,
            address token,
            bytes32 salt,
            address authorizedSigner
        ) external view returns (bytes32);
        function getVoucherDigest(bytes32 channelId, uint128 cumulativeAmount) external view returns (bytes32);
    }
}

struct ChannelEnv<P> {
    address: Address,
    contract: ITempoStreamChannel::ITempoStreamChannelInstance<P>,
    id: B256,
    open_gas_used: u64,
}

impl<P: Provider + Clone> ChannelEnv<P> {
    async fn open(
        address: Address,
        sender: &mut TempoTxSender<P>,
        payee: Address,
        salt: u8,
    ) -> eyre::Result<Self> {
        let contract = ITempoStreamChannel::new(address, sender.provider.clone());
        let salt = B256::with_last_byte(salt);
        let id = contract
            .computeChannelId(
                sender.address(),
                payee,
                PATH_USD_ADDRESS,
                salt,
                Address::ZERO,
            )
            .call()
            .await?;
        sender
            .send_call(
                PATH_USD_ADDRESS,
                ITIP20::approveCall {
                    spender: address,
                    amount: U256::from(DEPOSIT),
                },
            )
            .await?;
        let sent = sender
            .send_call(
                address,
                ITempoStreamChannel::openCall {
                    payee,
                    token: PATH_USD_ADDRESS,
                    deposit: DEPOSIT as u128,
                    salt,
                    authorizedSigner: Address::ZERO,
                },
            )
            .await?;
        Ok(Self {
            address,
            contract,
            id,
            open_gas_used: sent.gas_used,
        })
    }

    fn gas_used(&self) -> u64 {
        self.open_gas_used
    }

    async fn top_up(
        &self,
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        sender: &mut TempoTxSender<P>,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        sender
            .send_call(
                PATH_USD_ADDRESS,
                ITIP20::approveCall {
                    spender: self.address,
                    amount: U256::from(amount),
                },
            )
            .await?;
        gas.call(
            name,
            sender,
            self.address,
            ITempoStreamChannel::topUpCall {
                channelId: self.id,
                additionalDeposit: U256::from(amount),
            },
        )
        .await
    }

    async fn settle(
        &self,
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        submitter: &mut TempoTxSender<P>,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        let signature = self.voucher_signature(payer, amount).await?;
        gas.call(
            name,
            submitter,
            self.address,
            ITempoStreamChannel::settleCall {
                channelId: self.id,
                cumulativeAmount: amount as u128,
                signature,
            },
        )
        .await
    }

    async fn settle_unrecorded(
        &self,
        submitter: &mut TempoTxSender<P>,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        let signature = self.voucher_signature(payer, amount).await?;
        submitter
            .send_call(
                self.address,
                ITempoStreamChannel::settleCall {
                    channelId: self.id,
                    cumulativeAmount: amount as u128,
                    signature,
                },
            )
            .await
    }

    async fn close(
        &self,
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        submitter: &mut TempoTxSender<P>,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Receipt> {
        let signature = self.voucher_signature(payer, amount).await?;
        gas.call(
            name,
            submitter,
            self.address,
            ITempoStreamChannel::closeCall {
                channelId: self.id,
                cumulativeAmount: amount as u128,
                signature,
            },
        )
        .await
    }

    async fn request_close(
        &self,
        gas: &mut GasSnapshot,
        name: impl Into<String>,
        sender: &mut TempoTxSender<P>,
    ) -> eyre::Result<Receipt> {
        gas.call(
            name,
            sender,
            self.address,
            ITempoStreamChannel::requestCloseCall { channelId: self.id },
        )
        .await
    }

    async fn voucher_signature(
        &self,
        payer: &PrivateKeySigner,
        amount: u64,
    ) -> eyre::Result<Bytes> {
        let digest = self
            .contract
            .getVoucherDigest(self.id, amount as u128)
            .call()
            .await?;
        Ok(Bytes::copy_from_slice(
            &payer.sign_hash_sync(&digest)?.as_bytes(),
        ))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_legacy_stream_channel_contract_gas_snapshots() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let mut funder = TempoTxSender::connect(http_url.clone(), test_signer(0)?).await?;
    let mut payer =
        TempoTxSender::connect_with_zero_nonce(http_url.clone(), fixed_signer(0x11)).await?;
    let mut payee =
        TempoTxSender::connect_with_zero_nonce(http_url.clone(), fixed_signer(0x12)).await?;
    let mut new_payee =
        TempoTxSender::connect_with_zero_nonce(http_url, fixed_signer(0x13)).await?;
    let legacy_contract = deploy_legacy_stream_channel(&mut funder).await?;

    funder
        .fund_tip20(
            PATH_USD_ADDRESS,
            [payer.address(), payee.address(), new_payee.address()],
            U256::from(FUNDING),
        )
        .await?;

    let mut gas = GasSnapshot::new();

    let first = ChannelEnv::open(legacy_contract, &mut payer, payee.address(), 1).await?;
    gas.record("open_new_channel_first_reserve_balance", first.gas_used());

    let second = ChannelEnv::open(legacy_contract, &mut payer, payee.address(), 2).await?;
    gas.record(
        "open_new_channel_existing_reserve_balance",
        second.gas_used(),
    );

    second
        .top_up(&mut gas, "top_up_existing_channel", &mut payer, 250_000)
        .await?;

    second
        .settle(
            &mut gas,
            "settle_existing_channel_existing_payee_balance",
            &mut payee,
            &payer.signer,
            400_000,
        )
        .await?;

    let settle_new_payee =
        ChannelEnv::open(legacy_contract, &mut payer, new_payee.address(), 3).await?;
    settle_new_payee
        .settle(
            &mut gas,
            "settle_existing_channel_new_payee_balance",
            &mut new_payee,
            &payer.signer,
            300_000,
        )
        .await?;

    let close_only = ChannelEnv::open(legacy_contract, &mut payer, payee.address(), 4).await?;
    close_only
        .close(
            &mut gas,
            "close_existing_channel_no_prior_settlement",
            &mut payee,
            &payer.signer,
            700_000,
        )
        .await?;

    let close_after_settle =
        ChannelEnv::open(legacy_contract, &mut payer, payee.address(), 5).await?;
    close_after_settle
        .settle_unrecorded(&mut payee, &payer.signer, 250_000)
        .await?;
    close_after_settle
        .close(
            &mut gas,
            "close_existing_channel_after_settlement",
            &mut payee,
            &payer.signer,
            650_000,
        )
        .await?;

    let request_close_channel =
        ChannelEnv::open(legacy_contract, &mut payer, payee.address(), 6).await?;
    request_close_channel
        .request_close(&mut gas, "request_close_existing_channel", &mut payer)
        .await?;

    request_close_channel
        .top_up(
            &mut gas,
            "top_up_existing_channel_cancel_close_request",
            &mut payer,
            100_000,
        )
        .await?;

    print_gas_snapshot("Legacy TempoStreamChannel gas snapshot", &gas);

    insta::assert_yaml_snapshot!(gas);

    Ok(())
}

async fn deploy_legacy_stream_channel<P: Provider + Clone>(
    sender: &mut TempoTxSender<P>,
) -> eyre::Result<Address> {
    let init_code = compile_legacy_stream_channel()?;
    let createx = CreateX::new(CREATEX_ADDRESS, &sender.provider);

    let deployed_address = createx
        .deployCreate(init_code.clone())
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(GAS_LIMIT)
        .call()
        .await?
        .0;

    let receipt = createx
        .deployCreate(init_code)
        .nonce(sender.nonce)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "legacy stream channel deploy failed");
    sender.nonce += 1;

    Ok(deployed_address.into())
}

fn compile_legacy_stream_channel() -> eyre::Result<Bytes> {
    let root = std::env::temp_dir().join(format!(
        "tempo-legacy-stream-channel-{}",
        std::process::id()
    ));
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir_all(root.join("src"))?;
    fs::create_dir_all(root.join("tempo-std/src/interfaces"))?;

    write_file(
        root.join("src/LegacyTempoStreamChannel.sol"),
        LEGACY_STREAM_CHANNEL_SOURCE,
    )?;
    write_file(
        root.join("tempo-std/src/interfaces/ITIP20.sol"),
        ITIP20_SOURCE,
    )?;
    write_file(
        root.join("tempo-std/src/interfaces/ITempoStreamChannel.sol"),
        I_TEMPO_STREAM_CHANNEL_SOURCE,
    )?;
    write_file(
        root.join("foundry.toml"),
        &format!(
            r#"[profile.default]
src = "{}/src"
out = "{}/out"
remappings = ["tempo-std/={}/tempo-std/src/"]
via_ir = true
optimizer = true
evm_version = "cancun"
bytecode_hash = "none"
"#,
            root.display(),
            root.display(),
            root.display()
        ),
    )?;

    let output = Command::new("forge")
        .arg("build")
        .arg("--config-path")
        .arg(root.join("foundry.toml"))
        .arg(root.join("src/LegacyTempoStreamChannel.sol"))
        .output()?;
    eyre::ensure!(
        output.status.success(),
        "forge build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let artifact = fs::read_to_string(
        root.join("out/LegacyTempoStreamChannel.sol/LegacyTempoStreamChannel.json"),
    )?;
    let artifact: serde_json::Value = serde_json::from_str(&artifact)?;
    let bytecode = artifact["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| eyre::eyre!("legacy stream channel artifact missing bytecode"))?;
    Ok(Bytes::from(hex::decode(bytecode.trim_start_matches("0x"))?))
}

fn write_file(path: impl AsRef<Path>, contents: &str) -> eyre::Result<()> {
    Ok(fs::write(path, contents)?)
}
