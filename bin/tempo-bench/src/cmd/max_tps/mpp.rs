use super::*;
use alloy::{
    primitives::{address, keccak256},
    sol,
    sol_types::{SolCall, SolValue},
};
use tempo_alloy::{primitives::transaction::Call, rpc::TempoTransactionRequest};

/// Mainnet (presto) MPP contract address.
pub(super) const MAINNET_MPP_CONTRACT_ADDRESS: Address =
    address!("0x33b901018174ddabe4841042ab76ba85d4e24f25");
/// Testnet (moderato) MPP contract address.
pub(super) const TESTNET_MPP_CONTRACT_ADDRESS: Address =
    address!("0xe1c4d3dce17bc111181ddf716f75bae49e61a336");

/// Resolves the MPP contract address from the chain ID.
pub(super) fn resolve_contract_address(chain_id: u64) -> eyre::Result<Address> {
    match chain_id {
        // Presto (mainnet)
        4217 => Ok(MAINNET_MPP_CONTRACT_ADDRESS),
        // Moderato (testnet)
        42431 => Ok(TESTNET_MPP_CONTRACT_ADDRESS),
        other => eyre::bail!(
            "unknown chain ID {other} for MPP contract address, use --mpp-contract-address to specify it explicitly"
        ),
    }
}

sol! {
    #[sol(rpc)]
    #[allow(clippy::too_many_arguments)]
    interface ITempoStreamChannel {
        function open(
            address payee,
            address token,
            uint128 deposit,
            bytes32 salt,
            address authorizedSigner
        ) external returns (bytes32 channelId);

        function close(
            bytes32 channelId,
            uint128 cumulativeAmount,
            bytes calldata signature
        ) external;
    }
}

/// Precompute the channel ID using the same formula as the contract.
///
/// `channelId = keccak256(abi.encode(payer, payee, token, salt, authorizedSigner, channel, chainId))`
pub(super) fn compute_channel_id(
    payer: Address,
    payee: Address,
    token: Address,
    salt: B256,
    authorized_signer: Address,
    channel_address: Address,
    chain_id: u64,
) -> B256 {
    keccak256(
        (
            payer,
            payee,
            token,
            salt,
            authorized_signer,
            channel_address,
            U256::from(chain_id),
        )
            .abi_encode(),
    )
}

/// Build a `TempoTransactionRequest` with two calls: channel open + close.
///
/// The signer is both payer and payee, so `close` succeeds immediately.
pub(super) fn build_open_and_close(
    channel_address: Address,
    payer: Address,
    token: Address,
    salt: B256,
    channel_id: B256,
) -> TempoTransactionRequest {
    let open_call = Call {
        to: channel_address.into(),
        input: ITempoStreamChannel::openCall {
            payee: payer,
            token,
            deposit: 1,
            salt,
            authorizedSigner: Address::ZERO,
        }
        .abi_encode()
        .into(),
        value: U256::ZERO,
    };

    let close_call = Call {
        to: channel_address.into(),
        input: ITempoStreamChannel::closeCall {
            channelId: channel_id,
            cumulativeAmount: 0,
            signature: Default::default(),
        }
        .abi_encode()
        .into(),
        value: U256::ZERO,
    };

    TempoTransactionRequest {
        calls: vec![open_call, close_call],
        ..Default::default()
    }
}

/// Approves the channel contract to spend tokens for signers that need it.
pub(super) async fn setup(
    signer_providers: &[(Secp256k1Signer, DynProvider<TempoNetwork>)],
    channel_address: Address,
    fee_token: Address,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<()> {
    info!(%channel_address, "Checking MPP channel token approvals");

    // Check allowances and collect approval futures for signers that need it
    let approvals: Vec<_> = stream::iter(signer_providers.iter())
        .filter_map(|(signer, provider)| {
            let provider = provider.clone();
            let owner = signer.address();
            async move {
                let token = ITIP20Instance::new(fee_token, provider);
                let allowance = token.allowance(owner, channel_address).call().await.ok()?;
                if allowance == U256::ZERO {
                    Some(Box::pin(
                        async move { token.approve(channel_address, U256::MAX).send().await },
                    ) as BoxFuture<'static, _>)
                } else {
                    None
                }
            }
        })
        .collect::<Vec<_>>()
        .await;

    if approvals.is_empty() {
        info!("All signers already have approvals");
        return Ok(());
    }

    info!(count = approvals.len(), "Approving signers");

    join_all(
        approvals.into_iter().progress(),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await
    .context("Failed to approve MPP channel contract")?;

    Ok(())
}
