//! Updates ZonePortal access policy and enabled tokens.

use alloy::{
    network::ReceiptResponse as _,
    primitives::{Address, address},
    providers::{DynProvider, Provider as _, ProviderBuilder},
    sol_types::SolCall as _,
};
use eyre::{WrapErr as _, ensure};
use std::path::PathBuf;
use tempo_alloy::{TempoNetwork, provider::ext::TempoProviderExt, rpc::TempoCallBuilderExt};
use tempo_contracts::zones::{ZonePortal, ZonePortal::Role};
use zone_sequencer::nonce_keys::ADMIN_OPS_NONCE_KEY;

use crate::{
    safe::{SafeProposal, verify_safe, write_safe_proposal},
    zone_utils::parse_private_key,
};

#[derive(Debug, clap::Args)]
struct PortalAccessArgs {
    /// Tempo L1 RPC URL.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// ZonePortal contract address on Tempo L1.
    #[arg(long, env = "L1_PORTAL_ADDRESS")]
    portal: Address,

    /// ZonePortal admin private key. Required unless --safe-address is used.
    #[arg(
        long,
        env = "ADMIN_KEY",
        hide_env_values = true,
        required_unless_present = "safe_address",
        conflicts_with = "safe_address"
    )]
    admin_key: Option<String>,

    /// Safe contract that is the ZonePortal admin. Emits an unsigned proposal instead of sending.
    #[arg(long, value_name = "ADDRESS", requires = "safe_output")]
    safe_address: Option<Address>,

    /// New Safe Transaction Builder JSON file to create.
    #[arg(long, value_name = "PATH", requires = "safe_address")]
    safe_output: Option<PathBuf>,
}

#[derive(Debug, clap::Parser)]
pub(crate) struct EnableToken {
    #[command(flatten)]
    args: PortalAccessArgs,

    /// TIP-20 token address or well-known alias (pathusd, alphausd, betausd).
    #[arg(value_parser = parse_token)]
    token: Address,
}

#[derive(Debug, clap::Parser)]
pub(crate) struct SetAccessMode {
    #[command(flatten)]
    args: PortalAccessArgs,

    /// Require the Account role for deposits, refunds, and plain withdrawals.
    #[arg(long)]
    enforced: bool,
}

#[derive(Debug, clap::Parser)]
pub(crate) struct SetGatewayMode {
    #[command(flatten)]
    args: PortalAccessArgs,

    /// Require callback targets to have the CallbackGateway role.
    #[arg(long)]
    enforced: bool,
}

#[derive(Debug, clap::Parser)]
pub(crate) struct SetAllowedAccount {
    #[command(flatten)]
    args: PortalAccessArgs,

    /// Account whose closed-loop membership should be updated.
    account: Address,

    /// Add the Account role. Omit to remove it.
    #[arg(long)]
    allowed: bool,
}

#[derive(Debug, clap::Parser)]
pub(crate) struct SetGateway {
    #[command(flatten)]
    args: PortalAccessArgs,

    /// Callback gateway whose role should be updated.
    account: Address,

    /// Add the CallbackGateway role. Omit to remove it.
    #[arg(long)]
    allowed: bool,
}

impl EnableToken {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        if let Some(proposal) = self.args.safe_proposal() {
            let (portal, provider) = connect_safe(&self.args, proposal.safe).await?;
            portal
                .enableToken(self.token)
                .from(proposal.safe)
                .call()
                .await
                .wrap_err("ZonePortal.enableToken Safe simulation failed")?;
            let calldata = ZonePortal::enableTokenCall { token: self.token }.abi_encode();
            return write_safe_proposal(
                &provider,
                &proposal,
                "ZonePortal.enableToken",
                self.args.portal,
                calldata,
            )
            .await;
        }

        let token = self.token;
        let (portal, provider, nonce) = connect(self.args).await?;
        ensure!(
            !portal
                .isTokenEnabled(token)
                .call()
                .await
                .wrap_err("failed checking whether token is already enabled")?,
            "token {token} is already enabled"
        );
        let receipt = portal
            .enableToken(token)
            .nonce_key(ADMIN_OPS_NONCE_KEY)
            .nonce(nonce)
            .send()
            .await
            .wrap_err("failed sending ZonePortal.enableToken")?
            .get_receipt()
            .await
            .wrap_err("failed waiting for enableToken receipt")?;
        ensure!(receipt.status(), "enableToken transaction reverted");
        ensure!(
            portal.isTokenEnabled(token).call().await?,
            "portal did not enable token {token}"
        );
        println!("Enabled token {token}");
        println!("Transaction: {}", receipt.transaction_hash());
        drop(provider);
        Ok(())
    }
}

impl SetAccessMode {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        if let Some(proposal) = self.args.safe_proposal() {
            let (portal, provider) = connect_safe(&self.args, proposal.safe).await?;
            portal
                .setAccessMode(self.enforced)
                .from(proposal.safe)
                .call()
                .await
                .wrap_err("ZonePortal.setAccessMode Safe simulation failed")?;
            let calldata = ZonePortal::setAccessModeCall {
                enforced: self.enforced,
            }
            .abi_encode();
            return write_safe_proposal(
                &provider,
                &proposal,
                "ZonePortal.setAccessMode",
                self.args.portal,
                calldata,
            )
            .await;
        }

        let (portal, provider, nonce) = connect(self.args).await?;
        let receipt = portal
            .setAccessMode(self.enforced)
            .nonce_key(ADMIN_OPS_NONCE_KEY)
            .nonce(nonce)
            .send()
            .await
            .wrap_err("failed sending ZonePortal.setAccessMode")?
            .get_receipt()
            .await
            .wrap_err("failed waiting for setAccessMode receipt")?;
        ensure!(receipt.status(), "setAccessMode transaction reverted");
        ensure!(
            portal.isAccessEnforced().call().await? == self.enforced,
            "portal access mode did not update"
        );
        print_success("account access mode", &receipt.transaction_hash());
        drop(provider);
        Ok(())
    }
}

impl SetGatewayMode {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        if let Some(proposal) = self.args.safe_proposal() {
            let (portal, provider) = connect_safe(&self.args, proposal.safe).await?;
            portal
                .setGatewayMode(self.enforced)
                .from(proposal.safe)
                .call()
                .await
                .wrap_err("ZonePortal.setGatewayMode Safe simulation failed")?;
            let calldata = ZonePortal::setGatewayModeCall {
                enforced: self.enforced,
            }
            .abi_encode();
            return write_safe_proposal(
                &provider,
                &proposal,
                "ZonePortal.setGatewayMode",
                self.args.portal,
                calldata,
            )
            .await;
        }

        let (portal, provider, nonce) = connect(self.args).await?;
        let receipt = portal
            .setGatewayMode(self.enforced)
            .nonce_key(ADMIN_OPS_NONCE_KEY)
            .nonce(nonce)
            .send()
            .await
            .wrap_err("failed sending ZonePortal.setGatewayMode")?
            .get_receipt()
            .await
            .wrap_err("failed waiting for setGatewayMode receipt")?;
        ensure!(receipt.status(), "setGatewayMode transaction reverted");
        ensure!(
            portal.isGatewayOpen().call().await? != self.enforced,
            "portal gateway mode did not update"
        );
        print_success("callback gateway mode", &receipt.transaction_hash());
        drop(provider);
        Ok(())
    }
}

impl SetAllowedAccount {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        if let Some(proposal) = self.args.safe_proposal() {
            let (portal, provider) = connect_safe(&self.args, proposal.safe).await?;
            portal
                .setAllowedAccount(self.account, self.allowed)
                .from(proposal.safe)
                .call()
                .await
                .wrap_err("ZonePortal.setAllowedAccount Safe simulation failed")?;
            let calldata = ZonePortal::setAllowedAccountCall {
                account: self.account,
                allowed: self.allowed,
            }
            .abi_encode();
            return write_safe_proposal(
                &provider,
                &proposal,
                "ZonePortal.setAllowedAccount",
                self.args.portal,
                calldata,
            )
            .await;
        }

        let (portal, provider, nonce) = connect(self.args).await?;
        let receipt = portal
            .setAllowedAccount(self.account, self.allowed)
            .nonce_key(ADMIN_OPS_NONCE_KEY)
            .nonce(nonce)
            .send()
            .await
            .wrap_err("failed sending ZonePortal.setAllowedAccount")?
            .get_receipt()
            .await
            .wrap_err("failed waiting for setAllowedAccount receipt")?;
        ensure!(receipt.status(), "setAllowedAccount transaction reverted");
        ensure!(
            portal.hasRole(self.account, Role::Account).call().await? == self.allowed,
            "portal account role did not update"
        );
        print_success("allowed account", &receipt.transaction_hash());
        drop(provider);
        Ok(())
    }
}

impl SetGateway {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        if let Some(proposal) = self.args.safe_proposal() {
            let (portal, provider) = connect_safe(&self.args, proposal.safe).await?;
            portal
                .setGateway(self.account, self.allowed)
                .from(proposal.safe)
                .call()
                .await
                .wrap_err("ZonePortal.setGateway Safe simulation failed")?;
            let calldata = ZonePortal::setGatewayCall {
                account: self.account,
                allowed: self.allowed,
            }
            .abi_encode();
            return write_safe_proposal(
                &provider,
                &proposal,
                "ZonePortal.setGateway",
                self.args.portal,
                calldata,
            )
            .await;
        }

        let (portal, provider, nonce) = connect(self.args).await?;
        let receipt = portal
            .setGateway(self.account, self.allowed)
            .nonce_key(ADMIN_OPS_NONCE_KEY)
            .nonce(nonce)
            .send()
            .await
            .wrap_err("failed sending ZonePortal.setGateway")?
            .get_receipt()
            .await
            .wrap_err("failed waiting for setGateway receipt")?;
        ensure!(receipt.status(), "setGateway transaction reverted");
        ensure!(
            portal
                .hasRole(self.account, Role::CallbackGateway)
                .call()
                .await?
                == self.allowed,
            "portal gateway role did not update"
        );
        print_success("callback gateway", &receipt.transaction_hash());
        drop(provider);
        Ok(())
    }
}

impl PortalAccessArgs {
    fn safe_proposal(&self) -> Option<SafeProposal> {
        self.safe_address.map(|safe| SafeProposal {
            safe,
            output: self
                .safe_output
                .clone()
                .expect("clap requires --safe-output with --safe-address"),
        })
    }
}

fn parse_token(value: &str) -> Result<Address, String> {
    match value.to_ascii_lowercase().as_str() {
        "pathusd" | "path-usd" | "path_usd" => {
            Ok(address!("0x20c0000000000000000000000000000000000000"))
        }
        "alphausd" | "alpha-usd" | "alpha_usd" => {
            Ok(address!("0x20c0000000000000000000000000000000000001"))
        }
        "betausd" | "beta-usd" | "beta_usd" => {
            Ok(address!("0x20c0000000000000000000000000000000000002"))
        }
        _ => value
            .parse()
            .map_err(|error| format!("invalid token address or alias `{value}`: {error}")),
    }
}

async fn connect(
    args: PortalAccessArgs,
) -> eyre::Result<(
    tempo_contracts::zones::ZonePortal::ZonePortalInstance<DynProvider<TempoNetwork>, TempoNetwork>,
    DynProvider<TempoNetwork>,
    u64,
)> {
    let admin_key = args
        .admin_key
        .as_deref()
        .ok_or_else(|| eyre::eyre!("ADMIN_KEY is required for direct portal updates"))?;
    let signer = parse_private_key(admin_key).wrap_err("ADMIN_KEY is not valid")?;
    let signer_address = signer.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(signer)
        .connect(&args.l1_rpc_url)
        .await
        .wrap_err("failed connecting to Tempo L1 RPC")?
        .erased();
    let portal = ZonePortal::new(args.portal, provider.clone());
    let admin = portal
        .admin()
        .call()
        .await
        .wrap_err("failed reading portal admin")?;
    ensure!(
        signer_address == admin,
        "ADMIN_KEY signer {signer_address} is not portal admin {admin}"
    );
    let nonce = provider
        .get_transaction_count_with_nonce_key(signer_address, ADMIN_OPS_NONCE_KEY)
        .await
        .wrap_err("failed reading portal admin nonce")?;
    Ok((portal, provider, nonce))
}

async fn connect_safe(
    args: &PortalAccessArgs,
    safe: Address,
) -> eyre::Result<(
    tempo_contracts::zones::ZonePortal::ZonePortalInstance<DynProvider<TempoNetwork>, TempoNetwork>,
    DynProvider<TempoNetwork>,
)> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&args.l1_rpc_url)
        .await
        .wrap_err("failed connecting to Tempo L1 RPC")?
        .erased();
    let portal = ZonePortal::new(args.portal, provider.clone());
    let admin = portal
        .admin()
        .call()
        .await
        .wrap_err("failed reading portal admin")?;
    ensure!(safe == admin, "Safe {safe} is not portal admin {admin}");
    verify_safe(&provider, safe).await?;
    Ok((portal, provider))
}

fn print_success(operation: &str, tx_hash: &impl std::fmt::Display) {
    println!("Updated {operation}");
    println!("Transaction: {tx_hash}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_account_calldata_has_expected_selector() {
        let calldata = ZonePortal::setAllowedAccountCall {
            account: Address::repeat_byte(0x33),
            allowed: true,
        }
        .abi_encode();
        assert_eq!(&calldata[..4], &[0x90, 0xf5, 0x95, 0x98]);
    }

    #[test]
    fn gateway_calldata_has_expected_selector() {
        let calldata = ZonePortal::setGatewayCall {
            account: Address::repeat_byte(0x44),
            allowed: false,
        }
        .abi_encode();
        assert_eq!(&calldata[..4], &[0x10, 0xce, 0xa8, 0x57]);
    }

    #[test]
    fn token_aliases_resolve_case_insensitively() {
        assert_eq!(
            parse_token("pathUSD").unwrap(),
            address!("0x20c0000000000000000000000000000000000000")
        );
        assert_eq!(
            parse_token("ALPHA-USD").unwrap(),
            address!("0x20c0000000000000000000000000000000000001")
        );
        assert_eq!(
            parse_token("beta_usd").unwrap(),
            address!("0x20c0000000000000000000000000000000000002")
        );
    }

    #[test]
    fn enable_token_calldata_has_expected_selector() {
        let calldata = ZonePortal::enableTokenCall {
            token: Address::repeat_byte(0x55),
        }
        .abi_encode();
        assert_eq!(&calldata[..4], &[0xc6, 0x90, 0x90, 0x8a]);
    }
}
