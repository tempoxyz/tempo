//! xtask is a Swiss army knife of tools that help with running and testing tempo.
use crate::{
    admin::Admin,
    benchmark_results::BenchmarkResults,
    check_abi::CheckAbi,
    configure_benchmark_fees::ConfigureBenchmarkFees,
    create_zone::CreateZone,
    demo_blacklist::DemoBlacklist,
    demo_swap_and_deposit::DemoSwapAndDeposit,
    deploy_neobank_fixtures::DeployNeobankFixtures,
    deploy_router::DeployRouter,
    deposit::Deposit,
    forced_withdraw::ForcedWithdraw,
    generate_p2p_key::GenerateP2pKey,
    generate_zone_genesis::GenerateZoneGenesis,
    install_reference_zone_factory::InstallReferenceZoneFactory,
    portal_access::{EnableToken, SetAccessMode, SetAllowedAccount, SetGateway, SetGatewayMode},
    portal_pause::PausePortal,
    set_encryption_key::SetEncryptionKey,
    spam_deposits::SpamDeposits,
    verify_closed_loop::VerifyClosedLoop,
    verify_portal_backing::VerifyPortalBacking,
    zone_info::ZoneInfoCmd,
};
use clap::Parser as _;
use eyre::Context;

mod admin;
mod benchmark_results;
mod check_abi;
mod configure_benchmark_fees;
mod create_zone;
mod demo_blacklist;
mod demo_swap_and_deposit;
mod deploy_neobank_fixtures;
mod deploy_router;
mod deposit;
mod forced_withdraw;
mod generate_p2p_key;
mod generate_zone_genesis;
mod genesis_forks;
mod install_reference_zone_factory;
mod portal_access;
mod portal_pause;
mod safe;
mod set_encryption_key;
mod spam_deposits;
mod verify_closed_loop;
mod verify_portal_backing;
mod zone_info;
mod zone_utils;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    let args = Args::parse();
    match args.action {
        Action::Admin(args) => args.run().await.wrap_err("admin command failed"),
        Action::BenchmarkResults(args) => args.run().wrap_err("failed to render benchmark results"),
        Action::CheckAbi(args) => args.run().wrap_err("failed ABI alignment check"),
        Action::ConfigureBenchmarkFees(args) => args
            .run()
            .await
            .wrap_err("failed to configure benchmark fees"),
        Action::CreateZone(args) => args.run().await.wrap_err("failed to create zone"),
        Action::DemoBlacklist(args) => args.run().await.wrap_err("failed to run blacklist demo"),
        Action::DemoSwapAndDeposit(args) => args
            .run()
            .await
            .wrap_err("failed to run swap-and-deposit demo"),
        Action::DeployNeobankFixtures(args) => args
            .run()
            .await
            .wrap_err("failed to deploy private-Zone benchmark fixtures"),
        Action::DeployRouter(args) => args.run().await.wrap_err("failed to deploy router"),
        Action::Deposit(args) => args.run().await.wrap_err("failed to send deposit"),
        Action::EnableToken(args) => args.run().await.wrap_err("failed to enable token"),
        Action::ForcedWithdraw(args) => args.run().await.wrap_err("forced withdrawal failed"),
        Action::GenerateZoneGenesis(args) => {
            args.run().await.wrap_err("failed to generate zone genesis")
        }
        Action::GenerateP2pKey(args) => args.run().wrap_err("failed to generate P2P key"),
        Action::InstallReferenceZoneFactory(args) => args
            .run()
            .wrap_err("failed to install reference ZoneFactory"),
        Action::PausePortal(args) => args.run().await.wrap_err("failed to pause portal"),
        Action::SetAccessMode(args) => args.run().await.wrap_err("failed to set access mode"),
        Action::SetAllowedAccount(args) => {
            args.run().await.wrap_err("failed to update account role")
        }
        Action::SetGateway(args) => args.run().await.wrap_err("failed to update gateway role"),
        Action::SetGatewayMode(args) => args.run().await.wrap_err("failed to set gateway mode"),
        Action::SetEncryptionKey(args) => args.run().await.wrap_err("failed to set encryption key"),
        Action::SpamDeposits(args) => args.run().await.wrap_err("failed to spam deposits"),
        Action::VerifyClosedLoop(args) => {
            args.run().await.wrap_err("closed-loop verification failed")
        }
        Action::VerifyPortalBacking(args) => args
            .run()
            .await
            .wrap_err("Portal backing verification failed"),
        Action::ZoneInfo(args) => args.run().await.wrap_err("failed to fetch zone info"),
    }
}

#[derive(Debug, clap::Parser)]
#[command(author)]
#[command(version)]
#[command(about)]
#[command(long_about = None)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
    Admin(Admin),
    BenchmarkResults(BenchmarkResults),
    CheckAbi(CheckAbi),
    ConfigureBenchmarkFees(ConfigureBenchmarkFees),
    CreateZone(CreateZone),
    DemoBlacklist(DemoBlacklist),
    DemoSwapAndDeposit(DemoSwapAndDeposit),
    DeployNeobankFixtures(DeployNeobankFixtures),
    DeployRouter(DeployRouter),
    Deposit(Deposit),
    EnableToken(EnableToken),
    ForcedWithdraw(ForcedWithdraw),
    GenerateP2pKey(GenerateP2pKey),
    GenerateZoneGenesis(GenerateZoneGenesis),
    InstallReferenceZoneFactory(InstallReferenceZoneFactory),
    PausePortal(PausePortal),
    SetAccessMode(SetAccessMode),
    SetAllowedAccount(SetAllowedAccount),
    SetGateway(SetGateway),
    SetGatewayMode(SetGatewayMode),
    SetEncryptionKey(SetEncryptionKey),
    SpamDeposits(SpamDeposits),
    VerifyClosedLoop(VerifyClosedLoop),
    VerifyPortalBacking(VerifyPortalBacking),
    ZoneInfo(ZoneInfoCmd),
}
