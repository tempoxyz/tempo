use super::*;
use alloy::sol;

sol! {
    #[sol(rpc)]
    StorageBloat,
    "artifacts/StorageBloat.json"
}

/// Setup storage bloat contract for benchmarking state bloat:
/// - Deploy a single StorageBloat contract
pub(super) async fn setup(
    signer_providers: &[(Secp256k1Signer, DynProvider<TempoNetwork>)],
) -> eyre::Result<Address> {
    let (_signer, provider) = signer_providers
        .first()
        .ok_or_eyre("No signer providers found")?;

    info!("Deploying StorageBloat contract");

    let contract = StorageBloat::deploy(provider.clone()).await?;
    let address = *contract.address();

    info!(%address, "Deployed StorageBloat contract");

    Ok(address)
}
