use alloy::{
    primitives::B256,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use eyre::WrapErr as _;
use std::path::PathBuf;
use tempo_contracts::precompiles::IValidatorConfigV2;
use tempo_precompiles::VALIDATOR_CONFIG_V2_ADDRESS;

/// Migrate a validator from V1 to V2 using the `ValidatorConfigV2.migrateValidator` contract call.
///
/// This calls `migrateValidator(uint64 idx)` on the `ValidatorConfigV2` precompile,
/// which copies validator state from V1 at the given index. Must be called by the
/// contract owner.
#[derive(Debug, clap::Args)]
pub(crate) struct MigrateValidator {
    /// The V1 validator index to migrate.
    #[arg(long, value_name = "INDEX")]
    idx: u64,

    /// Path to the file holding the Ethereum private key (raw 32 bytes).
    #[arg(long, value_name = "FILE")]
    private_key: PathBuf,

    /// The RPC URL to submit the transaction to.
    #[arg(long, value_name = "RPC_URL")]
    rpc_url: String,
}

impl MigrateValidator {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let private_key_bytes =
            std::fs::read(&self.private_key).wrap_err("failed reading private key")?;
        let private_key =
            B256::try_from(private_key_bytes.as_slice()).wrap_err("invalid private key")?;

        let signer =
            PrivateKeySigner::from_bytes(&private_key).wrap_err("invalid signer key")?;

        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let calldata = IValidatorConfigV2::migrateValidatorCall { idx: self.idx };

        let tx = TransactionRequest::default()
            .to(VALIDATOR_CONFIG_V2_ADDRESS)
            .input(calldata.abi_encode().into());

        let pending = provider
            .send_transaction(tx)
            .await
            .wrap_err("failed to send migrateValidator transaction")?;

        let tx_hash = pending.tx_hash();
        println!("migrateValidator(idx={}) submitted: {tx_hash}", self.idx);

        Ok(())
    }
}
