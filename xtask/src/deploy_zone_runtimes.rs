//! Deploy the shared Zone runtimes manually, without the native ZoneFactory.
//!
//! The T10 hardfork normally etches the ZonePortal implementation, the verifier, and the shared
//! messenger at fixed protocol-managed addresses ([`ZONE_PORTAL_IMPL_ADDRESS`],
//! [`ZONE_VERIFIER_ADDRESS`], [`ZONE_MESSENGER_ADDRESS`]). Those are vanity addresses reachable
//! only by protocol-level state injection, so an EOA cannot reproduce them.
//!
//! This command deploys ordinary copies of the same runtime bytecode at CREATE-derived addresses
//! using nothing but a private key and an RPC URL. That works on any network, whether or not T10
//! is active, and is useful for exercising or inspecting the contracts standalone: reading the
//! verifier, poking the messenger, or confirming the runtimes deploy and match the expected bytes.
//!
//! ## What this cannot do
//!
//! It cannot stand up a working *zone*, and no real portal can reference these copies. Every
//! address a zone resolves is fixed to a canonical one:
//!
//! * a portal proxy hardcodes [`ZONE_PORTAL_IMPL_ADDRESS`] in its 45-byte runtime
//!   (`ZONE_PORTAL_PROXY_RUNTIME`), so it always delegates to the canonical implementation;
//! * the factory writes [`ZONE_MESSENGER_ADDRESS`] and [`ZONE_VERIFIER_ADDRESS`] into portal
//!   storage from constants, and `CreateZoneParams` has no fields for them, so a zone creator
//!   cannot point a portal at a different messenger or verifier;
//! * the implementation gates its one-time `initialize` on the caller being the factory, reverting
//!   `NotFactory()` for an EOA, so a hand-rolled proxy cannot be initialized either.
//!
//! Getting these runtimes to their canonical addresses therefore requires either the genesis
//! allocation (`cargo xtask generate-genesis` etches them when T10 is active at genesis) or the T10
//! boundary install on a live chain. There is no EOA-only path, and no `anvil_setCode`-style escape
//! hatch on a Tempo node.

use alloy::{
    network::{EthereumWallet, TransactionBuilder as _},
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use eyre::{Context as _, ensure, eyre};
use tempo_contracts::{
    precompiles::{
        ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS,
        ZONE_VERIFIER_ADDRESS,
    },
    zones::{ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME},
};

/// Deploy the ZonePortal implementation, verifier, and messenger runtimes without the factory.
#[derive(Debug, clap::Args)]
pub(crate) struct DeployZoneRuntimes {
    /// RPC endpoint to deploy against.
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,

    /// Deployer private key, hex encoded. Pays for gas.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: PrivateKeySigner,

    /// Print the deployment plan and exit without sending transactions.
    #[arg(long)]
    dry_run: bool,
}

/// Length of the [`runtime_initcode`] prefix, and therefore the offset of the runtime within it.
const INITCODE_PREFIX_LEN: u8 = 10;

/// Maximum deployed contract size (EIP-170).
const MAX_CODE_SIZE: usize = 24_576;

impl DeployZoneRuntimes {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        // Ordered so the verifier and messenger, which a portal has to reference, come first.
        let targets = [
            (
                "ZoneVerifier",
                &ZONE_VERIFIER_RUNTIME,
                ZONE_VERIFIER_ADDRESS,
            ),
            (
                "ZoneMessenger",
                &ZONE_MESSENGER_RUNTIME,
                ZONE_MESSENGER_ADDRESS,
            ),
            (
                "ZonePortal implementation",
                &ZONE_PORTAL_RUNTIME,
                ZONE_PORTAL_IMPL_ADDRESS,
            ),
        ];

        for (label, runtime, _) in &targets {
            ensure!(
                runtime.len() <= MAX_CODE_SIZE,
                "{label} runtime is {} bytes, over the {MAX_CODE_SIZE}-byte contract size limit",
                runtime.len()
            );
        }

        if self.dry_run {
            println!("Would deploy (canonical protocol address in parentheses):");
            for (label, runtime, canonical) in &targets {
                println!("  {label} — {} bytes  ({canonical})", runtime.len());
            }
            return Ok(());
        }

        let deployer = self.private_key.address();
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(self.private_key))
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let chain_id = provider
            .get_chain_id()
            .await
            .wrap_err("failed to read chain id")?;
        println!(
            "Deployer {deployer} on chain {chain_id} via {}",
            self.rpc_url
        );

        let mut deployed = Vec::with_capacity(targets.len());
        for (label, runtime, canonical) in &targets {
            let address = deploy_runtime(&provider, label, runtime).await?;
            deployed.push((*label, address, *canonical));
        }

        println!("\nDeployed (canonical protocol address in parentheses):");
        for (label, address, canonical) in &deployed {
            println!("  {label:<25} {address}  ({canonical})");
        }
        println!(
            "\nThese are CREATE-derived addresses, not the canonical ones the T10 boundary etches,\n\
             and no real portal can reference them: proxies hardcode the canonical implementation,\n\
             and the factory at {ZONE_FACTORY_ADDRESS} fixes each portal's messenger and verifier to\n\
             the canonical addresses. Use genesis or the T10 boundary for a usable zone."
        );

        Ok(())
    }
}

/// Deploys `runtime` verbatim and returns the address it landed at.
async fn deploy_runtime(
    provider: &impl Provider,
    label: &str,
    runtime: &[u8],
) -> eyre::Result<Address> {
    let receipt = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(runtime_initcode(runtime)))
        .await
        .wrap_err_with(|| format!("failed to submit {label} deployment"))?
        .get_receipt()
        .await
        .wrap_err_with(|| format!("failed to confirm {label} deployment"))?;

    ensure!(
        receipt.status(),
        "{label} deployment reverted in {:?}",
        receipt.transaction_hash
    );
    let deployed = receipt
        .contract_address
        .ok_or_else(|| eyre!("{label} receipt carried no contract address"))?;

    // The initcode returns the runtime verbatim, so a mismatch means the chain rejected or
    // truncated the code rather than that the transaction merely failed.
    let onchain = provider
        .get_code_at(deployed)
        .await
        .wrap_err_with(|| format!("failed to read back {label} code"))?;
    ensure!(
        onchain.as_ref() == runtime,
        "{label} code at {deployed} does not match the expected runtime ({} vs {} bytes)",
        onchain.len(),
        runtime.len()
    );

    println!("  deployed {label} at {deployed} ({} bytes)", runtime.len());
    Ok(deployed)
}

/// Wraps deployed runtime bytecode in minimal initcode that returns it verbatim.
///
/// `PUSH2 len; DUP1; PUSH1 10; PUSH0; CODECOPY; PUSH0; RETURN` — copies the trailing runtime out
/// of the initcode and returns it as the deployed code.
fn runtime_initcode(runtime: &[u8]) -> Bytes {
    let len = u16::try_from(runtime.len()).expect("zone runtimes are far below 64 KiB");

    let mut initcode = Vec::with_capacity(runtime.len() + usize::from(INITCODE_PREFIX_LEN));
    initcode.push(0x61); // PUSH2 len
    initcode.extend_from_slice(&len.to_be_bytes());
    initcode.push(0x80); // DUP1
    initcode.push(0x60); // PUSH1 <runtime offset>
    initcode.push(INITCODE_PREFIX_LEN);
    initcode.push(0x5f); // PUSH0 (memory destination)
    initcode.push(0x39); // CODECOPY
    initcode.push(0x5f); // PUSH0 (return offset)
    initcode.push(0xf3); // RETURN
    debug_assert_eq!(initcode.len(), usize::from(INITCODE_PREFIX_LEN));

    initcode.extend_from_slice(runtime);
    initcode.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initcode_returns_runtime_verbatim() {
        let runtime = [0xefu8; 300];
        let initcode = runtime_initcode(&runtime);

        assert_eq!(
            &initcode[..usize::from(INITCODE_PREFIX_LEN)],
            &[0x61, 0x01, 0x2c, 0x80, 0x60, 0x0a, 0x5f, 0x39, 0x5f, 0xf3]
        );
        assert_eq!(&initcode[usize::from(INITCODE_PREFIX_LEN)..], &runtime);
    }

    #[test]
    fn zone_runtimes_fit_the_contract_size_limit() {
        for (label, runtime) in [
            ("verifier", &ZONE_VERIFIER_RUNTIME),
            ("messenger", &ZONE_MESSENGER_RUNTIME),
            ("portal", &ZONE_PORTAL_RUNTIME),
        ] {
            assert!(
                runtime.len() <= MAX_CODE_SIZE,
                "{label} runtime is {} bytes, over the EIP-170 limit",
                runtime.len()
            );
        }
    }
}
