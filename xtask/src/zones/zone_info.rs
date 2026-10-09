use alloy::{primitives::Address, providers::ProviderBuilder};
use eyre::eyre;
use tempo_alloy::TempoNetwork;
use tempo_contracts::zones::{ZONE_MESSENGER_ADDRESS, ZoneFactory};

use crate::{
    admin::{PortalSnapshot, read_portal_snapshot},
    zone_utils::MODERATO_ZONE_FACTORY,
};

#[derive(Debug, clap::Parser)]
pub(crate) struct ZoneInfoCmd {
    /// Zone ID (integer) or portal address (0x...) to look up.
    identifier: String,

    /// Tempo L1 HTTP RPC URL.
    #[arg(long, default_value = "https://rpc.moderato.tempo.xyz")]
    l1_rpc_url: String,

    /// ZoneFactory contract address on Tempo L1.
    #[arg(long, env = "ZONE_FACTORY", default_value_t = MODERATO_ZONE_FACTORY)]
    zone_factory: Address,
}

impl ZoneInfoCmd {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.l1_rpc_url)
            .await?;

        let factory = ZoneFactory::new(self.zone_factory, &provider);

        let zone_id = if self.identifier.starts_with("0x") {
            // Look up by portal address — scan all zones
            let portal: Address = self.identifier.parse()?;
            let next_zone_id = factory.nextZoneId().call().await?;

            let mut found = None;
            for id in 1..next_zone_id {
                let info = factory.zones(id).call().await?;
                if info.portal == portal {
                    found = Some(id);
                    break;
                }
            }
            found.ok_or_else(|| eyre!("no zone found with portal address {portal}"))?
        } else {
            self.identifier
                .parse::<u32>()
                .map_err(|_| eyre!("expected a zone ID (integer) or portal address (0x...)"))?
        };

        let info = factory.zones(zone_id).call().await?;
        if info.portal.is_zero() {
            return Err(eyre!("zone {zone_id} does not exist"));
        }
        println!("Zone {}", info.zoneId);
        println!("  Portal:                {}", info.portal);
        println!("  Messenger:             {ZONE_MESSENGER_ADDRESS}");
        println!("  Admin:                 {}", info.admin);
        println!("  Sequencers:            {:?}", info.sequencers);
        println!("  Threshold:             {}", info.threshold);
        println!("  Verifier:              {}", info.verifier);
        println!("  RPC URL:               {}", info.rpcUrl);

        // Reuse the same pinned finalized snapshot as `admin check` so related reads cannot mix
        // state from different blocks.
        let snapshot: PortalSnapshot =
            read_portal_snapshot(&provider, self.zone_factory, zone_id, Some(info.portal)).await?;

        println!("\nPortal State");
        println!(
            "  Finalized L1 Block:    {}",
            snapshot.finalized_block_number
        );
        println!("  Active Sequencers:     {:?}", snapshot.sequencers);
        println!(
            "  Sequencer Set Version: {}",
            snapshot.sequencer_set_version
        );
        if snapshot.leader.is_zero() {
            println!("  Leader:                (uninitialized)");
        } else {
            println!("  Leader:                {}", snapshot.leader);
            println!("  Leader Epoch:          {}", snapshot.leader_epoch);
            println!(
                "  Leader Activation:     Tempo block {}",
                snapshot.leader_activation_tempo_block
            );
        }
        println!("  Zone Gas Rate:         {}", snapshot.zone_gas_rate);
        println!("  Paused:                {}", snapshot.paused);
        println!("  Pause expiry:          {}", snapshot.pause_expiry);
        println!(
            "  Pause abdication at:   {}",
            snapshot.pause_abdication_effective_at
        );
        println!(
            "  Access abdication at:  {}",
            snapshot.access_abdication_effective_at
        );
        println!(
            "  Withdrawal Batch:      {}",
            snapshot.withdrawal_batch_index
        );
        println!("  Block Hash:            {}", snapshot.block_hash);
        println!(
            "  Deposit Queue Hash:    {}",
            snapshot.current_deposit_queue_hash
        );
        println!(
            "  Last Synced Block:     {}",
            snapshot.last_synced_tempo_block
        );

        // Encryption key
        match snapshot.encryption_key {
            Some(key) => {
                println!("\nEncryption Key");
                println!("  X:                     {}", key.x);
                println!("  Y Parity:              0x{:02x}", key.y_parity);
            }
            None => println!("\nEncryption Key:          (not set)"),
        }

        // Enabled tokens
        println!("\nEnabled Tokens ({})", snapshot.enabled_tokens.len());
        for (i, token) in snapshot.enabled_tokens.iter().enumerate() {
            println!("  [{i}] {token}");
        }

        Ok(())
    }
}
