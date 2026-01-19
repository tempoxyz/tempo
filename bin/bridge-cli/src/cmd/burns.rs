use clap::Parser;
use eyre::Result;
use std::path::PathBuf;
use tempo_bridge_exex::StateManager;

#[derive(Parser, Debug)]
pub struct BurnsArgs {
    /// Path to bridge state file
    #[arg(short, long, default_value = "bridge-state.json")]
    state: PathBuf,

    /// Show only burns without unlock tx
    #[arg(long)]
    pending: bool,

    /// Output format (table, json)
    #[arg(short, long, default_value = "table")]
    format: String,
}

impl BurnsArgs {
    pub async fn run(self) -> Result<()> {
        if !self.state.exists() {
            println!("No state file found at {:?}", self.state);
            return Ok(());
        }

        let state_manager = StateManager::new_persistent(&self.state)?;
        let stats = state_manager.get_stats().await;

        if self.format == "json" {
            let data = serde_json::json!({
                "processed_burns": stats.processed_burns,
            });
            println!("{}", serde_json::to_string_pretty(&data)?);
            return Ok(());
        }

        println!("Processed Burns");
        println!("===============");
        println!();
        println!("Total processed burns: {}", stats.processed_burns);
        println!();

        if self.pending {
            println!("Note: Use --pending to filter burns awaiting unlock on origin chain.");
        }

        Ok(())
    }
}
