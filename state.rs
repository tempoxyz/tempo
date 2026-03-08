use eyre::{eyre, Result}; // Add this import if not present

// ... other imports and code ...

impl Storage {
    // Refactored init function with safe handling
    pub async fn init<P: AsRef<Path>>(path: P, round: u64) -> Result<Self> {
        let mut states = Journal::new(path.as_ref().join("states"))?;
        
        // Safe check instead of expect
        if states.size().await? == 0 {
            states.append(round.to_le_bytes().to_vec()).await?;
            states.sync().await?;
        }
        
        // Safer state recovery (replace expect with ? and error wrapping)
        let current = states
            .read(states.size().await? - 1)
            .await?
            .ok_or_else(|| eyre!("No state found in journal after initialization"))?;
        
        let current = u64::from_le_bytes(
            current
                .try_into()
                .map_err(|_| eyre!("Invalid state byte length"))?,
        );
        
        Ok(Self { states })
    }

    // Refactored prune function
    pub async fn prune(&mut self, round: u64) -> Result<()> {
        let size = self.states.size().await?;
        
        // Safe calculation instead of expect
        let segments_to_prune = size
            .checked_sub(round as usize + 1)
            .ok_or_else(|| eyre!("Prune calculation underflow: size {} < round {} + 1", size, round))?;
        
        self.states.prune(segments_to_prune).await?;
        Ok(())
    }
}

// Refactored Round::from_state (change return to Result<Self>)
impl Round {
    pub fn from_state(storage: &mut Storage) -> Result<Self> {
        // Load current state safely
        let current = storage.states
            .read(storage.states.size().await? - 1)
            .await?
            .ok_or_else(|| eyre!("Failed to read current state from journal"))?;
        
        let current_round = u64::from_le_bytes(
            current
                .try_into()
                .map_err(|_| eyre!("Invalid round byte length in state"))?,
        );
        
        // ... rest of the initialization ...
        
        Ok(Self { /* fields */ })
    }
}
