# Tempo Alloy

Tempo types for [Alloy](https://alloy.rs).

## Getting Started

To use `tempo-alloy`, add the crate as a dependency in your `Cargo.toml` file:

```toml
[dependencies]
tempo-alloy = { git = "https://github.com/tempoxyz/tempo" }
```

## Development Status

`tempo-alloy` is currently in development and is not yet ready for production use.

## Usage

To get started, instantiate a provider with [`TempoNetwork`]:

```rust
use alloy::{
    providers::{Provider, ProviderBuilder},
    transports::TransportError
};
use tempo_alloy::TempoNetwork;

async fn build_provider() -> Result<impl Provider<TempoNetwork>, TransportError> {
    ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect("https://rpc.testnet.tempo.xyz")
        .await
}
```

This crate also exposes bindings for all Tempo precompiles, such as [TIP20](https://docs.tempo.xyz/protocol/tip20/overview):

```rust
use alloy::{
    primitives::{U256, address},
    providers::ProviderBuilder,
};
use tempo_alloy::{TempoNetwork, contracts::precompiles::ITIP20};
 
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;
 
    let token = ITIP20::new( 
        address!("0x20c0000000000000000000000000000000000001"), // AlphaUSD 
        provider, 
    ); 
 
    let receipt = token 
        .transfer( 
            address!("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbb"), 
            U256::from(100).pow(U256::from(10e6)), // 100 tokens (6 decimals) 
        ) 
        .send() 
        .await?
        .get_receipt() 
        .await?; 
 
    Ok(())
}
```

See the [examples directory](https://github.com/tempoxyz/tempo/tree/main/crates/alloy/examples) for additional runnable code samples.