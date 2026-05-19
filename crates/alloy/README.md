# Tempo Alloy

Tempo types for [Alloy](https://alloy.rs).

## Getting Started

To use `tempo-alloy`, add the crate as a dependency in your `Cargo.toml` file:

```toml
[dependencies]
tempo-alloy = { git = "https://github.com/tempoxyz/tempo" }
```

If you need the Reth RPC conversion/compatibility impls used by Tempo node-side code,
enable the `reth` feature explicitly:

```toml
[dependencies]
tempo-alloy = { git = "https://github.com/tempoxyz/tempo", features = ["reth"] }
```

## Development Status

`tempo-alloy` is under active development. It is intended for application developers building on Tempo.

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
        .connect("https://rpc.moderato.tempo.xyz")
        .await
}
```

This crate also exposes bindings for all Tempo precompiles, such as [TIP20](https://docs.tempo.xyz/protocol/tip20/overview):

```rust,no_run
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

## Provider Extensions

`tempo-alloy` also exposes Tempo-specific provider helpers for fixed-address precompiles:

```rust,no_run
use alloy::{
    primitives::address,
    providers::ProviderBuilder,
};
use tempo_alloy::{TempoNetwork, provider::ext::TempoProviderExt};

async fn keychain_example() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect("https://rpc.moderato.tempo.xyz")
        .await?;

    let account = address!("0x1111111111111111111111111111111111111111");
    let key_id = address!("0x2222222222222222222222222222222222222222");

    let key = provider.get_keychain_key(account, key_id).await?;
    let same_key = provider.account_keychain().getKey(account, key_id).call().await?;

    assert_eq!(key, same_key);
    Ok(())
}
```

### Sponsored transactions

Sponsored transactions are another provider extension. They route unsigned Tempo AA transaction
submissions to a sponsor relay, which applies policy, adds the fee-payer signature, broadcasts the
transaction, and returns the transaction hash. The recommended API is to build a normal Tempo
provider, add a sponsor relay endpoint, then connect to the default RPC:

```rust,no_run
use alloy::{network::EthereumWallet, providers::{ProviderBuilder, fillers::RecommendedFillers}};
use tempo_alloy::{
    TempoNetwork,
    fillers::Random2DNonceFiller,
    provider::ext::TempoProviderBuilderExt,
};

async fn sponsored_provider(
    rpc_url: &str,
    sponsor_url: &str,
    signer: alloy::signers::local::PrivateKeySigner,
) -> Result<impl alloy::providers::Provider<TempoNetwork>, alloy::transports::TransportError> {
    ProviderBuilder::<_, _, TempoNetwork>::default()
        .filler(Random2DNonceFiller)
        .filler(<TempoNetwork as RecommendedFillers>::recommended_fillers())
        .wallet(EthereumWallet::from(signer))
        .sponsor(sponsor_url)
        .connect(rpc_url)
        .await
}
```

By default, `.sponsor(sponsor_url)` uses sign-and-relay sponsorship: sponsored
`eth_sendRawTransaction` submissions are sent to the sponsor service, which signs and broadcasts
them. Use `sponsor_with_config` to set the mode, sponsor auth, or sponsor header forwarding:

```rust,ignore
use alloy_transport::Authorization;
use tempo_alloy::provider::ext::SponsorConfig;

ProviderBuilder::<_, _, TempoNetwork>::default()
    // fillers and wallet omitted
    .sponsor_with_config(
        sponsor_url,
        SponsorConfig::sign_only().with_auth(Authorization::bearer("sponsor-token")),
    )
    .connect(rpc_url)
    .await?;
```

For advanced users, `tempo_alloy::transport::RelayTransport` wraps two transports:

- the default Tempo RPC transport for ordinary requests, reads, and sign-only broadcasts;
- the sponsor transport for signing or sign-and-relay `eth_sendRawTransaction` submissions.

Single `eth_sendRawTransaction` requests are locally preflighted as unsigned Tempo AA transactions.
In the default sign-and-relay mode, they are forwarded to the sponsor service. In sign-only mode,
`RelayTransport` calls `eth_signRawTransaction` on the sponsor service and then broadcasts the
returned fee-payer-signed raw transaction through the default RPC. Other methods are forwarded
unchanged to the default RPC.

Sponsor config controls sponsor auth and original-header forwarding. Sign-and-relay forwards
original headers by default for compatibility; sign-only sponsor signing never does and preserves
original headers only for the final default-RPC broadcast.

Lower-level entry points are available when either endpoint needs custom auth, dynamic headers,
proxies, retry policy, or middleware:

- `RelayConnector::http(default_rpc, sponsor_rpc)` implements Alloy's `TransportConnect`;
- `RelayConnector::with_mode(default, sponsor, mode)` builds from explicit connectors;
- `RelayConnector::with_config(default, sponsor, mode, forward_headers)` also configures sponsor header forwarding;
- `RelayTransport::new(default_transport, sponsor_transport)` wraps existing transports directly;
- `RelayTransport::with_mode(default_transport, sponsor_transport, mode)` selects an explicit mode;
- `RelayTransport::with_config(default_transport, sponsor_transport, mode, forward_headers)` also configures sponsor header forwarding;
- `RelayLayer::new(sponsor_transport)` supports Tower-style composition.

Runtime policy is intentionally strict:

- only unsigned Tempo AA raw transactions are sponsored
- already fee-payer-signed transactions are rejected before the sponsor relay is called
- JSON-RPC batches containing `eth_sendRawTransaction` are not supported by `RelayTransport`

Use Tempo AA native batching by including multiple calls in one Tempo AA transaction instead of
putting multiple `eth_sendRawTransaction` requests in a JSON-RPC batch. Validation is always strict,
and forwarded requests preserve JSON-RPC ids. Sign-and-relay sponsor requests may inherit original
headers; sign-only sponsor signing uses only sponsor transport headers, while its final default-RPC
broadcast may preserve original headers.

Sponsor relay services may enforce their own policy, rate limits, and authentication. Applications
should surface sponsor errors to users and avoid assuming every valid Tempo AA transaction is
eligible for sponsorship.
