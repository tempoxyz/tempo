# Bridge Sidecar Specification

This document specifies the bridge sidecar binary that validators run to observe messages and produce BLS signatures.

## Overview

The bridge sidecar:
- Watches chains for `MessageSent` events
- Waits for finality
- Signs attestations with the validator's BLS key share
- Broadcasts partial signatures via P2P
- Aggregates partial signatures and submits to destination chain

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Bridge Sidecar Architecture                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   ┌─────────────────┐           ┌─────────────────┐                             │
│   │  Chain Watcher  │           │  Chain Watcher  │                             │
│   │   (Ethereum)    │           │   (Tempo)       │                             │
│   └────────┬────────┘           └────────┬────────┘                             │
│            │ MessageSent events          │                                       │
│            ▼                             ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────┐           │
│   │                      Message Processor                          │           │
│   │  • Compute attestation hash                                     │           │
│   │  • Sign with BLS key share                                      │           │
│   │  • Broadcast partial via P2P                                    │           │
│   └─────────────────────────────────────────────────────────────────┘           │
│            │                                                                     │
│            ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────┐           │
│   │                         Aggregator                              │           │
│   │  • Collect t-of-n partial signatures                            │           │
│   │  • Recover threshold signature                                  │           │
│   └─────────────────────────────────────────────────────────────────┘           │
│            │                                                                     │
│            ▼                                                                     │
│   ┌─────────────────────────────────────────────────────────────────┐           │
│   │                         Submitter                               │           │
│   │  • Call write(sender, messageHash, originChainId, signature)    │           │
│   └─────────────────────────────────────────────────────────────────┘           │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Configuration

```toml
# bridge-sidecar.toml

[general]
log_level = "info"
metrics_port = 9090

[[chains]]
name = "ethereum"
chain_id = 1
rpc_url = "https://eth-mainnet.g.alchemy.com/v2/KEY"
bridge_address = "0x..."
finality_mode = "finalized"
poll_interval_secs = 12

[[chains]]
name = "tempo"
chain_id = 12345
rpc_url = "http://localhost:8545"
bridge_address = "0x..."
finality_mode = "instant"
poll_interval_secs = 1

[signer]
validator_index = 0
bls_key_share_file = "/path/to/validator.bls.key"

[p2p]
listen_addr = "/ip4/0.0.0.0/tcp/9000"
bootstrap_peers = ["/ip4/10.0.0.1/tcp/9000/p2p/Qm..."]

[threshold]
threshold = 3
validator_count = 4

[persistence]
db_path = "/var/lib/bridge-sidecar/state.db"
```

## Core Components

### Chain Watcher

Monitors for `MessageSent` events:

```rust
pub struct ChainWatcher {
    chain_id: u64,
    provider: Provider<Http>,
    bridge_address: Address,
    finality_mode: FinalityMode,
}

impl ChainWatcher {
    pub async fn watch(&mut self, tx: mpsc::Sender<Message>) -> Result<()> {
        loop {
            let finalized = self.get_finalized_block().await?;
            
            // Query MessageSent(address sender, bytes32 messageHash, uint64 destinationChainId)
            let logs = self.provider.get_logs(&Filter::new()
                .address(self.bridge_address)
                .topic0(MESSAGE_SENT_TOPIC)
                .from_block(self.last_block + 1)
                .to_block(finalized)
            ).await?;
            
            for log in logs {
                let sender = Address::from_slice(&log.topics[1][12..]);
                let message_hash = B256::from_slice(&log.topics[2]);
                let dest_chain_id = u64::from_be_bytes(log.topics[3][24..].try_into()?);
                
                tx.send(Message {
                    sender,
                    message_hash,
                    origin_chain_id: self.chain_id,
                    destination_chain_id: dest_chain_id,
                }).await?;
            }
            
            self.last_block = finalized;
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}
```

### BLS Signer

Signs attestation hashes:

```rust
pub const BLS_DST: &[u8] = b"TEMPO_BRIDGE_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

pub struct BLSSigner {
    share: Share,
    validator_index: u32,
}

impl BLSSigner {
    pub fn sign_partial(&self, attestation_hash: B256) -> PartialSignature {
        let partial = partial_sign_message::<MinSig>(
            &self.share,
            Some(BLS_DST),
            attestation_hash.as_slice(),
        );
        
        PartialSignature {
            index: self.validator_index,
            signature: partial.signature.compress(),
        }
    }
}
```

### Aggregator

Collects partials and recovers threshold signature:

```rust
pub struct Aggregator {
    threshold: usize,
    sharing: Sharing<MinSig>,
    pending: HashMap<B256, Vec<PartialSignature>>,
}

impl Aggregator {
    pub fn add_partial(
        &mut self,
        attestation_hash: B256,
        partial: PartialSignature,
    ) -> Option<[u8; 96]> {
        let partials = self.pending.entry(attestation_hash).or_default();
        
        // Deduplicate by index
        if partials.iter().any(|p| p.index == partial.index) {
            return None;
        }
        partials.push(partial);
        
        // Check threshold
        if partials.len() >= self.threshold {
            let signature = threshold_signature_recover(&self.sharing, partials).ok()?;
            self.pending.remove(&attestation_hash);
            return Some(signature.compress());
        }
        
        None
    }
}
```

### Submitter

Submits to destination chain:

```rust
pub struct Submitter {
    provider: Provider<Http>,
    wallet: LocalWallet,
    bridge_address: Address,
}

impl Submitter {
    pub async fn submit(
        &self,
        message: &Message,
        signature: [u8; 96],
    ) -> Result<TxHash> {
        // write(address sender, bytes32 messageHash, uint64 originChainId, bytes signature)
        let calldata = IMessageBridge::writeCall {
            sender: message.sender,
            messageHash: message.message_hash,
            originChainId: message.origin_chain_id,
            signature: signature.into(),
        }.abi_encode();
        
        let tx = TransactionRequest::default()
            .to(self.bridge_address)
            .data(calldata);
        
        let receipt = self.provider.send_transaction(tx, None).await?.await?;
        Ok(receipt.transaction_hash)
    }
}
```

## Main Loop

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load()?;
    let signer = BLSSigner::from_file(&config.signer.bls_key_share_file)?;
    let aggregator = Arc::new(Mutex::new(Aggregator::new(&config)?));
    let mut gossip = P2PGossip::new(&config.p2p).await?;
    
    let (tx, mut rx) = mpsc::channel(1000);
    
    // Spawn watchers for each chain
    for chain in &config.chains {
        let watcher = ChainWatcher::new(chain).await?;
        let tx = tx.clone();
        tokio::spawn(async move { watcher.watch(tx).await });
    }
    
    // Submitters for each chain
    let submitters: HashMap<u64, Submitter> = config.chains.iter()
        .map(|c| (c.chain_id, Submitter::new(c)))
        .collect();
    
    loop {
        tokio::select! {
            // New message from chain watcher
            Some(msg) = rx.recv() => {
                let attestation_hash = msg.attestation_hash();
                let partial = signer.sign_partial(attestation_hash);
                
                // Broadcast our partial
                gossip.broadcast(attestation_hash, &msg, &partial).await?;
                
                // Add to aggregator
                if let Some(sig) = aggregator.lock().await.add_partial(attestation_hash, partial) {
                    let submitter = &submitters[&msg.destination_chain_id];
                    submitter.submit(&msg, sig).await?;
                }
            }
            
            // Partial from another validator
            Ok((attestation_hash, msg, partial)) = gossip.recv() => {
                if let Some(sig) = aggregator.lock().await.add_partial(attestation_hash, partial) {
                    let submitter = &submitters[&msg.destination_chain_id];
                    submitter.submit(&msg, sig).await?;
                }
            }
        }
    }
}
```

## P2P Gossip

```rust
#[derive(Serialize, Deserialize)]
pub struct GossipMessage {
    pub attestation_hash: B256,
    pub message: Message,
    pub partial: PartialSignature,
}

pub struct P2PGossip {
    swarm: Swarm<gossipsub::Behaviour>,
    topic: gossipsub::IdentTopic,
}

impl P2PGossip {
    pub async fn broadcast(
        &mut self,
        attestation_hash: B256,
        message: &Message,
        partial: &PartialSignature,
    ) -> Result<()> {
        let msg = GossipMessage {
            attestation_hash,
            message: message.clone(),
            partial: partial.clone(),
        };
        self.swarm.behaviour_mut().publish(self.topic.clone(), bincode::serialize(&msg)?)?;
        Ok(())
    }
    
    pub async fn recv(&mut self) -> Result<(B256, Message, PartialSignature)> {
        loop {
            if let SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) = 
                self.swarm.select_next_some().await 
            {
                let msg: GossipMessage = bincode::deserialize(&message.data)?;
                return Ok((msg.attestation_hash, msg.message, msg.partial));
            }
        }
    }
}
```

## Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `bridge_messages_observed` | Counter | Messages observed per chain |
| `bridge_partials_signed` | Counter | Partial signatures created |
| `bridge_partials_received` | Counter | Partials received via P2P |
| `bridge_aggregations_completed` | Counter | Threshold signatures created |
| `bridge_submissions_total` | Counter | Transactions submitted |
| `bridge_last_block_processed` | Gauge | Last block per chain |

## Deployment

### Systemd

```ini
[Unit]
Description=Tempo Bridge Sidecar
After=network.target

[Service]
Type=simple
User=bridge
ExecStart=/usr/local/bin/bridge-sidecar run -c /etc/bridge-sidecar/config.toml
Restart=always

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin bridge-sidecar

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/bridge-sidecar /usr/local/bin/
ENTRYPOINT ["bridge-sidecar"]
```

## File Locations

| Component | Path |
|-----------|------|
| Main | `crates/bridge-sidecar/src/main.rs` |
| Watcher | `crates/bridge-sidecar/src/watcher.rs` |
| Signer | `crates/bridge-sidecar/src/signer.rs` |
| Aggregator | `crates/bridge-sidecar/src/aggregator.rs` |
| P2P | `crates/bridge-sidecar/src/p2p.rs` |
| Submitter | `crates/bridge-sidecar/src/submitter.rs` |
