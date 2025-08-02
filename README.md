# reth x malachite integration

The goal of this app is to integrate the Reth execution library and the Malachite BFT consensus library to produce a “full” node prototype capable of both consensus and execution. This new reth node opens the possibility of building new ethereum based alt-L1 networks fully within the existing, battle-tested reth ecosystem of tools.

## Documentation

- [Architecture Overview](docs/malachite-reth-interactions.md) - High-level overview of the Malachite-Reth integration

## Testing

### End-to-End Testing Framework

The project includes a comprehensive e2e testing framework located in the `./testnet` directory. This framework allows you to:

- Spin up local test networks with configurable node counts
- Run automated tests to verify consensus and block production
- Monitor network health and debug issues
- Test different network topologies and configurations

For detailed instructions on using the e2e testing framework, see the [Testnet README](./testnet/README.md).

Quick start:

```bash
# Launch a 3-node test network
$ ./testnet/spawn.sh

# Run automated e2e test
$ ./testnet/scripts/e2e_test.sh
```
