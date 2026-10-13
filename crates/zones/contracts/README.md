# Zone runtime contracts

This directory contains the Solidity contracts that remain deployed: the shared Tempo Zone
runtimes (`ZonePortal`, `ZoneMessenger`, and `Verifier`) and the `SwapAndDepositRouter` utility.
The shared runtime bytecode is synchronized into the Tempo repository by the
`sync-tempo-zone-runtimes` workflow.

Run the contract tests with a Tempo-capable Foundry build:

```bash
forge test
```

Zone Portal implementations are named for their activation fork, starting with
`src/runtime/tempo/ZonePortalT14.sol`. Add a new version for subsequent changes rather than
editing a deployed version. The compiler (0.8.35), EVM target (Osaka), optimizer runs (200),
and IR pipeline are pinned in `foundry.toml`; Solidity dependencies are pinned as submodules.

Check the full deployed bytecode, including compiler metadata, against the corresponding
`T*_ZONE_PORTAL_RUNTIME` constant and the active version in dev genesis:

```bash
uv run --no-project python scripts/check-zone-portal-bytecode.py
```

CI runs this check for every `ZonePortalT*.sol` source and also runs when embedded bytecode
or dev genesis changes. Changes to imported sources or compiler settings can affect older
versions too; preserve their build inputs when adding a new fork. Historical runtimes before
T14 retain their existing bytecode and are outside this check because their complete original
build inputs are not included here. Solidity metadata also depends on source paths and names:
see [Contract Metadata](https://docs.soliditylang.org/en/latest/metadata.html).
