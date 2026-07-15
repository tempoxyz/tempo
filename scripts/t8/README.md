# T8 network checks

These scripts exercise the externally observable behavior of TIP-1042,
TIP-1062/TIP-1087, TIP-1070, and TIP-1075 against a live Tempo RPC. They mutate
chain state and should be run with a disposable funded key.

```bash
export RPC_URL=https://rpc-nextfork.devnet.tempo.xyz
export PRIVATE_KEY=0x...
scripts/t8/run-all.sh
```

`USE_FAUCET=1` (the default) calls `tempo_fundAddress`. Set it to `0` when the
key is already funded. The TIP-1070 check reads the current committee; set
`WAIT_FOR_EPOCH=1` to keep polling until the onchain committee epoch advances.

## DEX transition and gas comparison

Run setup before T8 activation and verification after activation with the same
key and state file:

```bash
T8_DEX_STATE_FILE=t8-moderato.json scripts/t8/test-tip-1062-1087.sh setup
# activate T8
T8_DEX_STATE_FILE=t8-moderato.json scripts/t8/test-tip-1062-1087.sh verify
```

The setup phase places a legacy order and records its receipt gas. Verification
confirms that the legacy order remains readable, assigns the saved book index,
places a new order on the indexed book, cancels the legacy order, and requires
the indexed placement to use less gas. On a network where T8 is already active,
`post-only` verifies new indexed orderbook lookup plus order placement/cancel.

The public DEX ABI intentionally hides the physical order version. The test
therefore proves V2 eligibility by checking the persisted book index and then
exercising the write/read/cancel path whose T8 implementation selects V2 for an
indexed book; exact storage layout remains covered by the Rust unit tests.
