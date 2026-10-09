# Transaction storage access RPC

Enable the usual `eth` RPC module (`--http --http.api eth` or the equivalent
WebSocket configuration). Tempo registers these methods on the ordinary node
and the read-only RPC worker:

- `tempo_createAccessList(transaction, block?)` simulates a
  `TempoTransactionRequest` with `eth_call` semantics at the selected block's
  post-block state. The block defaults to `latest`; both block numbers/tags and
  EIP-1898 block identifiers work. The configured RPC gas and memory limits apply.
- `tempo_getTransactionAccessList(hash)` replays a mined transaction against its
  exact pre-transaction state, applying preceding transactions and system changes
  or using the cached block access list. It returns `null` for missing/pending
  transactions. Replay requires the parent block's historical state.

Both return:

```json
{
  "accessList": [
    {
      "address": "0x4242424242424242424242424242424242424242",
      "readStorageKeys": ["0x0000000000000000000000000000000000000000000000000000000000000001"],
      "writeStorageKeys": ["0x0000000000000000000000000000000000000000000000000000000000000002"]
    }
  ],
  "gasUsed": "0x5208",
  "success": true,
  "returnData": "0x"
}
```

Addresses and keys are deduplicated and sorted. Keys are 32-byte hex words.
Each key occurs in only one array: `readStorageKeys` contains slots accessed
without a write; written slots appear only in `writeStorageKeys`, including slots
that were also read. These classify storage-key accesses, not physical DB page
I/O. Account-only accesses have empty key arrays. The result covers
persistent EVM storage and native Tempo precompiles, including TIP-20 balances,
nonce lanes, fee collection, and storage credits. `DELEGATECALL` keys belong to
the storage owner. Transient `TLOAD`/`TSTORE` keys are excluded.

This is an execution access list: no-op stores, writes later restored to their
original values, and accesses inside reverted calls are retained. It is not a
list of committed changes. A forbidden or failed opcode is not reported as a
successful write. Reverts/halts return the observed accesses with `success:
false`, an `error` string, and any `returnData`. Invalid requests, transaction
validation failures, missing historical state, and unavailable blocks use normal
JSON-RPC errors. Nothing is submitted or committed to chain state.

Simulation disables fee charging like `eth_call`; use mined replay to observe
actual transaction fee writes. Supplying an input EIP-2930 access list warms
those keys but does not by itself label them as writes.

Examples (replace the RPC address, sender, target, calldata, and hash):

```sh
curl -s http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tempo_createAccessList","params":[{"from":"0x1111111111111111111111111111111111111111","to":"0x4242424242424242424242424242424242424242","input":"0x","gas":"0xf4240"},"latest"]}'

curl -s http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tempo_getTransactionAccessList","params":["0x0000000000000000000000000000000000000000000000000000000000000000"]}'
```

The historical router selects the execution era from the simulation block or
mined transaction's block. Each era worker must advertise these methods; older
worker binaries without them cannot serve these requests.
