import hashlib,json,pathlib,subprocess
out=pathlib.Path(__file__).resolve().parent
root=out.parents[2]
phases=json.loads((out/'persistence-summary.json').read_text())
measurements={x['name']:x['delta'] for x in phases['declared_write'] if x['labels']['node']=='a'}
prefix='reth_storage_providers_database_save_blocks_'
trie=measurements[prefix+'write_trie_updates_sum']; state=measurements[prefix+'write_hashed_state_sum']; total=measurements[prefix+'total_sum']
assert abs((trie+state)/total-1)<0.001
batch=json.loads((out/'builder-batch-snapshots.json').read_text())[2]
assert batch['batch_size']==51 and batch['count_increment']==1
io=json.loads((out/'phase-io.json').read_text())
wait=json.loads((out/'builder-root-wait.json').read_text())
ops=json.loads((out/'database-operations.json').read_text())
counts={(x['labels']['node'],x['labels'].get('table'),x['labels'].get('operation')):x['delta'] for x in ops}
assert io['builder_stalled_after_load']['major_faults']==io['builder_stalled_after_load']['io']['rios']
reth=pathlib.Path('/home/ubuntu/repos/reth-payload-cancel-fix')
sources={}
for rel in ['crates/storage/provider/src/providers/database/provider.rs','crates/trie/db/src/trie_cursor.rs','crates/stages/stages/src/stages/merkle.rs','crates/trie/trie/src/trie.rs']:
 p=reth/rel;sources[str(p)]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
(out/'source-evidence.json').write_text(json.dumps({'reth_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=reth,text=True).strip(),'files':sources},indent=2)+'\n')
text=f'''# Why declared writes were slow

The dominant steady-flow bottleneck was applying storage and trie changes to MDBX. There is strong evidence of cold database page loading and cache churn inside that work. Once the follower fell into pipeline catch-up, its serial incremental Merkle calculation also spent minutes in a read-heavy phase. The data does not isolate Ethereum Merkle-node pages from hashed-storage leaf pages or MDBX index pages, or assign an exact fraction of elapsed time to disk waits versus database CPU work.

## A complete builder persistence batch

A 51-block persistence request started at 19:47:53.372838 UTC and finished at 19:51:29.855873 UTC (216.483 seconds). The provider phase gauges sampled immediately afterward report:

| Work | Seconds |
| --- | ---: |
| Write already-hashed state | {batch['write_hashed_state']:.3f} |
| Apply already-computed trie updates | {batch['write_trie_updates']:.3f} |
| Provider save total, excluding final commit | {batch['total']:.3f} |
| Final MDBX transaction commit, from its log event | 0.315 |

The trie phase includes merging/masking update batches and database mutation. It does not recompute the block's Merkle root. The hashed-state phase includes merging and writing values whose keys are already hashed; its name does not mean that this time is spent computing Keccak hashes. Static-file and RocksDB work run in parallel and must not be added to the MDBX total.

Across four completed builder batches recorded by the available measurement counters, {trie:.3f} of {total:.3f} seconds ({100*trie/total:.1f}%) went to trie updates and {state:.3f} seconds ({100*state/total:.1f}%) to hashed state. Final MDBX commits totaled {measurements[prefix+'commit_mdbx_sum']:.3f} seconds over the counter interval, including other commits. These are completed-operation durations. The metric samples span load seconds 600.002–1135.003; batches can begin before that interval, so the totals are not fractions of its wall time.

## Root computation and persistence are distinct

For the 140 completed nonempty builds in the full ten-minute write window, the exposed root wait had median {wait['root_wait']['p50_ms']:.1f} ms and p95 {wait['root_wait']['p95_ms']:.1f} ms. Median completed build time was {wait['build']['p50_ms']:.1f} ms. Root work overlaps execution; this wait is not total root CPU/I/O work. Concurrent proof-worker cursor times also cannot be added as wall time. Persistence backpressure, active for 93.2% of the observation window, prevents many builds from starting.

The relevant implementation is:

- [Provider batch application]({reth}/crates/storage/provider/src/providers/database/provider.rs:733): merge precomputed hashed-state and trie updates, then apply each to the database.
- [Hashed storage replacement]({reth}/crates/storage/provider/src/providers/database/provider.rs:2771): seek the old entry, delete it if found, then upsert the replacement.
- [Storage trie node replacement]({reth}/crates/trie/db/src/trie_cursor.rs:280): the same seek/delete/upsert sequence for updated trie nodes.
- [Catch-up Merkle stage]({reth}/crates/stages/stages/src/stages/merkle.rs:330): run incremental root calculation, then write its resulting trie updates.

Database cursor counters recorded {counts[('a','StoragesTrie','cursor-upsert')]:,.0f} storage-trie upserts and {counts[('a','HashedStorages','cursor-upsert')]:,.0f} hashed-storage upserts, with millions of matching deletes. These counter cohorts include in-flight persistence and lag the canonical workload; they are not an exact per-transaction amplification ratio.

## Direct evidence of page loading

During 115.6 seconds after offered load stopped, the builder stayed at block 551. Execution, included-transaction, and root-completion counters did not advance. Nevertheless it read 6.653 GB and wrote 6.905 GB on its database device. It incurred 1,624,374 major faults and exactly 1,624,374 physical reads, averaging 4,096 bytes each; file-cache refaults were 1,624,095. That is strong evidence of repeated database page loading during persistence, with concurrent page writes. The cache contained roughly 12 GiB of file pages under the 20 GiB whole-node cap.

The follower's final catch-up batch, blocks 412–885, spent 593.515 seconds in incremental Merkle calculation plus update application and commit. Its first six one-minute slices show 56–62 MB/s of reads, about 14–15k major faults/s, and just 0.21 MB/s of writes. In minutes eight and nine, writes rose to about 61 MB/s while reads remained about 57 MB/s. This is consistent with read-heavy traversal followed by database update work. The telemetry does not timestamp the internal calculation-to-update boundary; the read/write split is an inference from I/O, not an instrumented phase split. Both existing trie nodes and hashed storage values are read by the root calculator.

The preceding catch-up batch, blocks 337–411, took 666.455 seconds in the same stage. Their final MDBX commits took only 135 ms and 76 ms respectively. The subsequent empty-block batch took 8 ms. This was incremental work, not a full rebuild of all 1.6 billion slots.

## Consequences and the remaining experiment

EIP-2930 warmth records a logical access's EVM gas status; it does not keep the entire trie/database update working set resident until persistence. Slot prewarming, Merkle-path prefetching, and preparing MDBX pages for mutation are different tasks. Uniform slot targets become scattered hashed keys across a large database. Updating a logical slot requires replacing its value and affected trie nodes, and database page mutation can incur reads, copy-on-write and page-management costs. Their precise time split is not measured here.

A focused follow-up should replay identical frozen state/trie-update batches on disposable database copies with the same memory cap, comparing demand paging with bounded prefetch of both storage and trie database pages. Time merging, seek/read, delete/upsert, and commit separately; record per-thread major faults, on/off-CPU stacks, and physical I/O. Count prefetch time in the total to retain the 1 Ggas/s criterion. This distinguishes removable page-fault latency from database mutation/CPU work without mixing in EVM or consensus effects.

Also include a fixed-width value control. The benchmark toggles bit 255 of a small nonzero value: the first update increases the compact value payload from at most four bytes to 32 bytes (the key remains 32 bytes). Existing-slot replacement therefore includes encoded-value growth. This can contribute to page splits and write amplification, but its contribution has not been measured. It remains a valid existing-slot stress case; it should not be presented as a constant-size overwrite benchmark.

Evidence: [phase counters]({out}/persistence-summary.json), [batch snapshots]({out}/builder-batch-snapshots.json), [execution-idle I/O and Merkle stages]({out}/phase-io.json), [Merkle I/O slices]({out}/follower-merkle-io-slices.json), [root-wait distribution]({out}/builder-root-wait.json), [database operations]({out}/database-operations.json), and [source hashes]({out}/source-evidence.json). The extraction scripts and timestamped log events with original file/line provenance are in this directory. No runtime or original benchmark result was changed.
'''
(out/'README.md').write_text(text)
print(json.dumps({'trie_update_share':trie/total,'hashed_state_share':state/total,'example_save_seconds':batch['total'],'diagnosis':str(out/'README.md')},indent=2))
