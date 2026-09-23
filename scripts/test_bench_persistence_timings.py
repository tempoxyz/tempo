import runpy
from pathlib import Path
import unittest

analyze = runpy.run_path(str(Path(__file__).with_name("bench-persistence-timings.py")))["analyze"]


class PersistenceReportTest(unittest.TestCase):
    def event(self, message, tip=10, node="a", **values):
        return dict(benchmark_id="test", benchmark_run="feature-1", runner_role=node,
                    last_block_number=tip, state_block_number=tip, message=message, **values)

    def test_weighted_ratios_exclude_incomplete_batches_and_other_nodes(self):
        rows = []
        for tip, blocks, seconds in [(10, 10, 2), (40, 30, 3)]:
            rows += [self.event("Persistence batch writes", tip, block_count=blocks,
                                transaction_count=blocks * 10, state_trie_block_count=blocks,
                                elapsed_seconds=seconds),
                     self.event("Persistence batch complete", tip, commit_seconds=1,
                                elapsed_seconds=seconds + 1)]
        rows += [self.event("Persistence batch writes", 99, block_count=100,
                            transaction_count=1000, state_trie_block_count=100,
                            elapsed_seconds=999),
                 self.event("Persistence table operations", 99, table="Storage", operations=1,
                            operation_nanos=999000000000),
                 self.event("Persistence batch complete", 10, node="b", commit_seconds=99,
                            elapsed_seconds=100)]
        report = analyze(rows + rows[:1])
        self.assertEqual(report["unmatched_write_batches"], 1)
        self.assertEqual(report["unmatched_completed_batches"], 1)
        phase = report["phases"][0]
        self.assertEqual(phase["completed_batches"], 2)
        self.assertEqual(phase["complete_persistence_ms_per_block"], 175)
        self.assertEqual(phase["tables"], {})

    def test_overlap_and_shards_are_reported_separately(self):
        rows = [self.event("Persistence batch writes", block_count=2, transaction_count=20,
                           state_trie_block_count=1, elapsed_seconds=3),
                self.event("Persistence batch complete", commit_seconds=1, elapsed_seconds=4),
                self.event("Persistence worker preparation")]
        for shard, start in [(0, 0), (1, 1)]:
            rows.append(self.event("Persistence table task", table="Storage", shard=shard,
                                   start_offset_seconds=start, elapsed_seconds=2))
        phase = analyze(rows)["phases"][0]
        self.assertEqual(phase["mean_peak_overlapping_table_tasks"], 2)
        self.assertEqual(len(phase["table_tasks"]), 2)
        self.assertEqual(phase["state_trie_blocks"], 1)


if __name__ == "__main__":
    unittest.main()
