import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("timings", Path(__file__).with_name("bench-persistence-timings.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def row(name, end, node="a", **labels):
    return {"metric": {"__name__": name, "instance": node, **labels},
            "values": [[0, "10"], [10, str(10 + end)]]}


class MetricsTests(unittest.TestCase):
    def test_weighted_ratios_and_node_isolation(self):
        rows = [row(m.P + "persisted_blocks_total", 5),
                row(m.P + "persisted_transactions_total", 100),
                row(m.P + "save_blocks_duration_seconds_sum", 2),
                row(m.P + "save_blocks_duration_seconds_count", 2),
                row(m.T + "_sum", 1, table="HashedStorages", shard="2"),
                row(m.T + "_count", 2, table="HashedStorages", shard="2"),
                row("reth_storage_providers_static_file_segment_write_seconds_sum", 0.2, segment="Headers"),
                row("reth_storage_providers_static_file_segment_write_seconds_count", 2, segment="Headers"),
                row(m.P + "persisted_blocks_total", 1000, node="b")]
        result = m.analyze({"data": {"resultType": "matrix", "result": rows}})["phases"]
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["complete_persistence_ms_per_block"], 400)
        self.assertEqual(result[0]["persistence_service_transactions_per_second"], 50)
        self.assertEqual(result[0]["tables"][0]["mean_task_ms"], 500)
        self.assertEqual(result[0]["tables"][1]["backend"], "static_file")
        self.assertAlmostEqual(result[0]["tables"][1]["mean_task_ms"], 100)
        self.assertIsNone(result[0]["mean_validator_execution_ms"])

    def test_reject_reset_and_missing_scrapes(self):
        with self.assertRaises(ValueError):
            m.delta({"values": [[0, "5"], [1, "2"]]})
        with self.assertRaises(ValueError):
            m.delta({"values": [[0, "5"]]})


if __name__ == "__main__":
    unittest.main()
