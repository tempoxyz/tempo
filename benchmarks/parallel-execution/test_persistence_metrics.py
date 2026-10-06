#!/usr/bin/env python3
"""Counter selection, transport bounds and retained failure evidence."""

import contextlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import persistence_metrics as metrics


SUM = metrics.PREFIX + "save_blocks_total_sum"
COUNT = metrics.PREFIX + "save_blocks_total_count"


class PersistenceMetricsTests(unittest.TestCase):
    def test_keeps_cumulative_counts_and_gauges_without_rolling_quantiles(self):
        body = (f'# TYPE {SUM} counter\n{SUM}{{chain="tempo"}} 1.25e+1\n'
                f'{COUNT} 2\n{metrics.PREFIX}save_blocks_mdbx_last 4.5\n'
                f'{metrics.PREFIX}save_blocks_total{{quantile="0.5"}} 6\n'
                'unrelated_metric NaN\n').encode()
        rows = metrics.selected_samples(body)
        self.assertEqual([row['name'] for row in rows], [SUM, COUNT, metrics.PREFIX + 'save_blocks_mdbx_last'])
        self.assertEqual(rows[0]['value'], '1.25e+1')
        self.assertEqual(rows[0]['labels'], '{chain="tempo"}')

    def test_rejects_missing_truncated_invalid_or_duplicate_selected_data(self):
        for body in [b'unrelated_metric 1\n', f'{SUM} 1'.encode(),
                     f'{SUM} NaN\n'.encode(), f'{SUM} +Inf\n'.encode(),
                     f'{SUM} -1\n'.encode(), f'{COUNT} 0.5\n'.encode(),
                     f'{SUM} 1\n{SUM} 2\n'.encode(), f'{SUM} nope\n'.encode()]:
            with self.subTest(body=body), self.assertRaises(ValueError):
                metrics.selected_samples(body)

    def test_response_and_series_bounds(self):
        with patch.object(metrics, 'MAX_BODY', 8), self.assertRaises(ValueError):
            metrics.selected_samples(f'{SUM} 1\n'.encode())
        with self.assertRaisesRegex(ValueError, 'too many'):
            metrics.selected_samples(''.join(f'{SUM}{{id="{i}"}} 1\n' for i in range(129)).encode())

    def test_real_http_response_and_limit(self):
        body = f'{SUM} 12\n{COUNT} 3\n'.encode()
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_args):
                pass
        with http.server.HTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            self.addCleanup(thread.join)
            self.addCleanup(server.shutdown)
            url = f'http://127.0.0.1:{server.server_port}/metrics'
            result = metrics.snapshot('a', url)
            self.assertEqual(result['response_bytes'], len(body))
            self.assertEqual(result['samples'][1]['value'], '3')
            with patch.object(metrics, 'MAX_BODY', 8), self.assertRaisesRegex(ValueError, '8 MiB'):
                metrics.snapshot('a', url)

    def run_cli(self, path, snapshot):
        argv = ['persistence_metrics', '--phase', 'feature-1', '--boundary', 'post', '--output', str(path)]
        with patch('sys.argv', argv), patch.object(metrics, 'snapshot', side_effect=snapshot), contextlib.redirect_stdout(io.StringIO()):
            return metrics.main()

    def test_cli_retains_failure_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'post.json'
            self.assertEqual(self.run_cli(path, TimeoutError('timed out')), 1)
            saved = path.read_bytes()
            self.assertEqual(json.loads(saved)['errors'], ['timed out'])
            with self.assertRaises(FileExistsError):
                self.run_cli(path, lambda role, url: {'role': role, 'url': url})
            self.assertEqual(path.read_bytes(), saved)

    def test_cli_records_both_peers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'post.json'
            self.assertEqual(self.run_cli(path, lambda role, url: {'role': role, 'url': url}), 0)
            result = json.loads(path.read_text())
            self.assertEqual(result['status'], 'passed')
            self.assertEqual([node['role'] for node in result['nodes']], ['a', 'b'])
            self.assertEqual(result['boundary'], 'post')


if __name__ == '__main__':
    unittest.main()
