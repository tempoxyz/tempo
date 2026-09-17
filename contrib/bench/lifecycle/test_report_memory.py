import json
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

import report


class ReportMemoryTests(unittest.TestCase):
    def test_serialization_is_released_before_package_generation(self):
        # Keep the decoded input outside tracing; measure the temporary serialization
        # retained at the actual package boundary, not peak encoder workspace.
        data = {'payload': '<' + 'x' * (8 * 1024 * 1024)}
        observed = []
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            def package(actual, destination):
                self.assertIs(actual, data)
                self.assertEqual(destination, out)
                observed.append(tracemalloc.get_traced_memory()[0])
            with patch.object(report, 'build', return_value=data), patch.object(report, 'write_package', side_effect=package):
                tracemalloc.start()
                try:
                    self.assertIs(report.write_report([], out), data)
                finally:
                    tracemalloc.stop()
            self.assertEqual(len(observed), 1)
            self.assertLess(observed[0], 1024 * 1024)
            self.assertEqual((out/'lifecycle.json').read_text(), json.dumps(data, separators=(',', ':')).replace('<', r'\u003c'))


if __name__ == '__main__':
    unittest.main()
