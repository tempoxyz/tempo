"""Regression checks for nextest JUnit warnings; no third-party dependencies."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from warn_flaky_e2e import report_flakes


class FlakyReportTests(unittest.TestCase):
    def report(self, xml):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "junit.xml"
            if xml is not None:
                path.write_text(xml, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                report_flakes(path)
            return output.getvalue()

    def test_clean_failed_and_skipped_tests_do_not_warn(self):
        output = self.report("""<testsuites><testsuite>
            <testcase name="clean"/>
            <testcase name="failed"><failure/><rerunFailure/></testcase>
            <testcase name="aborted"><error/><rerunError/></testcase>
            <testcase name="skipped"><skipped/></testcase>
        </testsuite></testsuites>""")
        self.assertEqual(output, "")

    def test_both_flaky_tags_count_once_per_test(self):
        output = self.report("""<testsuites><testsuite>
            <testcase classname="tempo-e2e::integration" name="recovers">
                <flakyFailure type="test failure"/><flakyError type="abort"/>
            </testcase>
            <testcase classname="tempo-e2e::integration" name="also_recovers">
                <flakyError/>
            </testcase>
            <testcase name="still_fails"><failure/><rerunFailure/></testcase>
        </testsuite></testsuites>""")
        self.assertEqual(output.count("::warning title=Flaky E2E test::"), 2)
        self.assertIn("tempo-e2e::integration::recovers passed after 2 failed", output)
        self.assertIn("also_recovers passed after 1 failed", output)
        self.assertNotIn("still_fails", output)

    def test_output_comments_and_unrelated_tags_do_not_warn(self):
        output = self.report("""<testsuites><testsuite><testcase>
            <!-- <flakyFailure/> -->
            <system-out><![CDATA[<flakyFailure type="test failure"/>]]></system-out>
            <system-err>&lt;flakyError/&gt;</system-err>
            <flakyFailureOther/>
        </testcase></testsuite></testsuites>""")
        self.assertEqual(output, "")

    def test_nonpassing_results_with_flaky_tags_do_not_warn(self):
        # Newer nextest versions can be configured to fail recovered flakes.
        for result in ("failure", "error", "skipped"):
            with self.subTest(result=result):
                self.assertEqual(
                    self.report(f"<testcase><{result}/><flakyFailure/></testcase>"), ""
                )

    def test_xml_entities_and_command_data_are_escaped(self):
        output = self.report("""<testcase classname="suite" name="a&amp;b%&#13;&#10;test">
            <flakyFailure/>
        </testcase>""")
        self.assertIn("suite::a&b%25%0D%0Atest", output)
        self.assertEqual(len(output.splitlines()), 1)

    def test_missing_report_is_not_a_flaky_warning(self):
        self.assertIn("No E2E JUnit report found", self.report(None))
        self.assertNotIn("::warning", self.report(None))

    def test_malformed_report_is_advisory(self):
        output = self.report("<testsuites>")
        self.assertIn("::warning title=E2E report unavailable::", output)
        self.assertNotIn("Flaky E2E test", output)


if __name__ == "__main__":
    unittest.main()
