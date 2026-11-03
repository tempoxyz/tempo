"""Regression checks for TOML comment stripping used while publishing crates."""

import unittest

from sanitize_toml import _depth_delta, _strip_comment, strip_dep_lines


class StripCommentTests(unittest.TestCase):
    def test_plain_comment_and_its_braces_are_ignored(self):
        self.assertEqual(_strip_comment('name = "foo" # comment {'), 'name = "foo" ')
        self.assertEqual(_depth_delta("# { ignored"), (0, 0))
        self.assertEqual(_depth_delta('foo = { version = "1" } # [no]'), (0, 0))

    def test_hash_inside_single_quotes_is_not_a_comment(self):
        line = "description = 'The blockchain #1 for payments'"
        self.assertEqual(_strip_comment(line), line)

    def test_hash_inside_double_quotes_is_not_a_comment(self):
        line = 'description = "The blockchain #1 for payments"'
        self.assertEqual(_strip_comment(line), line)

    def test_comment_after_a_closed_literal_string_is_removed(self):
        self.assertEqual(
            _strip_comment("key = 'value' # comment"),
            "key = 'value' ",
        )

    def test_even_backslashes_do_not_escape_the_closing_quote(self):
        # File text: "\\" # { not code
        # (a basic string of two backslashes, then a comment).
        line = '"\\\\" # { not code'
        self.assertEqual(_strip_comment(line), '"\\\\" ')

    def test_escaped_quote_does_not_end_a_basic_string(self):
        line = r'"say \" # still a string" # real'
        self.assertEqual(_strip_comment(line), r'"say \" # still a string" ')

    def test_hash_inside_a_literal_triple_quote_is_kept(self):
        line = "note = '''hash # not a comment'''"
        self.assertEqual(_strip_comment(line), line)


class DepthDeltaTests(unittest.TestCase):
    def test_braces_inside_a_literal_string_do_not_count(self):
        self.assertEqual(_depth_delta("key = 'value { not a brace'"), (0, 0))

    def test_brackets_inside_a_basic_string_do_not_count(self):
        self.assertEqual(_depth_delta('key = "value [ not a bracket ]"'), (0, 0))

    def test_real_braces_outside_strings_still_count(self):
        self.assertEqual(_depth_delta('foo = { version = "1"'), (1, 0))
        self.assertEqual(_depth_delta("foo = { version = '1' }"), (0, 0))
        self.assertEqual(_depth_delta('features = ["a"'), (0, 1))

    def test_comment_after_even_backslashes_does_not_count(self):
        self.assertEqual(_depth_delta('"\\\\" # { not code'), (0, 0))


class StripDepLinesTests(unittest.TestCase):
    def test_hash_inside_a_string_does_not_swallow_the_next_dependency(self):
        text = (
            "foo = { version = \"1\", note = 'hash # { not a brace' }\n"
            "bar = \"1\"\n"
        )
        result = strip_dep_lines(text, lambda name: name == "foo")
        self.assertNotIn("foo", result)
        self.assertIn('bar = "1"', result)


if __name__ == "__main__":
    unittest.main()
