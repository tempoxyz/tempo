"""Exercise the release workflow's tag parsing and package-version check."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = yaml.safe_load((ROOT / '.github/workflows/zones-release.yml').read_text())


def script(job, name):
    return next(step['run'] for step in WORKFLOW['jobs'][job]['steps']
                if step.get('name') == name)


class ZonesReleaseTests(unittest.TestCase):
    def parse_tag(self, tag, dispatch=True):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'output'
            result = subprocess.run(['bash', '-eu', '-c', script('get-version', 'Get version from tag')],
                                    env=dict(os.environ, INPUT_TAG=tag if dispatch else '',
                                             GITHUB_REF=f'refs/tags/{tag}', GITHUB_OUTPUT=str(output)),
                                    text=True, capture_output=True)
            return result.returncode, output.read_text() if output.exists() else ''

    def test_zones_tags_keep_separate_ref_and_filename_version(self):
        for tag in ('zones/v0.3.5', 'zones/v0.3.5-rc.1'):
            for dispatch in (True, False):
                with self.subTest(tag=tag, dispatch=dispatch):
                    code, output = self.parse_tag(tag, dispatch)
                    self.assertEqual(code, 0)
                    self.assertEqual(output, f'tag={tag}\nversion={tag[6:]}\n')

    def test_rejects_tempo_tags_branches_and_invalid_versions(self):
        for tag in ('v1.16.0', 'main', 'zones/main', 'zones/v0.3', 'zones/v0.3.5/other',
                    'zones/v0.3.5\ntag=other'):
            with self.subTest(tag=tag):
                code, output = self.parse_tag(tag)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, '')

    def test_selects_zones_package_and_rejects_version_prefix_collisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            cargo = Path(tmp) / 'cargo'
            cargo.write_text('#!/bin/sh\nprintf \'%s\\n\' \'{"packages":['
                             '{"name":"tempo","version":"1.16.0"},'
                             '{"name":"tempo-zone","version":"0.3.5"}]}\'\n')
            cargo.chmod(0o755)
            for version, allowed in (('v0.3.5', True), ('v0.3.5-rc.1', True),
                                     ('v0.3.50', False), ('v1.16.0', False)):
                with self.subTest(version=version):
                    result = subprocess.run(['bash', '-eu', '-c',
                                             script('check-version', 'Verify crate version matches tag')],
                                            env=dict(os.environ, VERSION=version,
                                                     PATH=f'{tmp}:{os.environ["PATH"]}'),
                                            capture_output=True)
                    self.assertEqual(result.returncode == 0, allowed)
