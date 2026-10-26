"""Exercise the release workflow's archive and publication gates without GitHub."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest

import yaml
from pathlib import Path


WORKFLOW = (Path(__file__).parents[1] / "workflows/zones-release.yml").read_text()


PARSED_WORKFLOW = yaml.safe_load(WORKFLOW)
PROFILING_WORKFLOW = yaml.safe_load(
    (Path(__file__).parents[1] / "workflows/zones-docker-profiling.yml").read_text()
)


def step_script(name):
    step = WORKFLOW.split(f"      - name: {name}\n", 1)[1]
    lines = step.split("        run: |\n", 1)[1].splitlines()
    end = next(
        (i for i, line in enumerate(lines) if line.strip() and not line.startswith("          ")),
        len(lines),
    )
    return textwrap.dedent("\n".join(lines[:end]))


class ZonesReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.assets = self.root / "candidate"
        self.assets.mkdir()
        self.binary_name = "tempo-zone-v0.3.5-x86_64-unknown-linux-gnu"
        self.archive = self.assets / f"{self.binary_name}.tar.gz"
        self.payload = b"canonical release binary\n"
        self.binary_hash = hashlib.sha256(self.payload).hexdigest()
        self.manifest = self.root / "manifest.json"
        self.env = {
            **os.environ,
            "COMMIT_SHA": "a" * 40,
            "SOURCE_DATE_EPOCH": "1780000000",
            "VERSION": "v0.3.5",
            "CLEAN_REBUILD_SHA256": self.binary_hash,
            "CANDIDATE_ARTIFACT_ID": "1234",
            "CANDIDATE_ASSET_DIR": str(self.assets),
            "CONTRACT_NAME": "tempo-zone-linux-x86_64-reproducible",
            "CONTRACT_VERSION": "1",
            "MANIFEST": str(self.manifest),
            "RUNNER_TEMP": str(self.root),
            "GITHUB_OUTPUT": str(self.root / "outputs"),
        }

    def make_archive(self, *, mode=0o755, uid=0, gid=0, kind=tarfile.REGTYPE, duplicate=False):
        with tarfile.open(self.archive, "w:gz") as archive:
            member = tarfile.TarInfo(self.binary_name)
            member.mode, member.uid, member.gid, member.type = mode, uid, gid, kind
            member.size = len(self.payload) if kind == tarfile.REGTYPE else 0
            member.linkname = "target" if kind != tarfile.REGTYPE else ""
            archive.addfile(member, io.BytesIO(self.payload))
            if duplicate:
                archive.addfile(member, io.BytesIO(self.payload))
        self.archive_hash = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        Path(f"{self.archive}.sha256").write_text(f"{self.archive_hash}  {self.archive.name}\n")
        (self.assets / f"{self.binary_name}.sha256").write_text(
            f"{self.binary_hash}  {self.binary_name}\n"
        )

    def run_step(self, name):
        return subprocess.run(
            ["bash", "-c", step_script(name)],
            cwd=self.root, env=self.env, text=True, capture_output=True,
        )

    def test_prepared_archive_satisfies_verification_contract(self):
        binary = self.root / "out/tempo-zone"
        binary.parent.mkdir()
        binary.write_bytes(self.payload)
        binary.chmod(0o4777)
        result = self.run_step("Prepare release archive and checksums")
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in (self.archive.name, f"{self.archive.name}.sha256", f"{self.binary_name}.sha256"):
            shutil.copyfile(self.root / name, self.assets / name)
        with tarfile.open(self.archive, "r:gz") as archive:
            member = archive.getmembers()[0]
            self.assertEqual((member.uid, member.gid, member.mode), (0, 0, 0o755))
        result = self.run_step("Verify archived binary against clean rebuild")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_commit_dry_run_archive_and_manifest(self):
        self.env['VERSION'] = 'sha-abcdef0'
        self.binary_name = 'tempo-zone-sha-abcdef0-x86_64-unknown-linux-gnu'
        self.archive = self.assets / f'{self.binary_name}.tar.gz'
        self.test_prepared_archive_satisfies_verification_contract()
        manifest = json.loads(self.manifest.read_text())
        self.assertEqual(manifest['version'], 'sha-abcdef0')
        self.assertEqual(manifest['comparison_result'], 'success')
        self.assertEqual(manifest['candidate_binary_sha256'], manifest['clean_rebuild_binary_sha256'])

    def test_archive_gate_accepts_safe_binary_and_rejects_unsafe_headers(self):
        cases = [
            ({}, True),
            ({"mode": 0o4755}, False),
            ({"mode": 0o2755}, False),
            ({"mode": 0o777}, False),
            ({"uid": 1000}, False),
            ({"gid": 1000}, False),
            ({"kind": tarfile.SYMTYPE}, False),
            ({"kind": tarfile.LNKTYPE}, False),
            ({"duplicate": True}, False),
        ]
        for headers, accepted in cases:
            with self.subTest(headers=headers):
                shutil.rmtree(self.root / "canonical-linux-x86_64-extracted", ignore_errors=True)
                self.make_archive(**headers)
                result = self.run_step("Verify archived binary against clean rebuild")
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                manifest = json.loads(self.manifest.read_text())
                self.assertEqual(manifest["comparison_result"], "success" if accepted else "failed")
                if not accepted:
                    self.assertFalse((self.root / "canonical-linux-x86_64-extracted").exists())

    def prepare_publication(self):
        self.make_archive()
        result = self.run_step("Verify archived binary against clean rebuild")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.canonical = self.root / "artifacts/canonical"
        shutil.copytree(self.assets, self.canonical)
        self.published_manifest = self.root / "artifacts/verification/tempo-zone-linux-x86_64-verification.json"
        self.published_manifest.parent.mkdir(parents=True)
        shutil.copyfile(self.manifest, self.published_manifest)
        self.env["VERIFIED_ARCHIVE_SHA256"] = self.archive_hash

    def test_publication_uses_verified_checksums(self):
        self.prepare_publication()
        for name in (f"{self.binary_name}.sha256", f"{self.archive.name}.sha256"):
            (self.canonical / name).write_text("untrusted candidate checksum\n")
        result = self.run_step("Bind canonical assets to independent verification")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.canonical / f"{self.binary_name}.sha256").read_text(),
            f"{self.binary_hash}  {self.binary_name}\n",
        )
        self.assertEqual(
            (self.canonical / f"{self.archive.name}.sha256").read_text(),
            f"{self.archive_hash}  {self.archive.name}\n",
        )

    def test_publication_rejects_replaced_archive_or_verification(self):
        self.prepare_publication()
        # Even a self-consistent replacement archive/checksum cannot replace
        # the archive approved by the independent comparison job.
        replacement = self.canonical / self.archive.name
        replacement.write_bytes(b"replacement archive")
        (self.canonical / f"{self.archive.name}.sha256").write_text(
            f"{hashlib.sha256(replacement.read_bytes()).hexdigest()}  {self.archive.name}\n"
        )
        result = self.run_step("Bind canonical assets to independent verification")
        self.assertNotEqual(result.returncode, 0)
        shutil.copyfile(self.archive, replacement)
        verified = json.loads(self.manifest.read_text())
        for field in (
            "comparison_result", "commit_sha", "version", "candidate_artifact_id",
            "candidate_archive_sha256", "candidate_binary_sha256", "clean_rebuild_binary_sha256",
        ):
            with self.subTest(field=field):
                self.published_manifest.write_text(json.dumps({**verified, field: "replaced"}))
                result = self.run_step("Bind canonical assets to independent verification")
                self.assertNotEqual(result.returncode, 0)


def script(job, name):
    return next(step['run'] for step in PARSED_WORKFLOW['jobs'][job]['steps']
                if step.get('name') == name)


class ZonesReleaseTagTests(unittest.TestCase):
    def test_release_jobs_check_out_resolved_commit(self):
        for job in ('check-version', 'build-linux-x86_64-release',
                    'rebuild-linux-x86_64-release', 'build-other-release', 'create-release'):
            with self.subTest(job=job):
                checkout = next(step for step in PARSED_WORKFLOW['jobs'][job]['steps']
                                if step.get('uses', '').startswith('actions/checkout@'))
                self.assertEqual(checkout['with']['ref'],
                                 '${{ needs.resolve-release.outputs.commit_sha }}')

    def test_profiling_cannot_select_a_release_tag(self):
        dispatch = PROFILING_WORKFLOW.get('on', PROFILING_WORKFLOW.get(True))['workflow_dispatch']
        self.assertNotIn('inputs', dispatch or {})
        metadata = next(step for step in PROFILING_WORKFLOW['jobs']['build-and-push']['steps']
                        if step.get('id') == 'meta-tempo-zone')
        self.assertEqual(metadata['with']['tags'].splitlines(),
                         ['type=raw,value=profiling', 'type=sha,prefix=profiling-sha-'])

    def parse_tag(self, tag, dispatch=True, on_main=True, commit=False, requested_sha=None, ancestor=False,
                  use_head=False, release_prep=None):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'output'
            subprocess.run(['git', 'init', '-q', tmp], check=True)
            if release_prep:
                # Files on main, then their contents in a release commit off main.
                for path, (before, _) in release_prep.items():
                    (Path(tmp) / path).parent.mkdir(parents=True, exist_ok=True)
                    (Path(tmp) / path).write_text(before)
                subprocess.run(['git', '-C', tmp, 'add', '.'], check=True)
            subprocess.run(['git', '-C', tmp, '-c', 'user.name=Test',
                            '-c', 'user.email=test@example.invalid', 'commit',
                            '--allow-empty', '-qm', 'test: release fixture'], check=True)
            subprocess.run(['git', '-C', tmp, 'update-ref', 'refs/remotes/origin/main', 'HEAD'], check=True)
            if ancestor:
                original = subprocess.check_output(['git', '-C', tmp, 'rev-parse', 'HEAD'], text=True).strip()
                subprocess.run(['git', '-C', tmp, '-c', 'user.name=Test',
                                '-c', 'user.email=test@example.invalid', 'commit',
                                '--allow-empty', '-qm', 'test: advance main'], check=True)
                subprocess.run(['git', '-C', tmp, 'update-ref', 'refs/remotes/origin/main', 'HEAD'], check=True)
                subprocess.run(['git', '-C', tmp, 'checkout', '-q', original], check=True)
            if not on_main:
                for path, (_, after) in (release_prep or {}).items():
                    (Path(tmp) / path).write_text(after)
                subprocess.run(['git', '-C', tmp, 'add', '.'], check=True)
                subprocess.run(['git', '-C', tmp, '-c', 'user.name=Test',
                                '-c', 'user.email=test@example.invalid', 'commit',
                                '--allow-empty', '-qm', 'test: unmerged release'], check=True)
            if not commit:
                subprocess.run(['git', '-C', tmp, 'tag', tag], capture_output=True)
            sha = subprocess.check_output(['git', '-C', tmp, 'rev-parse', 'HEAD'], text=True).strip()
            result = subprocess.run(['bash', '-eu', '-c', script('resolve-release', 'Record immutable release inputs')],
                                    cwd=tmp, env=dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch' if dispatch else 'push', INPUT_TAG=tag if dispatch and not commit else '',
                                             INPUT_SHA=(requested_sha or sha) if commit and not use_head else '',
                                             GITHUB_SHA=(requested_sha or sha) if use_head else sha,
                                             GITHUB_REF=f'refs/tags/{tag}', GITHUB_OUTPUT=str(output)),
                                    text=True, capture_output=True)
            return result.returncode, output.read_text() if output.exists() else ''

    def test_zones_tags_keep_separate_ref_and_filename_version(self):
        for tag in ('zones/v0.3.5', 'zones/v0.3.5-rc.1'):
            for dispatch in (True, False):
                with self.subTest(tag=tag, dispatch=dispatch):
                    code, output = self.parse_tag(tag, dispatch)
                    self.assertEqual(code, 0)
                    values = dict(line.split('=', 1) for line in output.splitlines())
                    self.assertEqual(values['tag'], tag)
                    self.assertEqual(values['version'], tag[6:])
                    self.assertEqual(len(values['commit_sha']), 40)

    def test_rejects_tempo_tags_branches_and_invalid_versions(self):
        for tag in ('v1.16.0', 'main', 'zones/main', 'zones/v0.3', 'zones/v0.3.5/other',
                    'zones/v0.3.5\ntag=other'):
            with self.subTest(tag=tag):
                code, output = self.parse_tag(tag)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, '')

    def test_rejects_release_tag_outside_main(self):
        for dispatch in (True, False):
            with self.subTest(dispatch=dispatch):
                code, output = self.parse_tag('zones/v0.3.5', dispatch, on_main=False)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, '')

    def test_accepts_zones_version_bump_on_main(self):
        manifest = '[package]\nname = "tempo-zone"\nversion = "{}"\n'
        release_prep = {
            'bin/tempo-zone/Cargo.toml': (manifest.format('0.3.7'), manifest.format('0.3.8')),
            'Cargo.lock': ('[[package]]\nname = "tempo-zone"\nversion = "0.3.7"\n',
                           '[[package]]\nname = "tempo-zone"\nversion = "0.3.8"\n'),
        }
        for dispatch in (True, False):
            with self.subTest(dispatch=dispatch):
                code, output = self.parse_tag('zones/v0.3.8', dispatch, on_main=False, release_prep=release_prep)
                self.assertEqual(code, 0)
                self.assertIn('tag=zones/v0.3.8', output)

    def test_rejects_version_bump_with_other_changes_outside_main(self):
        manifest = '[package]\nname = "tempo-zone"\nversion = "{}"\n'
        for name, release_prep in {
            'other file': {
                'bin/tempo-zone/Cargo.toml': (manifest.format('0.3.7'), manifest.format('0.3.8')),
                'build.rs': ('', 'fn main() {}\n'),
            },
            'other line': {
                'bin/tempo-zone/Cargo.toml': (manifest.format('0.3.7'),
                                              manifest.format('0.3.8') + 'build = "build.rs"\n'),
            },
        }.items():
            with self.subTest(name=name):
                code, output = self.parse_tag('zones/v0.3.8', on_main=False, release_prep=release_prep)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, '')

    def test_commit_dry_run_input_validation(self):
        cases = [
            ("", "a" * 40, "true", True),
            ("zones/v0.3.5", "", "true", True),
            ("zones/v0.3.5", "", "false", True),
            ("", "a" * 40, "false", False),
            ("zones/v0.3.5", "a" * 40, "true", False),
            ("", "main", "true", False),
            ("", "a" * 7, "true", False),
            ("", "A" * 40, "true", False),
            ("", "", "true", True),
            ("", "", "false", False),
        ]
        for tag, sha, dry_run, accepted in cases:
            with self.subTest(tag=tag, sha=sha, dry_run=dry_run):
                result = subprocess.run(
                    ['bash', '-eu', '-c', script('resolve-release', 'Validate commit dry-run inputs')],
                    env=dict(os.environ, INPUT_TAG=tag, INPUT_SHA=sha, DRY_RUN=dry_run),
                    text=True, capture_output=True,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_commit_dry_run_resolves_without_a_tag(self):
        code, output = self.parse_tag('', commit=True)
        self.assertEqual(code, 0)
        values = dict(line.split('=', 1) for line in output.splitlines())
        self.assertEqual(values['tag'], '')
        self.assertTrue(values['version'].startswith('sha-'))
        self.assertTrue(values['commit_sha'].startswith(values['version'][4:]))
        self.assertTrue(values['source_date_epoch'].isdigit())

    def test_commit_dry_run_without_sha_uses_dispatched_head(self):
        code, output = self.parse_tag('', commit=True, use_head=True)
        self.assertEqual(code, 0)
        values = dict(line.split('=', 1) for line in output.splitlines())
        self.assertEqual(values['tag'], '')
        self.assertTrue(values['version'].startswith('sha-'))
        self.assertTrue(values['commit_sha'].startswith(values['version'][4:]))

    def test_commit_dry_run_accepts_an_ancestor_of_main(self):
        code, output = self.parse_tag('', commit=True, ancestor=True)
        self.assertEqual(code, 0)
        self.assertIn('version=sha-', output)

    def test_commit_dry_run_rejects_unmerged_or_mismatched_source(self):
        for options in ({'on_main': False}, {'requested_sha': 'a' * 40},
                        {'on_main': False, 'use_head': True}, {'requested_sha': 'a' * 40, 'use_head': True}):
            with self.subTest(options=options):
                code, output = self.parse_tag('', commit=True, **options)
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

    def test_all_accepted_prerelease_suffixes_create_prerelease_drafts(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = Path(tmp) / 'args'
            for version in ('v0.3.5', 'v0.3.5-rc.1', 'v0.3.5-preview.1'):
                with self.subTest(version=version):
                    subprocess.run(['bash', '-eu', '-c', script('create-release', 'Create Release').split('assets=()', 1)[0] + '\nprintf \'%s\\n\' \"$prerelease\" > \"$ARGS_FILE\"'],
                                   env=dict(os.environ, VERSION=version, TAG='zones/' + version,
                                            ARGS_FILE=str(args), PATH=f'{tmp}:{os.environ["PATH"]}'),
                                   check=True, capture_output=True)
                    self.assertEqual('--prerelease' in args.read_text().splitlines(), '-' in version)


if __name__ == "__main__":
    unittest.main()
