"""Exercise publication gates with independent executable/image fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
IMAGES = ('tempo', 'tempo-devnet', 'tempo-localnet', 'tempo-sidecar', 'tempo-xtask')


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        commands = self.work / 'bin'
        commands.mkdir()
        docker = commands / 'docker'
        docker.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FIXTURE/docker.log"
case "$1" in
  load|rm|tag) ;;
  create) printf '%s\\n' "${@: -1}" ;;
  cp)
    image="${2%%:*}"
    arch="${2#*:candidate-}"; arch="${arch%%:*}"
    binary="${2##*/}"
    source="$FIXTURE/payloads/$arch/$image/$binary"
    cp "$source" "$3"
    ;;
  push) printf 'sha256:%064d\\n' 1 ;;
  buildx)
    if [[ "$3" == inspect ]]; then printf 'sha256:%064d\\n' 2; fi
    ;;
  *) exit 80 ;;
esac
''')
        docker.chmod(0o755)
        self.env = {**os.environ, 'PATH': f'{commands}:{os.environ["PATH"]}',
                    'IMAGE_DIR': str(self.work), 'FIXTURE': str(self.work),
                    'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_ID': '123',
                    'GITHUB_OUTPUT': str(self.work / 'outputs')}
        for image in IMAGES:
            self.env[image.upper().replace('-', '_') + '_TAGS'] = (
                f'ghcr.io/tempoxyz/{image}:sha-abc\n'
                f'docker.io/tempoxyz/{image}:sha-abc')
        for arch in ('amd64', 'arm64'):
            candidate = self.work / f'docker-candidate-{arch}-1'
            candidate.mkdir()
            clean = self.work / f'docker-clean-{arch}-1'
            clean.mkdir()
            sums = []
            for image in IMAGES:
                payload = f'{image}-{arch}'.encode()
                directory = self.work / 'payloads' / arch / image
                directory.mkdir(parents=True)
                binary = 'tempo' if image == 'tempo-devnet' else image
                (directory / binary).write_bytes(payload)
                if image == 'tempo-localnet':
                    (directory / 'tempo').write_bytes(f'tempo-{arch}'.encode())
                (candidate / f'{image}.tar').write_bytes(payload)
                sums.append(f'{hashlib.sha256(payload).hexdigest()}  {image}\n')
            devnet = self.work / f'docker-clean-devnet-{arch}-1'
            devnet.mkdir()
            (devnet / 'clean.sha256').write_text(''.join(line for line in sums if line.endswith('  tempo-devnet\n')))
            (clean / 'clean.sha256').write_text(''.join(line for line in sums if not line.endswith('  tempo-devnet\n')))

    def run_script(self, script):
        return subprocess.run(['bash', str(ROOT / 'scripts' / script)], env=self.env,
                              capture_output=True, text=True)

    def verify(self):
        return self.run_script('verify-docker-rebuild.sh')

    def assert_no_publication(self):
        log = (self.work / 'docker.log').read_text() if (self.work / 'docker.log').exists() else ''
        self.assertFalse(any(line.startswith(('push ', 'buildx imagetools create'))
                             for line in log.splitlines()), log)

    def test_matching_executables_promote_without_building(self):
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = self.run_script('publish-verified-images.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        log = (self.work / 'docker.log').read_text().splitlines()
        self.assertEqual(sum(line.startswith('push ') for line in log), 20)
        self.assertEqual(sum(line.startswith('buildx imagetools create') for line in log), 10)
        self.assertFalse(any(line.startswith(('build ', 'buildx build')) for line in log))
        self.assertTrue((self.work / 'outputs').read_text().startswith('metadata={'))

    def test_each_mismatched_executable_blocks_publication(self):
        for arch in ('amd64', 'arm64'):
            for image in IMAGES:
                with self.subTest(arch=arch, image=image):
                    binary = 'tempo' if image == 'tempo-devnet' else image
                    path = self.work / 'payloads' / arch / image / binary
                    original = path.read_bytes()
                    path.write_bytes(b'tampered')
                    self.assertNotEqual(self.verify().returncode, 0)
                    self.assertFalse((self.work / 'verified.sha256').exists())
                    path.write_bytes(original)
        self.assert_no_publication()

    def test_localnet_embedded_node_is_also_verified(self):
        (self.work / 'payloads/amd64/tempo-localnet/tempo').write_bytes(b'tampered')
        self.assertNotEqual(self.verify().returncode, 0)
        self.assert_no_publication()

    def test_missing_independent_result_blocks_publication(self):
        (self.work / 'docker-clean-arm64-1/clean.sha256').unlink()
        self.assertNotEqual(self.verify().returncode, 0)
        self.assert_no_publication()

    def test_promotion_without_verification_fails(self):
        self.assertNotEqual(self.run_script('publish-verified-images.sh').returncode, 0)
        self.assert_no_publication()

    def test_archive_changed_after_comparison_blocks_publication(self):
        self.assertEqual(self.verify().returncode, 0)
        (self.work / 'docker-candidate-arm64-1/tempo.tar').write_bytes(b'tampered')
        self.assertNotEqual(self.run_script('publish-verified-images.sh').returncode, 0)
        self.assert_no_publication()

    def test_missing_devnet_result_blocks_publication(self):
        (self.work / 'docker-clean-devnet-arm64-1/clean.sha256').unlink()
        self.assertNotEqual(self.verify().returncode, 0)
        self.assert_no_publication()

    def test_missing_checksum_entry_blocks_publication(self):
        (self.work / 'docker-clean-amd64-1/clean.sha256').write_text('')
        self.assertNotEqual(self.verify().returncode, 0)
        self.assert_no_publication()

    def test_prepared_attempt_can_differ_from_promotion_attempt(self):
        self.env.update(GITHUB_RUN_ATTEMPT='2', ARTIFACT_RUN_ATTEMPT='1')
        self.assertEqual(self.verify().returncode, 0)
        result = self.run_script('publish-verified-images.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_prepared_run_requires_successful_same_workflow_and_commit(self):
        gh = self.work / 'bin/gh'
        gh.write_text('#!/usr/bin/env bash\nprintf \'%s\\n\' "$PREPARED_FIXTURE"\n')
        gh.chmod(0o755)
        sha = 'a' * 40
        self.env.update(PREPARED_RUN_ID='456', SOURCE_SHA=sha,
                        GITHUB_REPOSITORY='tempoxyz/tempo',
                        WORKFLOW_PATH='.github/workflows/docker.yml')
        valid = dict(status='completed', conclusion='success', head_sha=sha,
                     path='.github/workflows/docker.yml', run_attempt=2,
                     head_repository=dict(full_name='tempoxyz/tempo'), event='workflow_dispatch')
        self.env['PREPARED_FIXTURE'] = json.dumps(valid)
        result = self.run_script('validate-prepared-run.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / 'outputs').read_text(),
                         'artifact_run_id=456\nartifact_attempt=2\n')
        for invalid in (dict(conclusion='failure'), dict(status='in_progress'),
                        dict(head_sha='b' * 40), dict(path='.github/workflows/test.yml'),
                        dict(head_repository=dict(full_name='attacker/tempo')),
                        dict(event='pull_request'), dict(run_attempt=0)):
            with self.subTest(invalid=invalid):
                (self.work / 'outputs').unlink(missing_ok=True)
                self.env['PREPARED_FIXTURE'] = json.dumps({**valid, **invalid})
                self.assertNotEqual(self.run_script('validate-prepared-run.sh').returncode, 0)
                self.assertFalse((self.work / 'outputs').exists())

    def test_prepared_release_rejects_wrong_version_profile_or_source(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        step = workflow.split('      - name: Validate prepared release identity\n')[1]
        script = step.split('        run: |\n')[1].split('\n      - name:')[0]
        script = '\n'.join(line.removeprefix('          ') for line in script.splitlines())
        manifest = self.work / 'release-preparation/manifest.json'
        manifest.parent.mkdir()
        valid = dict(sha='a' * 40, version='v1.2.3', macos_profile='maxperf', dry_run=True)
        env = {**self.env, 'ARTIFACT_DIR': str(self.work), 'SOURCE_SHA': valid['sha'],
               'VERSION': 'v1.2.3', 'MACOS_PROFILE': 'maxperf'}
        manifest.write_text(json.dumps(valid))
        result = subprocess.run(['bash', '-e', '-c', script], env=env, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for invalid in (dict(sha='b' * 40), dict(version='v1.2.4'),
                        dict(macos_profile='profiling'), dict(dry_run=False)):
            with self.subTest(invalid=invalid):
                manifest.write_text(json.dumps({**valid, **invalid}))
                result = subprocess.run(['bash', '-e', '-c', script], env=env, capture_output=True)
                self.assertNotEqual(result.returncode, 0)

    def test_tag_selects_completed_preparation_or_falls_back(self):
        gh = self.work / 'bin/gh'
        gh.write_text('''#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *actions/workflows/*) printf '%s\\n' "$PREPARED_RUNS" ;;
  *'/artifacts?'*) printf '%s\\n' "$PREPARED_ARTIFACTS" ;;
  'api repos/'*) printf '%s\\n' "$PREPARED_FIXTURE" ;;
  'run download '*) printf '%s\\n' "$PREPARED_MANIFEST" > "${@: -1}/manifest.json" ;;
  *) exit 80 ;;
esac
''')
        gh.chmod(0o755)
        sha = 'a' * 40
        self.env.update(PREPARED_RUN_ID='', AUTO_REUSE='true', SOURCE_SHA=sha,
                        GITHUB_REPOSITORY='tempoxyz/tempo', VERSION='v1.2.3',
                        MACOS_PROFILE='maxperf', WORKFLOW_PATH='.github/workflows/docker.yml')
        valid = dict(status='completed', conclusion='success', head_sha=sha,
                     path='.github/workflows/docker.yml', run_attempt=2,
                     head_repository=dict(full_name='tempoxyz/tempo'), event='workflow_dispatch')
        self.env['PREPARED_FIXTURE'] = json.dumps(valid)
        self.env['PREPARED_RUNS'] = json.dumps(dict(workflow_runs=[dict(id=456)]))
        self.env['PREPARED_ARTIFACTS'] = '\n'.join(
            f'docker-{mode}-{arch}-2' for mode in ('candidate', 'clean', 'clean-devnet')
            for arch in ('amd64', 'arm64'))
        result = self.run_script('select-prepared-run.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / 'outputs').read_text(),
                         'artifact_run_id=456\nartifact_attempt=2\nprepared_run_id=456\n')
        (self.work / 'outputs').unlink()
        self.env['PREPARED_ARTIFACTS'] = ''
        result = self.run_script('select-prepared-run.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.work / 'outputs').exists())

        self.env['WORKFLOW_PATH'] = valid['path'] = '.github/workflows/release.yml'
        self.env['PREPARED_FIXTURE'] = json.dumps(valid)
        manifest = dict(sha=sha, version='v1.2.3', macos_profile='maxperf', dry_run=True)
        for version, expected in (('v1.2.3', True), ('v1.2.4', False)):
            with self.subTest(version=version):
                (self.work / 'outputs').unlink(missing_ok=True)
                self.env['PREPARED_MANIFEST'] = json.dumps({**manifest, 'version': version})
                result = self.run_script('select-prepared-run.sh')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.work / 'outputs').exists(), expected)

    def test_release_compares_archived_bytes(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        script = workflow.split('      - name: Verify actual archived executables\n')[1]
        script = script.split('        run: |\n')[1].split('\n      - name: Record prepared release identity')[0]
        script = '\n'.join(line.removeprefix('          ') for line in script.splitlines())
        for binary in ('tempo', 'tempo-sidecar'):
            for target in ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'):
                name = f'{binary}-v1.2.3-{target}'
                assets = self.work / f'{binary}-{target}'
                assets.mkdir()
                executable = assets / name
                executable.write_bytes(f'{binary}-{target}'.encode())
                digest = hashlib.sha256(executable.read_bytes()).hexdigest()
                with tarfile.open(assets / f'{name}.tar.gz', 'w:gz') as archive:
                    archive.add(executable, arcname=name)
                (assets / f'{name}.sha256').write_text(f'{digest}  {name}\n')
                clean = self.work / f'clean-{binary}-{target}'
                clean.mkdir()
                (clean / 'clean.sha256').write_text(f'{digest}  {binary}\n')
        env = {**self.env, 'ARTIFACT_DIR': str(self.work), 'VERSION': 'v1.2.3'}
        result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        checksum = self.work / 'clean-tempo-aarch64-unknown-linux-gnu/clean.sha256'
        checksum.write_text('0' * 64 + '  tempo\n')
        result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
