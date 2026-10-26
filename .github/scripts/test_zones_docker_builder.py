"""Run with RUN_DOCKER_TESTS=1 python3 -m unittest discover -s .github/scripts -p test_zones_docker_builder.py.

Exercise BuildKit's real stage graph and shell commands without compiling Rust or
Solidity. Only external base images/toolchains are replaced; RUN/COPY, cache mounts,
ARG inheritance, version validation and final entrypoints come from the Dockerfile.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('RUN_DOCKER_TESTS') == '1', 'requires local Docker/BuildKit')
class DockerBuilderTests(unittest.TestCase):
    @classmethod
    def docker(cls, *args, check=True):
        result = subprocess.run(['docker', *args], text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        if check and result.returncode:
            raise AssertionError(result.stdout)
        return result

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='zones-docker-test-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.context = Path(cls.tmp.name) / 'context'
        cls.context.mkdir()
        cls.archive = Path(cls.tmp.name) / 'image.tar'
        cls.fixture = 'zones-builder-test:' + Path(cls.tmp.name).name
        cls.result_image = cls.fixture + '-result'
        cls.addClassCleanup(cls.docker, 'image', 'rm', '-f', cls.fixture,
                            cls.result_image, check=False)
        # The classic image store requires loading before saving; containerd can
        # export directly, avoiding unnecessary (and potentially flaky) unpacking.
        status = json.loads(cls.docker('info', '--format', '{{json .DriverStatus}}').stdout)
        cls.direct_export = ['driver-type', 'io.containerd.snapshotter.v1'] in (status or [])
        source = (ROOT / 'zones/docker/Dockerfile').read_text()
        base = re.search(r'^FROM (debian:\S+)', source, re.M).group(1)
        # Reject unexpected binaries, so visiting the other compile branch fails.
        stub = cls.context / 'stub'
        stub.write_text(r'''#!/bin/sh
set -eu
case "$(basename "$0")" in
  cargo)
    command="$*"
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --bin) binary="$2"; shift ;;
        --profile) profile="$2"; shift ;;
      esac
      shift
    done
    test "$binary" = "$(cat /app/expected-binary)"
    mkdir -p "/app/target/$profile"
    printf '#!/bin/sh\nprintf "%%s\\n" "%s fixture-sha" "%s" "%s"\n' \
      "$binary" "$command" "$RUSTFLAGS" > "/app/target/$profile/$binary"
    chmod +x "/app/target/$profile/$binary"
    ;;
  forge) mkdir -p out; echo contract-fixture > out/fixture.json ;;
esac
''')
        stub.chmod(0o755)
        fixture_dockerfile = cls.context / 'Fixture.Dockerfile'
        fixture_dockerfile.write_text(f'''FROM {base}
COPY stub /usr/local/bin/cargo
RUN for cmd in apt-get curl forge jq; do cp /usr/local/bin/cargo /usr/local/bin/$cmd; done \\
    && mkdir -p /root/.foundry/bin \\
    && cp /usr/local/bin/cargo /root/.foundry/bin/foundryup \\
    && cp /usr/local/bin/cargo /root/.foundry/bin/cast
ENV SCCACHE_DIR=/sccache
WORKDIR /app
''')
        cls.docker('build', '--network=none', '--provenance=false', '-f', str(fixture_dockerfile), '-t', cls.fixture, str(cls.context))
        (cls.context / 'Dockerfile').write_text(re.sub(
            r'^FROM debian:\S+', f'FROM {cls.fixture}', source, flags=re.M))
        (cls.context / 'crates/zones/contracts').mkdir(parents=True)

    def build(self, binary, profile=None, sha='fixture-sha'):
        (self.context / 'expected-binary').write_text(binary)
        args = ['build', '--network=none', '--provenance=false', '--no-cache', '--progress=plain', '--target', binary,
                '--build-arg', f'CHEF_IMAGE={self.fixture}',
                '--build-arg', f'VERGEN_GIT_SHA={sha}',
                '--build-arg', 'EXTRA_RUSTFLAGS=-C debuginfo=1']
        args += (['--output', f'type=docker,dest={self.archive}'] if self.direct_export
                 else ['-t', self.result_image])
        if profile:
            args += ['--build-arg', f'RUST_PROFILE={profile}']
        result = self.docker(*args, str(self.context), check=False)
        if result.returncode == 0 and not self.direct_export:
            self.docker('image', 'save', '-o', str(self.archive), self.result_image)
        return result

    def read_image(self):
        # Inspect the exported image without running fixture containers.
        # Keep only our fixture files; never extract an image filesystem onto the host.
        files = {}
        with tarfile.open(self.archive) as image:
            manifest = json.load(image.extractfile('manifest.json'))[0]
            config = json.load(image.extractfile(manifest['Config']))['config']
            for layer in manifest['Layers']:
                with tarfile.open(fileobj=image.extractfile(layer), mode='r|*') as contents:
                    for member in contents:
                        path = member.name.removeprefix('./')
                        if member.isfile() and (path.startswith('usr/local/bin/') or
                                               path.endswith('/out/fixture.json')):
                            files[path] = (member.mode, contents.extractfile(member).read())
        return config, files

    def test_each_image_builds_only_its_binary_and_keeps_runtime_layout(self):
        for binary, entrypoint, workdir in (
            ('tempo-zone', '/usr/local/bin/tempo-zone', '/data'),
            ('tempo-zone-xtask', '/usr/local/bin/tempo-xtask', '/app'),
        ):
            for profile in (None, 'release'):
                with self.subTest(binary=binary, profile=profile):
                    result = self.build(binary, profile)
                    self.assertEqual(result.returncode, 0, result.stdout)
                    config, files = self.read_image()
                    self.assertEqual(config['Entrypoint'], [entrypoint])
                    self.assertEqual(config['WorkingDir'], workdir)
                    mode, script = files[entrypoint.lstrip('/')]
                    self.assertTrue(mode & 0o111)
                    output = subprocess.run(['sh', '-s', '--', '--version'], input=script.decode(),
                                            text=True, capture_output=True, check=True).stdout.splitlines()
                    features = ' --features jemalloc' if binary == 'tempo-zone' else ''
                    self.assertEqual(output, [f'{binary} fixture-sha',
                        f'build --locked --profile {profile or "profiling"} --bin {binary}{features}',
                        '-C link-arg=-fuse-ld=mold -C debuginfo=1'])
                    if binary == 'tempo-zone-xtask':
                        for command in ('cast', 'jq'):
                            self.assertTrue(files[f'usr/local/bin/{command}'][0] & 0o111)
                        self.assertNotIn('usr/local/bin/tempo-zone', files)
                        self.assertEqual(files['app/crates/zones/contracts/out/fixture.json'][1],
                                         b'contract-fixture\n')

    def test_node_rejects_wrong_provenance_but_xtask_does_not_run_node_check(self):
        for binary, success in (('tempo-zone', False), ('tempo-zone-xtask', True)):
            with self.subTest(binary=binary):
                result = self.build(binary, sha='wrong-sha')
                self.assertEqual(result.returncode == 0, success, result.stdout)
                if not success:
                    self.assertIn('grep -F', result.stdout)


if __name__ == '__main__':
    unittest.main()
