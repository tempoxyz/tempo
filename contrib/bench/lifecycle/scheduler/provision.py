"""Provision only opt-in scheduler dependencies; emit closed diagnostics only."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).parent
PYTHON = '/usr/bin/python3'
IMPORT = ['sudo', '-n', PYTHON, '-c', 'from bcc import BPF']
API = ['sudo', '-n', PYTHON, '-c',
       'import sys; from bcc import BPF; from bcc.table import _RINGBUF_CB_TYPE; '
       'assert sys.byteorder == "little"; assert hasattr(BPF, "_open_ring_buffer"); '
       'assert hasattr(BPF, "ring_buffer_consume")']
NATIVE = ['sudo', '-n', PYTHON, '-c',
          'import sys,tempfile; sys.path.insert(0,sys.argv[1]); '
          'from binary_capture import prepare_native; '
          'directory=tempfile.TemporaryDirectory(); prepare_native(directory.name); directory.cleanup()', str(ROOT)]
BPF_COMPILE = ['sudo', '-n', PYTHON, '-c',
               'from bcc import BPF; BPF(text="int probe(void *ctx) { return 0; }")']
CATEGORIES = {
    'scheduler_setup_ready': 'Scheduler BCC dependencies and compiler checks passed.',
    'scheduler_setup_skipped': 'Scheduler setup skipped outside scheduler mode.',
    'scheduler_setup_root': 'Scheduler setup requires passwordless root access.',
    'scheduler_setup_package_manager': 'Scheduler dependencies are missing; this host requires a supported distro package manager.',
    'scheduler_setup_packages': 'Scheduler dependency installation failed; check runner capacity and distro package availability.',
    'scheduler_setup_bcc_import': 'Distro Python cannot import BCC after provisioning.',
    'scheduler_setup_native_compile': 'The scheduler native collector cannot compile with the available C toolchain.',
    'scheduler_setup_bcc_api': 'The installed BCC API or host byte order is unsupported.',
    'scheduler_setup_bpf_compile': 'BCC cannot compile BPF on this kernel; kernel development files or capabilities are unavailable.',
}


def command(argv, timeout=120):
    try:
        # Root compiler probes use this job's owned scratch, including on cancellation.
        if os.environ.get('BENCH_RUN_CLEANUP') == 'true' and argv[:2] == ['sudo', '-n']:
            argv = argv[:2] + ['env', 'TMPDIR=' + os.environ['TMPDIR']] + argv[2:]
        return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def setup(environment, run=command, package_manager=Path('/usr/bin/apt-get')):
    if environment.get('BENCH_LIFECYCLE_SCHEDULER') != 'true':
        return 'scheduler_setup_skipped'
    if not run(['sudo', '-n', 'true']):
        return 'scheduler_setup_root'
    imported, compiled = run(IMPORT), run(NATIVE)
    packages = ([] if imported else ['python3-bpfcc', 'libbpfcc']) + ([] if compiled else ['gcc', 'libc6-dev'])
    if packages:
        if not package_manager.is_file():
            return 'scheduler_setup_package_manager'
        # needrestart may report pending restarts, but must not restart services.
        prefix = ['sudo', '-n', 'env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=l', str(package_manager)]
        if not run(prefix + ['-qq', 'update']) or not run(prefix + [
            '-qq', 'install', '-y', '--no-install-recommends', '-o', 'Dpkg::Options::=--force-confold', *packages], timeout=300):
            return 'scheduler_setup_packages'
    if not run(IMPORT):
        return 'scheduler_setup_bcc_import'
    if not run(NATIVE):
        return 'scheduler_setup_native_compile'
    if not run(API):
        return 'scheduler_setup_bcc_api'
    if not run(BPF_COMPILE):
        return 'scheduler_setup_bpf_compile'
    return 'scheduler_setup_ready'


def main():
    category = setup(os.environ)
    print(f'{category}: {CATEGORIES[category]}')
    return 0 if category in ('scheduler_setup_ready', 'scheduler_setup_skipped') else 1


if __name__ == '__main__':
    raise SystemExit(main())
