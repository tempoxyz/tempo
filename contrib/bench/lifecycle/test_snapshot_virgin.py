"""Disposable regular-file ext4 only. Production block-device admission is separately tested."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import snapshot_inventory as m


class Parser(unittest.TestCase):
    def test_status_zero_alone_never_establishes_missing_or_presence(self):
        version=b'debugfs 1.47.0 (5-Feb-2023)\n'
        valid=b'Inode: 12   Type: regular    Mode:  0644   Flags: 0x80000\n'
        self.assertEqual(m.inode_status((valid,version),'/known','regular'),'present')
        self.assertEqual(m.inode_status((b'',version+b'/known: File not found by ext2_lookup \n'),'/known','regular'),'missing')
        for output in [None,(b'',version),(valid,version+b'checksum failure\n'),
                       (b'',version+b'Filesystem not open\n'),(b'',version+b'/other: File not found by ext2_lookup\n'),
                       (b'garbage',version)]:
            self.assertEqual(m.inode_status(output,'/known','regular'),'unavailable')
        self.assertEqual(m.inode_status((valid.replace(b'regular',b'symlink'),version),'/known','regular'),'unsafe')

    def test_unprivileged_probe_never_opens_device_or_lock(self):
        with patch.object(m.os,'geteuid',return_value=1000),patch.object(m,'trusted_fd',side_effect=AssertionError()):
            result=m.virgin_inventory(Path('/unused'),Path('/mount'),time.monotonic()+1)
        self.assertEqual(result['status'],1)
        self.assertEqual(result['required']['unavailable'],511)

    def test_trusted_admission_rejects_regular_file_as_device_and_writable_ancestor(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.touch()
            # The fixture's user-owned ancestor is intentionally untrusted.
            with self.assertRaises(ValueError):m.trusted_fd(p,os.O_RDONLY,block=True)

    def test_actual_admission_control_flow_requires_distinct_block_devices(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);state=root/'a.json';lock=root/'schelk.lock';lock.touch()
            state.write_text(json.dumps(dict(is_mounted=False,mount_point='/expected',fstype='ext4',virgin='/dev/probe-virgin',scratch='/dev/probe-scratch')))
            backing=root/'backing';backing.touch()
            original_stat=os.fstat;original_resolve=Path.resolve;original_read=Path.read_text
            for same in (False,True):
                device_fds={};opened=[]
                def fake_open(path,flags,block=False):
                    self.assertEqual(flags,os.O_RDONLY)
                    fd=os.open(backing if block else path,flags);opened.append(fd)
                    if block:device_fds[fd]=os.makedev(240,190 if same or str(path).endswith('virgin') else 191)
                    return fd
                def fake_stat(fd):
                    if fd in device_fds:return SimpleNamespace(st_mode=stat.S_IFBLK|0o660,st_rdev=device_fds[fd],st_uid=0)
                    return original_stat(fd)
                def resolve(path,*args,**kwargs):
                    return path if str(path).startswith('/dev/probe-') else original_resolve(path,*args,**kwargs)
                def read(path,*args,**kwargs):
                    return '' if str(path)=='/proc/self/mountinfo' else original_read(path,*args,**kwargs)
                with patch.object(m.os,'geteuid',return_value=0),patch.object(m,'trusted_fd',side_effect=fake_open),patch.object(m.os,'fstat',side_effect=fake_stat),patch.object(Path,'resolve',resolve),patch.object(Path,'read_text',read),patch.object(m,'virgin_masks',return_value=dict(present=511,missing=0,unsafe=0,unavailable=0)) as probe:
                    result=m.virgin_inventory(state,Path('/expected'),time.monotonic()+1)
                self.assertEqual(result['status'],4 if same else 0)
                self.assertEqual(probe.call_count,0 if same else 1)
                for fd in opened:
                    with self.assertRaises(OSError):original_stat(fd)

    def test_parent_symlink_marks_all_unknown_target_paths_unsafe_without_following(self):
        with patch.object(m,'bounded_debugfs',return_value=(b'Inode: 12   Type: symlink    Mode:  0777   Flags: 0x0\n',b'debugfs 1.47.0 (5-Feb-2023)\n')) as calls:
            result=m.virgin_masks('/tool',1,time.monotonic()+1)
        self.assertEqual(result,dict(present=0,missing=0,unsafe=511,unavailable=0));self.assertEqual(calls.call_count,1)

    def test_child_timeout_and_output_cap_are_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);tool=root/'probe';fd=os.open('/dev/null',os.O_RDONLY)
            try:
                for text in ['#!/bin/sh\nsleep 5\n', '#!/usr/bin/python3\nimport sys\nsys.stdout.write("x"*70000)\n', '#!/bin/sh\nexit 3\n']:
                    tool.write_text(text);tool.chmod(0o755)
                    self.assertIsNone(m.bounded_debugfs(str(tool),fd,'stat /fixed',time.monotonic()+0.1))
            finally:os.close(fd)


@unittest.skipUnless(Path('/usr/sbin/debugfs').is_file() and shutil.which('mkfs.ext4'), 'local ext4 tools unavailable')
class Ext4Fixture(unittest.TestCase):
    def test_actual_read_only_ext4_present_missing_unsafe_and_corrupt(self):
        with tempfile.TemporaryDirectory(prefix='virgin-stat-test-') as d:
            root=Path(d);tree=root/'tree';tree.mkdir();dataset=tree/m.DATASET
            for name in m.REQUIRED:
                p=dataset/name;p.parent.mkdir(parents=True,exist_ok=True)
                if name in ('db','static_files'):p.mkdir()
                else:p.touch()
            (dataset/'signing.key').unlink()
            (dataset/'enode.key').unlink();(dataset/'enode.key').symlink_to('signing.share')
            image=root/'ext4.img'
            with image.open('wb') as output:output.truncate(16*1024*1024)
            subprocess.run([shutil.which('mkfs.ext4'),'-q','-F','-d',str(tree),str(image)],check=True,capture_output=True,timeout=10)
            before=hashlib.sha256(image.read_bytes()).hexdigest();fd=os.open(image,os.O_RDONLY)
            try:result=m.virgin_masks('/usr/sbin/debugfs',fd,time.monotonic()+10)
            finally:os.close(fd)
            self.assertEqual(result,dict(present=511-(1<<3)-(1<<5),missing=1<<3,unsafe=1<<5,unavailable=0))
            self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),before)
            invalid=root/'invalid';invalid.write_bytes(b'not a filesystem');fd=os.open(invalid,os.O_RDONLY)
            try:result=m.virgin_masks('/usr/sbin/debugfs',fd,time.monotonic()+2)
            finally:os.close(fd)
            self.assertEqual(result,dict(present=0,missing=0,unsafe=0,unavailable=511))


if __name__=='__main__':unittest.main()
