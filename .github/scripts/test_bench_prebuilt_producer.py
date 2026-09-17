import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import time
import tracemalloc
import unittest
from unittest.mock import patch

ROOT=Path(__file__).parent
spec=importlib.util.spec_from_file_location('producer',ROOT/'bench-prebuilt-producer.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


def fixture():
    dynamic=dict(elf_class=64,machine=62,little_endian=True,loader='glibc_x86_64',
                 needed=['libc.so.6'],versions={'libc.so.6':['GLIBC_2.2.5','GLIBC_2.34']})
    binary={}
    for role in p.ROLES:
        binary[role]=dict(source_repository='tempoxyz/tempo' if role=='tempo' else 'tempoxyz/txgen',
            source_sha=p.RUNTIME if role=='tempo' else p.TOOLS,source_tree='a'*40,
            cargo_toml_sha256='b'*64,cargo_lock_sha256='c'*64,
            profile='profiling' if role=='tempo' else 'release',default_features=role!='tempo',
            features=p.FEATURES if role=='tempo' else [],rustflags=p.RUSTFLAGS,cflags=p.CFLAGS,
            cxxflags=p.CFLAGS,bytes=100,sha256='d'*64,abi=copy.deepcopy(dynamic))
    return dict(path_remap='owned_source_build_toolchain_v1',native_flags_guard='reject_host_native_v1',
        schema=1,build_contract='x86_64_v3_locked_v1',producer_repository='tempoxyz/tempo',
        producer_workflow_path=p.WORKFLOW,producer_workflow_sha='e'*40,producer_run_id=1,
        producer_run_attempt=1,producer_workflow_sha256='f'*64,producer_script_sha256='a'*64,
        build_image=p.IMAGE,target=p.TARGET,rust_toolchain=p.TOOLCHAIN,rustc_commit=p.RUSTC_COMMIT,
        rustc_llvm=p.LLVM,native_compiler={k:dict(version='11.4.0',sha256='b'*64) for k in ['gcc','gxx']},
        binaries=binary,cpu_check=dict(source_sha256='c'*64,compiler_flags=p.CPU_FLAGS,bytes=100,
            sha256='d'*64,abi=dict(elf_class=64,machine=62,little_endian=True,loader='none',needed=[],versions={})),
        runtime_dependencies=dict(reth=p.RETH,commonware=p.COMMONWARE),
        registration=dict(symbol_verified=True,call_verified=True,verifier_sha256='e'*64))


class ManifestTests(unittest.TestCase):
    def test_closed_roundtrip_and_identity_mutations(self):
        value=fixture();self.assertEqual(p.validate_manifest(json.loads(json.dumps(value))),value)
        mutations=[lambda x:x.update(schema=True),lambda x:x.update(producer_run_id=True),
            lambda x:x.update(producer_run_attempt=0),lambda x:x.update(producer_run_id=2**53),
            lambda x:x.update(producer_workflow_sha='main'),lambda x:x.update(rust_toolchain='stable'),
            lambda x:x.update(rustc_commit='a'*40),lambda x:x.update(target='aarch64-unknown-linux-gnu'),
            lambda x:x.update(build_image='ubuntu:latest'),lambda x:x.update(hostname='private'),
            lambda x:x['runtime_dependencies'].update(reth='f'*40),
            lambda x:x['registration'].update(call_verified=False)]
        for mutate in mutations:
            bad=copy.deepcopy(value);mutate(bad)
            with self.subTest(mutate=mutate),self.assertRaises(p.Rejected):p.validate_manifest(bad)
        with self.assertRaises(p.Rejected):json.loads('{"schema":1,"schema":1}',object_pairs_hook=p.pairs)

    def test_role_features_flags_and_sizes_fail_closed(self):
        for role in p.ROLES:
            for key,wrong in [('source_sha','f'*40),('profile','dev'),('default_features',1),
                ('rustflags',['-C','target-cpu=native']),('cflags',['-march=native']),
                ('cxxflags',[]),('bytes',True),('bytes',p.MAX_BINARY+1),('sha256','SECRET'),
                ('features',['jemalloc','asm-keccak','keccak-cache-global']),('unexpected','host/path')]:
                value=fixture();value['binaries'][role][key]=wrong
                with self.subTest(role=role,key=key),self.assertRaises(p.Rejected):p.validate_manifest(value)
        value=fixture();value['binaries'].pop('bench')
        with self.assertRaises(p.Rejected):p.validate_manifest(value)
        value=fixture();value['cpu_check']['compiler_flags']=p.CFLAGS
        with self.assertRaises(p.Rejected):p.validate_manifest(value)

    def test_abi_admission_rejects_unbounded_or_private_values(self):
        for change in [dict(machine=True),dict(little_endian=1),dict(loader='/private/ld.so'),
            dict(needed=['/host/library']),dict(needed=['libc.so.6','libc.so.6']),
            dict(versions={'libc.so.6':['GLIBC_PRIVATE']}),
            dict(versions={'libc.so.6':['GLIBC_2.2.5']*129}),dict(versions={'foreign':['GLIBC_2.2.5']})]:
            value=fixture();value['binaries']['tempo']['abi'].update(change)
            with self.subTest(change=change),self.assertRaises(p.Rejected):p.validate_manifest(value)

    def test_only_exact_compiler_identity(self):
        data=('rustc 1.98.1 (48a229cea 2026-09-01)\nbinary: rustc\ncommit-hash: '+p.RUSTC_COMMIT+
              '\ncommit-date: 2026-09-01\nhost: '+p.TARGET+'\nrelease: 1.98.1\nLLVM version: 22.1.8\n').encode()
        p.parse_rustc(data)
        for bad in [data.replace(b'1.98.1',b'1.96.1'),data.replace(b'22.1.8',b'22.1.2'),
                    data+b'host: private\n',data.replace(p.TARGET.encode(),b'private-host')]:
            with self.assertRaises(p.Rejected):p.parse_rustc(bad)

    def test_commands_and_environment_remove_inherited_codegen_and_credentials(self):
        environment=p.build_environment({'PATH':'/usr/bin','HOME':'/home/test','RUSTUP_HOME':'/toolchain',
            'RUSTFLAGS':'-Ctarget-cpu=native','CARGO_ENCODED_RUSTFLAGS':'-Ctarget-cpu=native',
            'CFLAGS':'-march=native','RUSTC_WRAPPER':'sccache','GITHUB_TOKEN':'secret',
            'AWS_SECRET_ACCESS_KEY':'secret','CARGO_PROFILE_PROFILING_LTO':'off','CC':'hostcc'},
            Path('/private/cargo'),Path('/private/target'),Path('/toolchain/rustc'))
        self.assertNotIn('GITHUB_TOKEN',environment);self.assertNotIn('RUSTC_WRAPPER',environment)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY',environment);self.assertNotIn('CARGO_PROFILE_PROFILING_LTO',environment)
        self.assertEqual(environment['CARGO_ENCODED_RUSTFLAGS'],'-C\x1ftarget-cpu=x86-64-v3')
        self.assertEqual(environment['CFLAGS'],'-march=x86-64-v3 -mtune=generic -DNO_PCLMUL')
        self.assertEqual(p.build_command('tempo'),['cargo','+1.98.1','build','--locked','--target',p.TARGET,
            '--profile','profiling','--no-default-features','--features','asm-keccak,jemalloc,keccak-cache-global','--bin','tempo'])
        self.assertEqual(p.build_command('tools'),['cargo','+1.98.1','build','--locked','--target',p.TARGET,
            '--release','--package','txgen-tempo','--package','bench-cli','--bin','txgen-tempo','--bin','bench'])

    def test_native_invocation_guard_and_owned_path_remapping(self):
        for args in [['-march=native'],['-march','native'],['-mtune=native'],
                     ['-mcpu=skylake'],['-march=znver4'],['@private-response'],
                     ['-march'],['-mtune','skylake']]:
            with self.subTest(args=args),self.assertRaises(p.Rejected):p.native_arguments(args)
        self.assertEqual(p.native_arguments(['-march=x86-64-v3','-mtune=generic','-mavx512f']),
                         ['-march=x86-64-v3','-mtune=generic','-mavx512f'])
        with tempfile.TemporaryDirectory() as temp:
            private=Path(temp);producer=ROOT.parent.parent
            env=p.remapped_environment({},producer,producer,private,Path('/rust/bin/rustc'))
            self.assertIn('--remap-path-prefix='+str(private)+'=/build',env['CARGO_ENCODED_RUSTFLAGS'])
            self.assertIn('-ffile-prefix-map='+str(private)+'=/build',env['CFLAGS'])
            bad=subprocess.run([env['CC'],'-march=native','--version'],capture_output=True)
            self.assertNotEqual(bad.returncode,0);self.assertNotIn(b'private',bad.stderr)
            good=subprocess.run([env['CC'],'-dumpfullversion'],capture_output=True)
            self.assertEqual(good.returncode,0)

    def test_source_exact_commit_and_clean_tracked_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            repo=Path(temp)
            def git(*args):return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.DEVNULL).decode().strip()
            git('init');git('config','user.email','fixture@example.invalid');git('config','user.name','fixture')
            (repo/'Cargo.toml').write_text('[workspace]\n');(repo/'Cargo.lock').write_text('version = 4\n')
            git('add','.');git('commit','-m','fixture');commit=git('rev-parse','HEAD')
            self.assertEqual(p.source(repo,commit,'tempoxyz/tempo')['source_sha'],commit)
            with self.assertRaises(p.Rejected):p.source(repo,'a'*40,'tempoxyz/tempo')
            (repo/'Cargo.lock').write_text('version = 3\n')
            with self.assertRaises(p.Rejected):p.source(repo,commit,'tempoxyz/tempo')
            git('checkout','--','Cargo.lock');(repo/'extra').write_text('private')
            with self.assertRaises(p.Rejected):p.source(repo,commit,'tempoxyz/tempo')

    def test_binary_identity_rejects_symlink_and_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'binary';path.write_bytes(b'ELF')
            self.assertEqual(p.hashed(path)['bytes'],3)
            link=Path(temp)/'link';link.symlink_to(path)
            with self.assertRaises(p.Rejected):p.hashed(link)
            old=p.identity
            count=[0]
            def changed(file):
                result=old(file);count[0]+=1
                if count[0]>1:return (*result[:-1],result[-1]+1)
                return result
            with patch.object(p,'identity',side_effect=changed),self.assertRaises(p.Rejected):p.hashed(path)


class DiagnosticTests(unittest.TestCase):
    def test_actual_rust_elf_can_require_the_exact_loader_soname(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'fixture.rs';binary=root/'fixture'
            source.write_text('fn main() { std::thread::spawn(|| std::thread::current()).join().unwrap(); }')
            subprocess.run(['rustc','--crate-name','abi_fixture',str(source),'-o',str(binary)],check=True)
            with patch.object(p,'SONAMES',p.SONAMES-{'ld-linux-x86-64.so.2'}):
                with self.assertRaises(p.Rejected):p.abi(binary)
            value=p.abi(binary)
            self.assertIn('ld-linux-x86-64.so.2',value['needed'])
            self.assertEqual(value['loader'],'glibc_x86_64')
            value['needed'].append('ld-private.so')
            with self.assertRaises(p.Rejected):p.validate_abi(value)

    def test_closed_failure_stage_and_real_size_cap_preserved(self):
        with patch.dict(p.DIAGNOSTIC,dict(schema=1,stage=12,role=1,bytes=0,clean=1,abi=0,failure=0,check=0,tool=0,tool_bytes=0,tool_exit=0,tool_signal=0),clear=True):
            with tempfile.TemporaryDirectory() as temp:
                oversized=Path(temp)/'private-binary'
                with oversized.open('wb') as f:f.truncate(p.MAX_BINARY+1)
                try:p.hashed(oversized)
                except p.Rejected as error:receipt=p.failure_receipt(error)
                else:self.fail('original 2GiB cap was weakened')
                self.assertEqual(receipt['bytes'],p.MAX_BINARY+1)
                self.assertEqual((receipt['stage'],receipt['role'],receipt['failure']),(12,1,1))
                self.assertGreater(receipt['check'],0)
                self.assertEqual(set(receipt),{'schema','stage','role','bytes','clean','abi','failure','check','tool','tool_bytes','tool_exit','tool_signal'})
                self.assertTrue(all(type(v)is int for v in receipt.values()))
                try:raise OSError('private path and compiler output')
                except OSError as error:other=p.failure_receipt(error)
                self.assertEqual(other['failure'],2)
                self.assertNotIn('private',json.dumps(other))


class StreamingMarkerTests(unittest.TestCase):
    def test_large_stream_selection_is_bounded_and_checks_exit(self):
        selected=[]
        def visit(line):
            if line.endswith(' T reth_lifecycle_thread_register'):selected.append(line)
        code="import sys; b=('x'*4095+'\\n').encode(); [sys.stdout.buffer.write(b) for _ in range(8448)]; print('1 T reth_lifecycle_thread_register')"
        tracemalloc.start()
        try:
            p.stream_lines([sys.executable,'-c',code],visit,tool=1)
            _,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertEqual(selected,['1 T reth_lifecycle_thread_register'])
        self.assertGreater(p.DIAGNOSTIC['tool_bytes'],32*1024**2)
        self.assertLess(peak,2*1024**2)
        with self.assertRaises(p.Rejected):
            p.stream_lines([sys.executable,'-c',"print('match');raise SystemExit(7)"],lambda _:None)
        self.assertEqual(p.DIAGNOSTIC['tool_exit'],7)
        with self.assertRaises(p.Rejected):
            p.stream_lines([sys.executable,'-c',"print('x'*65537)"],lambda _:None)
        before=time.monotonic()
        with self.assertRaises(p.Rejected):
            p.stream_lines([sys.executable,'-c','import time;time.sleep(60)'],lambda _:None,timeout=.05)
        self.assertLess(time.monotonic()-before,6)

    def test_partial_lines_and_signal_exit_remain_distinct(self):
        rows=[]
        code="import os;os.write(1,b'first');os.write(1,b' line\\nlast')"
        p.stream_lines([sys.executable,'-c',code],rows.append)
        self.assertEqual(rows,['first line','last'])
        with self.assertRaises(p.Rejected):
            p.stream_lines([sys.executable,'-c','import os,signal;os.kill(os.getpid(),signal.SIGTERM)'],lambda _:None)
        self.assertEqual((p.DIAGNOSTIC['tool_exit'],p.DIAGNOSTIC['tool_signal']),(0,15))
        with self.assertRaises(p.Rejected):
            p.checked([sys.executable,'-c',"print('small');raise SystemExit(7)"])
        self.assertEqual((p.DIAGNOSTIC['tool_exit'],p.DIAGNOSTIC['tool_bytes']),(7,6))
        with self.assertRaises(p.Rejected):
            p.checked([sys.executable,'-c',"import sys;sys.stdout.buffer.write(b'x'*(32*1024*1024+1))"])
        self.assertEqual((p.DIAGNOSTIC['tool_exit'],p.DIAGNOSTIC['tool_bytes']),(0,32*1024*1024+1))

    def test_exited_leader_with_pipe_holding_descendant_is_cleaned(self):
        with tempfile.TemporaryDirectory() as temp:
            pidfile=Path(temp)/'owned-child'
            code="import os,sys,time;pid=os.fork();open(sys.argv[1],'w').write(str(pid)) if pid else time.sleep(60)"
            with self.assertRaises(p.Rejected):
                p.stream_lines([sys.executable,'-c',code,str(pidfile)],lambda _:None,timeout=.2)
            pid=int(pidfile.read_text());deadline=time.monotonic()+1
            while time.monotonic()<deadline:
                status=Path('/proc')/str(pid)/'stat'
                if not status.exists() or status.read_text().split()[2]=='Z':break
                time.sleep(.01)
            else:self.fail('owned descendant survived group cleanup')

    def test_marker_duplicate_missing_and_no_call_reject(self):
        for symbols,disassembly in [(['1 T reth_lifecycle_thread_register']*2,['0: call 1 <reth_lifecycle_thread_register>']),
                                    ([],['0: call 1 <reth_lifecycle_thread_register>']),
                                    (['1 T reth_lifecycle_thread_register'],['0: ret'])]:
            def fake(command,visit,**kwargs):
                for line in symbols if command[0]=='nm' else disassembly if command[0]=='objdump' else []:visit(line)
            with patch.object(p,'stream_lines',side_effect=fake),self.assertRaises(p.Rejected):
                p.verify_marker(ROOT.parent.parent,Path('/unused'))

    def test_actual_optimized_direct_and_pic_elf_without_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            direct=root/'direct.c';direct.write_text('__attribute__((noinline)) void reth_lifecycle_thread_register(void){__asm__ volatile("" ::: "memory");} int main(void){reth_lifecycle_thread_register();return 0;}')
            subprocess.run(['gcc','-O3','-fno-optimize-sibling-calls',str(direct),'-o',str(root/'direct')],check=True)
            p.verify_marker(ROOT.parent.parent,root/'direct')
            pic=root/'pic.S';pic.write_text('.text\n.globl reth_lifecycle_thread_register\n.type reth_lifecycle_thread_register,@function\nreth_lifecycle_thread_register:\nret\n.section .data.rel.ro,"aw"\n.align 8\nmarker_pointer:\n.quad reth_lifecycle_thread_register\n.text\n.globl main\n.type main,@function\nmain:\nsub $8,%rsp\ncall *marker_pointer(%rip)\nadd $8,%rsp\nxor %eax,%eax\nret\n.section .note.GNU-stack,"",@progbits\n')
            subprocess.run(['gcc','-O3','-fPIE','-pie',str(pic),'-o',str(root/'pic')],check=True)
            p.verify_marker(ROOT.parent.parent,root/'pic')
            spec=importlib.util.spec_from_file_location('marker',ROOT.parent.parent/p.VERIFIER)
            m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
            symbols=subprocess.check_output(['nm','--defined-only',str(root/'pic')],text=True)
            relocs=subprocess.check_output(['readelf','-rW',str(root/'pic')],text=True)
            self.assertTrue(m.marker_slots(symbols,relocs,'reth_lifecycle_thread_register'))
            disassembly=subprocess.check_output(['objdump','-d',str(root/'pic')],text=True)
            self.assertTrue(any('(%rip)' in line and m.marker_call(line,'reth_lifecycle_thread_register',m.marker_slots(symbols,relocs,'reth_lifecycle_thread_register')) for line in disassembly.splitlines()))


class CpuTests(unittest.TestCase):
    def test_actual_baseline_static_probe_and_each_missing_feature(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);binary=root/'cpu-check'
            subprocess.run(['gcc',*p.CPU_FLAGS,'-Wall','-Wextra','-Werror',str(ROOT/'bench-cpu-check.c'),'-o',str(binary)],check=True)
            self.assertEqual(p.abi(binary),dict(elf_class=64,machine=62,little_endian=True,loader='none',needed=[],versions={}))
            result=subprocess.run([str(binary)],capture_output=True,check=False)
            row=json.loads(result.stdout);self.assertEqual(set(row),{'schema','supported','checked','total'})
            self.assertEqual(row['total'],len(os.sched_getaffinity(0)))
            self.assertEqual(row['supported'],result.returncode==0)
            if row['supported']:self.assertEqual(row['checked'],row['total'])
            # Pure CPUID decoder injection: each requirement and missing OS YMM/XMM state.
            source=root/'features.c';source.write_text('#define main probe_main\n#include "'+str(ROOT/'bench-cpu-check.c')+'"\n#undef main\n#include <assert.h>\nint main(void) {\n'
                'unsigned c=(1U<<0)|(1U<<9)|(1U<<12)|(1U<<13)|(1U<<19)|(1U<<20)|(1U<<22)|(1U<<23)|(1U<<26)|(1U<<27)|(1U<<28)|(1U<<29);\n'
                'unsigned d=(1U<<0)|(1U<<8)|(1U<<15)|(1U<<23)|(1U<<24)|(1U<<25)|(1U<<26);\n'
                'unsigned b=(1U<<3)|(1U<<5)|(1U<<8),e=(1U<<0)|(1U<<5);\n'
                'assert(feature_set(c,d,b,e,6));\nfor(unsigned i=0;i<32;i++){unsigned bit=1U<<i;'
                'if(c&bit)assert(!feature_set(c&~bit,d,b,e,6));if(d&bit)assert(!feature_set(c,d&~bit,b,e,6));'
                'if(b&bit)assert(!feature_set(c,d,b&~bit,e,6));if(e&bit)assert(!feature_set(c,d,b,e&~bit,6));}\n'
                'assert(!feature_set(c,d,b,e,0));assert(!feature_set(c,d,b,e,2));assert(!feature_set(c,d,b,e,4));return 0;}\n')
            executable=root/'features';subprocess.run(['gcc',*p.CPU_FLAGS,str(source),'-o',str(executable)],check=True)
            subprocess.run([str(executable)],check=True)


class WorkflowTests(unittest.TestCase):
    def test_fixed_source_private_artifact_and_no_compile_cache(self):
        source=(ROOT.parent/'workflows'/'build.yml').read_text()
        for exact in [p.RUNTIME,p.TOOLS,p.IMAGE,'rustup toolchain install 1.98.1 --target x86_64-unknown-linux-gnu','--component rustfmt --profile minimal --no-self-update','timeout-minutes: 90',
                      'depot-ubuntu-latest-16','persist-credentials: false','compression-level: 0']:
            self.assertIn(exact,source)
        for forbidden in ['sccache','MINIO','target-cpu=native','pull_request:','inputs.','id-token: write','github-sts']:
            self.assertNotIn(forbidden,source)
        self.assertEqual(source.count('actions/upload-artifact@'),1)


if __name__=='__main__':unittest.main()
