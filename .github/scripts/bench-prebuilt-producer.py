#!/usr/bin/env python3
"""Fixed, private benchmark binary producer. No cache lookup/upload or runtime launch."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import selectors
import signal
import time
import stat
import struct
import subprocess
import sys
import tempfile

RUNTIME = '0f47e62fcf004ccd95fb61d7e1441ecb0229b52e'
TOOLS = '94f86f186cd18f641eb9699d7e31c9e536de7c17'
RETH = '0d12b5823268edee3dbf902079db182389e05ec5'
COMMONWARE = 'e755c2f335acb4fccab4cbfd3d4184206742360e'
TOOLCHAIN = '1.98.1'
RUSTC_COMMIT = '48a229ceaefd4985c50990b14116b6d856af0985'
LLVM = '22.1.8'
TARGET = 'x86_64-unknown-linux-gnu'
IMAGE = 'ubuntu:22.04@sha256:281c5745f657873d78e5531fc5ba8575f46ab7769b94550ac99543f122679986'
WORKFLOW = '.github/workflows/build.yml'
SCRIPT = '.github/scripts/bench-prebuilt-producer.py'
CPU_SOURCE = '.github/scripts/bench-cpu-check.c'
VERIFIER = 'contrib/bench/lifecycle/scheduler/diagnostic.py'
RUSTFLAGS = ['-C', 'target-cpu=x86-64-v3']
# RocksDB's header otherwise infers PCLMUL from AVX, which v3 does not require.
CFLAGS = ['-march=x86-64-v3', '-mtune=generic', '-DNO_PCLMUL']
CPU_FLAGS = ['-static', '-O2', '-march=x86-64', '-mtune=generic']
FEATURES = ['asm-keccak', 'jemalloc', 'keccak-cache-global']
ROLES = ('tempo', 'txgen-tempo', 'bench')
SONAMES = {'libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'librt.so.1',
           'libgcc_s.so.1', 'libstdc++.so.6', 'libudev.so.1', 'libssl.so.3',
           'libcrypto.so.3', 'libz.so.1', 'libzstd.so.1', 'libatomic.so.1',
           'ld-linux-x86-64.so.2'}
MAX_BINARY = 2 * 1024**3
MAX_MANIFEST = 65536
JS_MAX = 2**53-1
DIAGNOSTIC = dict(schema=1, stage=0, role=0, bytes=0, clean=0, abi=0, failure=0, check=0, tool=0, tool_bytes=0, tool_exit=0, tool_signal=0)


def checkpoint(stage, **values):
    DIAGNOSTIC.update(stage=stage, **values)


def failure_receipt(error):
    # Only fixed source-stage/role enums, source line, booleans-as-enums and sizes.
    # Never include exception text, paths, symbol names, or tool output.
    categories=(Rejected,OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError,ImportError)
    DIAGNOSTIC['failure']=next(i+1 for i,k in enumerate(categories) if isinstance(error,k))
    trace=error.__traceback__
    while trace is not None:
        if trace.tb_frame.f_code.co_filename==__file__ and trace.tb_frame.f_code.co_name!='need':
            DIAGNOSTIC['check']=trace.tb_lineno
        trace=trace.tb_next
    need(set(DIAGNOSTIC)=={'schema','stage','role','bytes','clean','abi','failure','check','tool','tool_bytes','tool_exit','tool_signal'})
    need(all(type(v)is int and 0<=v<=JS_MAX for v in DIAGNOSTIC.values()))
    return dict(DIAGNOSTIC)


class Rejected(Exception):
    pass


def need(condition):
    if not condition:
        raise Rejected('prebuilt_producer_rejected')


def uint(value, minimum=0, maximum=JS_MAX):
    need(type(value) is int and minimum <= value <= maximum)
    return value


def sha(value, size=64):
    need(type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None)
    return value


def keys(value, expected):
    need(type(value) is dict and set(value) == set(expected))


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result)
        result[key] = value
    return result


def identity(path):
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and not path.is_symlink())
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def hashed(path):
    before = identity(path)
    DIAGNOSTIC['bytes']=before[2]
    need(0 < before[2] <= MAX_BINARY)
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''):
            h.update(block)
    need(identity(path) == before)
    return dict(bytes=before[2], sha256=h.hexdigest())


def checked(command, cwd=None, env=None, timeout=60):
    # Tool diagnostics stay private and are never copied into the closed manifest.
    process = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=timeout, check=False)
    DIAGNOSTIC.update(tool=0,tool_bytes=len(process.stdout),
                      tool_exit=max(process.returncode,0),tool_signal=max(-process.returncode,0))
    need(process.returncode == 0)
    need(len(process.stdout) <= 32*1024*1024)
    return process.stdout


def git(repo, *args):
    return checked(['git', '-C', str(repo), *args]).decode().strip()


def source(repo, expected, repository):
    need(repo.is_dir() and repo.resolve() == repo and git(repo, 'rev-parse', 'HEAD') == expected)
    clean=git(repo, 'status', '--porcelain', '--untracked-files=all') == ''
    DIAGNOSTIC['clean']=1 if clean else 2
    need(clean)
    # Exact tracked bytes are rechecked after compilation too.
    for name in ('Cargo.toml', 'Cargo.lock'):
        need(checked(['git', '-C', str(repo), 'show', expected+':'+name]) == (repo/name).read_bytes())
    return dict(source_repository=repository, source_sha=expected,
                source_tree=git(repo, 'rev-parse', 'HEAD^{tree}'),
                cargo_toml_sha256=hashed(repo/'Cargo.toml')['sha256'],
                cargo_lock_sha256=hashed(repo/'Cargo.lock')['sha256'])


def parse_rustc(data):
    lines = data.decode().splitlines()
    need(lines and lines[0] == 'rustc 1.98.1 (48a229cea 2026-09-01)')
    fields = {}
    for line in lines[1:]:
        need(': ' in line)
        key, value = line.split(': ', 1)
        need(key not in fields)
        fields[key] = value
    need(fields == {'binary':'rustc', 'commit-hash':RUSTC_COMMIT, 'commit-date':'2026-09-01',
                    'host':TARGET, 'release':TOOLCHAIN, 'LLVM version':LLVM})


def build_command(role):
    need(role in ('tempo', 'tools'))
    command = ['cargo', '+'+TOOLCHAIN, 'build', '--locked', '--target', TARGET]
    if role == 'tempo':
        return command + ['--profile','profiling','--no-default-features','--features',
                          ','.join(FEATURES),'--bin','tempo']
    return command + ['--release','--package','txgen-tempo','--package','bench-cli',
                      '--bin','txgen-tempo','--bin','bench']


def build_environment(original, cargo_home, target_dir, rustc):
    # No inherited native flags, wrappers, Cargo config, tokens, MinIO or sccache.
    need('PATH' in original and 'HOME' in original)
    environment = {key:original[key] for key in ('PATH','HOME','RUSTUP_HOME') if key in original}
    environment.update(CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(target_dir),
        RUSTUP_TOOLCHAIN=TOOLCHAIN, RUSTC=str(rustc), CARGO_BUILD_JOBS='16',
        CARGO_ENCODED_RUSTFLAGS='\x1f'.join(RUSTFLAGS), RUSTFLAGS=' '.join(RUSTFLAGS),
        CFLAGS=' '.join(CFLAGS), CXXFLAGS=' '.join(CFLAGS), CC='/usr/bin/gcc', CXX='/usr/bin/g++',
        CARGO_TERM_COLOR='never', LC_ALL='C', LANG='C')
    return environment


def native_arguments(args):
    # Reject host selection even in compiler feature probes. Explicit per-file
    # ISA variants (e.g. runtime-dispatched crypto assembly) remain source-owned.
    need(len(args) <= 8192 and sum(len(arg) for arg in args) <= 1024*1024)
    need(all(not arg.startswith('@') for arg in args))
    for index, arg in enumerate(args):
        if arg in ('-march','-mtune','-mcpu'):
            need(index+1 < len(args)); arg += '=' + args[index+1]
        if arg.startswith('-march='): need(arg in ('-march=x86-64','-march=x86-64-v3'))
        if arg.startswith('-mtune='): need(arg == '-mtune=generic')
        need(not arg.startswith('-mcpu=') and 'target-cpu=native' not in arg)
    return args


def remapped_environment(environment, producer, repo, private, rustc):
    # Path-remap values are deliberately absent from the manifest. The fixed
    # policy names and source hash bind these exact synthetic destinations.
    roots = [(producer.parent,'/workspace'),(repo,'/source'),(private,'/build'),
             (rustc.parent.parent,'/toolchain')]
    rust = RUSTFLAGS + ['--remap-path-prefix='+str(a)+'='+b for a,b in roots]
    native = CFLAGS + ['-ffile-prefix-map='+str(a)+'='+b for a,b in roots]
    environment.update(CARGO_ENCODED_RUSTFLAGS='\x1f'.join(rust), RUSTFLAGS=' '.join(rust),
                       CFLAGS=' '.join(native), CXXFLAGS=' '.join(native))
    for key, compiler in [('CC','gcc'),('CXX','g++')]:
        wrapper = private/('guard-'+compiler)
        wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' -I '+
                           shlex.quote(str(producer/SCRIPT))+' --native-'+compiler+' "$@"\n')
        wrapper.chmod(0o700); environment[key]=str(wrapper)
    return environment


def abi(binary):
    DIAGNOSTIC['abi']=1
    with binary.open('rb') as source:
        header = source.read(64)
    need(len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01')
    need(struct.unpack_from('<H',header,18)[0] == 62)
    DIAGNOSTIC['abi']=2
    program = checked(['readelf','-lW',str(binary)]).decode()
    loaders = re.findall(r'\[Requesting program interpreter: ([^\]]+)\]',program)
    need(loaders in ([], ['/lib64/ld-linux-x86-64.so.2']))
    DIAGNOSTIC['abi']=3
    dynamic = checked(['readelf','-dW',str(binary)]).decode()
    needed = re.findall(r'\(NEEDED\).*Shared library: \[([^\]]+)\]',dynamic)
    need(len(needed) == len(set(needed)) and set(needed) <= SONAMES)
    DIAGNOSTIC['abi']=4
    version_text = checked(['readelf','-VW',str(binary)]).decode()
    versions = {}; library = None
    for line in version_text.splitlines():
        found = re.search(r'File: (\S+)\s+Cnt:',line)
        if found:
            library = found[1]; need(library in needed and library not in versions)
            versions[library] = []
        found = re.search(r'Name: (\S+)\s+Flags:',line)
        if found and library is not None:
            versions[library].append(found[1])
    result = dict(elf_class=64, machine=62, little_endian=True,
                  loader='glibc_x86_64' if loaders else 'none', needed=sorted(needed),
                  versions={k:sorted(set(v)) for k,v in sorted(versions.items())})
    DIAGNOSTIC['abi']=5
    validate_abi(result)
    DIAGNOSTIC['abi']=6
    return result


def validate_abi(value):
    keys(value, ('elf_class','machine','little_endian','loader','needed','versions'))
    need(type(value['elf_class']) is int and value['elf_class']==64)
    need(type(value['machine']) is int and value['machine']==62 and value['little_endian'] is True)
    need(value['loader'] in ('none','glibc_x86_64'))
    libs=value['needed']; need(type(libs) is list and libs==sorted(set(libs)) and set(libs)<=SONAMES)
    need(type(value['versions']) is dict and set(value['versions'])<=set(libs))
    if value['loader']=='none': need(not libs and not value['versions'])
    for library, versions in value['versions'].items():
        need(type(versions) is list and 0<len(versions)<=128 and versions==sorted(set(versions)))
        for version in versions:
            need(type(version) is str and re.fullmatch(r'(GLIBC|GLIBCXX|CXXABI|GCC|LIBUDEV|OPENSSL|ZLIB)_[0-9]+(?:\.[0-9]+){0,3}',version) is not None)


def validate_manifest(value):
    keys(value, ('schema','build_contract','producer_repository','producer_workflow_path',
        'producer_workflow_sha','producer_run_id','producer_run_attempt','producer_workflow_sha256',
        'producer_script_sha256','build_image','target','rust_toolchain','rustc_commit','rustc_llvm',
        'native_compiler','binaries','cpu_check','runtime_dependencies','registration',
        'path_remap','native_flags_guard'))
    need(type(value['schema']) is int and value['schema']==1)
    for key, expected in {'build_contract':'x86_64_v3_locked_v1','producer_repository':'tempoxyz/tempo',
        'producer_workflow_path':WORKFLOW,'build_image':IMAGE,'target':TARGET,'rust_toolchain':TOOLCHAIN,
        'rustc_commit':RUSTC_COMMIT,'rustc_llvm':LLVM,
        'path_remap':'owned_source_build_toolchain_v1',
        'native_flags_guard':'reject_host_native_v1'}.items(): need(value[key]==expected)
    for key in ('producer_workflow_sha256','producer_script_sha256'): sha(value[key])
    sha(value['producer_workflow_sha'],40)
    uint(value['producer_run_id'],1); uint(value['producer_run_attempt'],1)
    keys(value['runtime_dependencies'],('reth','commonware'))
    need(value['runtime_dependencies']=={'reth':RETH,'commonware':COMMONWARE})
    keys(value['native_compiler'],('gcc','gxx'))
    for compiler in value['native_compiler'].values():
        keys(compiler,('version','sha256')); sha(compiler['sha256'])
        need(type(compiler['version']) is str and re.fullmatch(r'11\.[0-9]+\.[0-9]+',compiler['version']) is not None)
    keys(value['registration'],('symbol_verified','call_verified','verifier_sha256'))
    need(value['registration']['symbol_verified'] is True and value['registration']['call_verified'] is True)
    sha(value['registration']['verifier_sha256'])
    keys(value['binaries'],ROLES)
    for role,item in value['binaries'].items():
        keys(item,('source_repository','source_sha','source_tree','cargo_toml_sha256','cargo_lock_sha256',
            'profile','default_features','features','rustflags','cflags','cxxflags','bytes','sha256','abi'))
        need(item['source_repository']==('tempoxyz/tempo' if role=='tempo' else 'tempoxyz/txgen'))
        need(item['source_sha']==(RUNTIME if role=='tempo' else TOOLS)); sha(item['source_tree'],40)
        for key in ('cargo_toml_sha256','cargo_lock_sha256','sha256'): sha(item[key])
        need(item['profile']==('profiling' if role=='tempo' else 'release'))
        need(type(item['default_features']) is bool and item['default_features']==(role!='tempo'))
        need(item['features']==(FEATURES if role=='tempo' else []))
        need(item['rustflags']==RUSTFLAGS and item['cflags']==CFLAGS and item['cxxflags']==CFLAGS)
        uint(item['bytes'],1,MAX_BINARY); validate_abi(item['abi']); need(item['abi']['loader']=='glibc_x86_64')
    cpu=value['cpu_check']; keys(cpu,('source_sha256','compiler_flags','bytes','sha256','abi'))
    sha(cpu['source_sha256']);sha(cpu['sha256']);uint(cpu['bytes'],1,16*1024*1024)
    need(cpu['compiler_flags']==CPU_FLAGS);validate_abi(cpu['abi']);need(cpu['abi']['loader']=='none')
    need(len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())<=MAX_MANIFEST)
    return value


def stream_lines(command, visit, *, timeout=120, tool=0):
    """Bound memory by one 64KiB record, not the complete tool transcript."""
    DIAGNOSTIC.update(tool=tool,tool_bytes=0,tool_exit=0,tool_signal=0)
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                             start_new_session=True)
    selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
    end=time.monotonic()+timeout;pending=b'';drained=False
    try:
        while True:
            remaining=end-time.monotonic();need(remaining>0)
            if not selector.select(min(remaining,0.5)):continue
            chunk=os.read(process.stdout.fileno(),65536)
            if not chunk:break
            DIAGNOSTIC['tool_bytes']+=len(chunk);need(DIAGNOSTIC['tool_bytes']<=JS_MAX)
            lines=(pending+chunk).split(b'\n');pending=lines.pop()
            for line in lines:
                need(len(line)<=65536);visit(line.decode())
            need(len(pending)<=65536)
        if pending:visit(pending.decode())
        remaining=end-time.monotonic();need(remaining>0)
        code=process.wait(timeout=remaining);drained=True
        DIAGNOSTIC.update(tool_exit=max(code,0),tool_signal=max(-code,0))
        need(code==0)
    finally:
        selector.close();process.stdout.close()
        # Do not poll/reap first: an exited leader may still own pipe-holding
        # descendants, and its unreaped PID protects this process-group identity.
        if not drained:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=5)


def verify_marker(producer, binary):
    spec=importlib.util.spec_from_file_location('prebuilt_marker_verifier',producer/VERIFIER)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    name='reth_lifecycle_thread_register';symbols=[]
    def symbol(line):
        words=line.split()
        if len(words)==3 and words[1] in ('T','t') and words[2]==name:
            need(len(symbols)==0);symbols.append(line)
    stream_lines(['nm','--defined-only',str(binary)],symbol,tool=1)
    need(len(symbols)==1)
    # Only marker relocations survive this streaming filter. Reuse the existing
    # source-bound GOT and instruction matchers exactly; addresses stay private.
    slots=set()
    def relocation(line):
        slots.update(module.marker_slots(symbols[0],line,name));need(len(slots)<=4096)
    stream_lines(['readelf','-rW',str(binary)],relocation,tool=2)
    found=False
    def instruction(line):
        nonlocal found
        if not found and module.marker_call(line,name,slots):found=True
    # Drain even after a match so a tool's nonzero exit can never be accepted.
    stream_lines(['objdump','-d',str(binary)],instruction,tool=3)
    need(found)


def produce(producer,runtime,tools,output):
    checkpoint(1)
    expected=sha(os.environ.get('PREBUILT_PRODUCER_SHA'),40)
    run_id=uint(int(os.environ.get('PREBUILT_RUN_ID','0')),1)
    attempt=uint(int(os.environ.get('PREBUILT_RUN_ATTEMPT','0')),1)
    need(git(producer,'rev-parse','HEAD')==expected and git(producer,'status','--porcelain','--untracked-files=all')=='')
    for path in (WORKFLOW,SCRIPT,CPU_SOURCE,VERIFIER):
        need(checked(['git','-C',str(producer),'show',expected+':'+path])==(producer/path).read_bytes())
    checkpoint(2)
    sources={'tempo':source(runtime,RUNTIME,'tempoxyz/tempo'),'tools':source(tools,TOOLS,'tempoxyz/txgen')}
    lock=(runtime/'Cargo.lock').read_text()
    for url,revision in [('joshieDo/reth',RETH),('joshieDo/monorepo',COMMONWARE)]:
        found=re.findall(r'source = "git\+https://github.com/'+url+r'\?rev=([a-f0-9]+)#([a-f0-9]+)"',lock)
        need(found and all(a==b==revision for a,b in found))
    checkpoint(3)
    parse_rustc(checked(['rustup','run',TOOLCHAIN,'rustc','-Vv']))
    rustc=Path(checked(['rustup','which','--toolchain',TOOLCHAIN,'rustc']).decode().strip())
    native={}
    for key,command in [('gcc','gcc'),('gxx','g++')]:
        path=Path(shutil.which(command)).resolve()
        native[key]={'version':checked([str(path),'-dumpfullversion']).decode().strip(),
                     'sha256':hashed(path)['sha256']}
    checkpoint(4)
    need(not output.exists() and output.parent.resolve()==output.parent)
    output.mkdir(mode=0o700)
    cpu=output/'cpu-check'
    checked(['/usr/bin/gcc',*CPU_FLAGS,str(producer/CPU_SOURCE),'-o',str(cpu)])
    cpuresult=json.loads(checked([str(cpu)]),object_pairs_hook=pairs)
    keys(cpuresult,('schema','supported','checked','total'))
    need(type(cpuresult['schema']) is int and cpuresult['schema']==1 and cpuresult['supported'] is True)
    need(uint(cpuresult['checked'],1)==uint(cpuresult['total'],1))
    need(shutil.disk_usage(output.parent).free>=64*1024**3)
    checkpoint(5)
    binaries={}
    for group,repo,names in [('tempo',runtime,('tempo',)),('tools',tools,('txgen-tempo','bench'))]:
        checkpoint(10 if group=='tempo' else 20,role=1 if group=='tempo' else 2,abi=0,bytes=0,clean=0)
        with tempfile.TemporaryDirectory(prefix='prebuilt-build-',dir=output.parent) as temp:
            private=Path(temp);home=private/'cargo';home.mkdir();target=private/'target';target.mkdir()
            environment=remapped_environment(build_environment(os.environ,home,target,rustc),
                                               producer,repo,private,rustc)
            # Streaming build logs are private workflow logs, never artifact members.
            result=subprocess.run(build_command(group),cwd=repo,env=environment,timeout=3600,check=False)
            need(result.returncode==0)
            checkpoint(11 if group=='tempo' else 21)
            need(source(repo,RUNTIME if group=='tempo' else TOOLS,
                        'tempoxyz/tempo' if group=='tempo' else 'tempoxyz/txgen')==sources[group])
            for role in names:
                checkpoint(12,role=ROLES.index(role)+1,abi=0,bytes=0)
                profile='profiling' if role=='tempo' else 'release'
                original=target/TARGET/profile/role
                signature=hashed(original);destination=output/role
                checkpoint(13)
                with original.open('rb') as src,destination.open('xb') as dst:shutil.copyfileobj(src,dst,1024*1024)
                destination.chmod(0o700);need(hashed(destination)==signature)
                checkpoint(14)
                binaries[role]=dict(sources[group],profile=profile,default_features=role!='tempo',
                    features=FEATURES if role=='tempo' else [],rustflags=RUSTFLAGS,cflags=CFLAGS,cxxflags=CFLAGS,
                    **signature,abi=abi(destination))
    checkpoint(30,role=1)
    verify_marker(producer,output/'tempo')
    checkpoint(31,role=0)
    manifest=dict(schema=1,build_contract='x86_64_v3_locked_v1',producer_repository='tempoxyz/tempo',
        producer_workflow_path=WORKFLOW,producer_workflow_sha=expected,producer_run_id=run_id,
        producer_run_attempt=attempt,producer_workflow_sha256=hashed(producer/WORKFLOW)['sha256'],
        producer_script_sha256=hashed(producer/SCRIPT)['sha256'],build_image=IMAGE,target=TARGET,
        rust_toolchain=TOOLCHAIN,rustc_commit=RUSTC_COMMIT,rustc_llvm=LLVM,native_compiler=native,
        path_remap='owned_source_build_toolchain_v1',native_flags_guard='reject_host_native_v1',
        binaries=binaries,cpu_check=dict(source_sha256=hashed(producer/CPU_SOURCE)['sha256'],
            compiler_flags=CPU_FLAGS,**hashed(cpu),abi=abi(cpu)),
        runtime_dependencies={'reth':RETH,'commonware':COMMONWARE},
        registration=dict(symbol_verified=True,call_verified=True,verifier_sha256=hashed(producer/VERIFIER)['sha256']))
    checkpoint(32)
    validate_manifest(manifest)
    checkpoint(33)
    need(source(runtime,RUNTIME,'tempoxyz/tempo')==sources['tempo'] and source(tools,TOOLS,'tempoxyz/txgen')==sources['tools'])
    need(git(producer,'rev-parse','HEAD')==expected and git(producer,'status','--porcelain','--untracked-files=all')=='')
    need(hashed(cpu)=={k:manifest['cpu_check'][k] for k in ('bytes','sha256')})
    need(set(p.name for p in output.iterdir())==set(ROLES)|{'cpu-check'})
    for role in ROLES:need(hashed(output/role)=={k:manifest['binaries'][role][k] for k in ('bytes','sha256')})
    checkpoint(34)
    with (output/'manifest.json').open('x') as file:
        file.write(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n')
    print('{"schema":1,"built":true,"binaries":4}')


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1] in ('--native-gcc','--native-g++'):
        try:
            args=native_arguments(sys.argv[2:])
            compiler='/usr/bin/'+sys.argv[1][len('--native-'):]
            os.execv(compiler,[compiler,*args])
        except (Rejected,OSError):
            raise SystemExit('prebuilt_native_flags_rejected') from None
    parser=argparse.ArgumentParser()
    for name in ('producer','runtime','tools','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try:
        produce(*(getattr(args,name).absolute() for name in ('producer','runtime','tools','output')))
    except (Rejected,OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError,ImportError) as error:
        print(json.dumps(failure_receipt(error),sort_keys=True,separators=(',',':')),flush=True)
        raise SystemExit('prebuilt_producer_rejected') from None
