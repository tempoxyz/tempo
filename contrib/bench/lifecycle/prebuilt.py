"""Closed portable-build contract and capacity arithmetic; no runner mutation."""
import hashlib
import json
import re

TOOLS = '94f86f186cd18f641eb9699d7e31c9e536de7c17'
RETH = '1c674b8670b257325df9dd1754efc1d20fe62293'
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
CFLAGS = ['-march=x86-64-v3', '-mtune=generic', '-DNO_PCLMUL']
CPU_FLAGS = ['-static', '-O2', '-march=x86-64', '-mtune=generic']
FEATURES = ['asm-keccak', 'jemalloc', 'keccak-cache-global']
ROLES = ('tempo', 'txgen-tempo', 'bench')
SONAMES = {'ld-linux-x86-64.so.2', 'libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'librt.so.1',
           'libgcc_s.so.1', 'libstdc++.so.6', 'libudev.so.1', 'libssl.so.3',
           'libcrypto.so.3', 'libz.so.1', 'libzstd.so.1', 'libatomic.so.1'}
MAX_BINARY = 2 * 1024**3
MAX_MANIFEST = 65536
JS_MAX = 2**53-1


class Rejected(ValueError):
    pass


def need(condition):
    if not condition:
        raise Rejected('prebuilt_contract_rejected')


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
        'native_compiler','binaries','cpu_check','runtime_dependencies','registration','path_remap','native_flags_guard'))
    need(type(value['schema']) is int and value['schema']==1)
    for key, expected in {'build_contract':'x86_64_v3_locked_v1','producer_repository':'tempoxyz/tempo',
        'producer_workflow_path':WORKFLOW,'build_image':IMAGE,'target':TARGET,'rust_toolchain':TOOLCHAIN,
        'rustc_commit':RUSTC_COMMIT,'rustc_llvm':LLVM,'path_remap':'owned_source_build_toolchain_v1','native_flags_guard':'reject_host_native_v1'}.items(): need(value[key]==expected)
    for key in ('producer_workflow_sha256','producer_script_sha256'): sha(value[key])
    sha(value['producer_workflow_sha'],40)
    uint(value['producer_run_id'],1); uint(value['producer_run_attempt'],1)
    keys(value['runtime_dependencies'],('reth','commonware'))
    for revision in value['runtime_dependencies'].values(): sha(revision,40)
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
        sha(item['source_sha'],40); sha(item['source_tree'],40)
        if role!='tempo': need(item['source_sha']==TOOLS)
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

PLAN_PATH = 'contrib/bench/lifecycle/prebuilt-plan.json'
BINARY_MODE = 'prebuilt_v1'
CAPACITY_MODE = 'prebuilt_capture_v1'
CAPTURE_BYTES = 49152 * (1 << 20)
MAX_ZIP = 7 * 1024**3
MAX_PLAN = 65536


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(data):
    need(type(data) is bytes and len(data) <= MAX_PLAN)
    def invalid(_): raise Rejected('prebuilt_contract_rejected')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def manifest_bytes(item):
    need(type(item['manifest_json']) is str)
    raw=item['manifest_json'].encode('utf-8')
    need(digest(raw)==sha(item['manifest_sha256']))
    return raw


def validate_plan(data):
    plan=parse(data)
    keys(plan,('schema','mode','arms','artifacts'))
    need(type(plan['schema']) is int and plan['schema']==1 and plan['mode']==BINARY_MODE)
    keys(plan['arms'],('baseline','feature'))
    items=plan['artifacts'];need(type(items) is list and 1<=len(items)<=2)
    used=set();identities=set();manifests=[]
    for arm,index in plan['arms'].items():
        if index is not None: used.add(uint(index,0,len(items)-1))
    need(used==set(range(len(items))))
    for item in items:
        keys(item,('artifact_id','artifact_name','zip_bytes','zip_sha256','manifest_sha256','manifest_json'))
        ident=uint(item['artifact_id'],1);need(ident not in identities);identities.add(ident)
        uint(item['zip_bytes'],1,MAX_ZIP);sha(item['zip_sha256'])
        raw=manifest_bytes(item);manifest=validate_manifest(parse(raw));manifests.append(manifest)
        need(item['artifact_name']==f"bench-prebuilt-v1-{manifest['producer_run_id']}-{manifest['producer_run_attempt']}")
    # Tools/compiler/target/flags must match across arms, not only Tempo's source.
    if len(manifests)==2:
        a,b=manifests
        for key in ('build_contract','build_image','target','rust_toolchain','rustc_commit','rustc_llvm','native_compiler','cpu_check'):
            need(a[key]==b[key])
        for role in ('txgen-tempo','bench'):need(a['binaries'][role]==b['binaries'][role])
    return plan


def budget(data):
    plan=validate_plan(data)
    # Conservatively retain every ZIP and every extracted bundle simultaneously.
    # The manifest, admission and fixed wrapper files get a separate 1 MiB reserve.
    transfer=0
    for item in plan['artifacts']:
        manifest=parse(manifest_bytes(item))
        transfer+=item['zip_bytes']+sum(v['bytes'] for v in manifest['binaries'].values())+manifest['cpu_check']['bytes']+len(manifest_bytes(item))
    return {'mode':CAPACITY_MODE,'plan_sha256':digest(data),'required_bytes':CAPTURE_BYTES+transfer+(1<<20)}


def arm(plan, name):
    need(name in ('baseline','feature'))
    index=plan['arms'][name];need(index is not None)
    item=plan['artifacts'][index]
    return item,parse(manifest_bytes(item))


if __name__=='__main__':
    import sys
    try:
        need(len(sys.argv)==1)
        print(json.dumps(budget(sys.stdin.buffer.read(MAX_PLAN+1)),separators=(',',':')))
    except (Rejected,ValueError,TypeError,KeyError,RecursionError,OverflowError):
        raise SystemExit('prebuilt_contract_rejected') from None
