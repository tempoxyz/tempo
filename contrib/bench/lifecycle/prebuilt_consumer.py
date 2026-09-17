"""Authenticated portable bundle retrieval. All errors are closed and path-free."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from prebuilt import (BINARY_MODE, CAPTURE_BYTES, MAX_BINARY, MAX_PLAN, PLAN_PATH,
                      ROLES, SONAMES, Rejected, arm, budget, digest, keys,
                      manifest_bytes, need, pairs, parse, sha, uint, validate_abi,
                      validate_plan)

MEMBERS = set(ROLES) | {'cpu-check','manifest.json'}
BLOCK = 1024 * 1024


def identity(path):
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and not path.is_symlink())
    return st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns


def signature(path):
    before=identity(path);h=hashlib.sha256()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        current=os.fstat(f.fileno());need((current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns)==before)
        for chunk in iter(lambda:f.read(BLOCK),b''):h.update(chunk)
    need(identity(path)==before)
    return {'bytes':before[2],'sha256':h.hexdigest()}


def checked(args, timeout=60):
    # Do not inherit LD_PRELOAD, LD_LIBRARY_PATH, Python, Cargo or tool wrappers.
    run=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'},timeout=timeout)
    need(run.returncode==0 and len(run.stdout)<=32*BLOCK and len(run.stderr)<=32*BLOCK)
    return run.stdout


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None


class Transport:
    def __init__(self, token):
        need(type(token) is str and 0<len(token)<10000)
        self.token=token
        self.opener=urllib.request.build_opener(NoRedirect)

    def request(self,path):
        need(re.fullmatch(r'repos/tempoxyz/tempo/[A-Za-z0-9_./?=&-]+',path) is not None)
        return urllib.request.Request('https://api.github.com/'+path,headers={
            'Authorization':'Bearer '+self.token,'Accept':'application/vnd.github+json',
            'X-GitHub-Api-Version':'2022-11-28'})

    def api(self,path):
        with self.opener.open(self.request(path),timeout=30) as response:
            need(response.status==200)
            raw=response.read(2*BLOCK+1);need(len(raw)<=2*BLOCK)
        return json.loads(raw,object_pairs_hook=pairs)

    def download(self,ident,destination,expected):
        request=self.request(f'repos/tempoxyz/tempo/actions/artifacts/{uint(ident,1)}/zip')
        try:
            response=self.opener.open(request,timeout=30)
        except urllib.error.HTTPError as error:
            need(error.code==302)
            location=error.headers.get('Location');need(type(location) is str)
            url=urllib.parse.urlsplit(location)
            need(url.scheme=='https' and url.port in (None,443) and not url.username and not url.password)
            need(re.fullmatch(r'[a-z0-9-]+\.blob\.core\.windows\.net',url.hostname or '') is not None)
            # Signed object storage receives no GitHub authorization header.
            response=self.opener.open(urllib.request.Request(location),timeout=30)
        h=hashlib.sha256();total=0;deadline=time.monotonic()+600
        with response, destination.open('xb') as output:
            need(response.status==200)
            length=response.headers.get('Content-Length')
            if length is not None:need(length.isdecimal() and int(length)==expected['bytes'])
            while True:
                need(time.monotonic()<deadline)
                chunk=response.read(min(BLOCK,expected['bytes']-total+1))
                if not chunk:break
                total+=len(chunk);need(total<=expected['bytes']);h.update(chunk);output.write(chunk)
        need({'bytes':total,'sha256':h.hexdigest()}==expected)


def metadata(transport,item,manifest):
    base='repos/tempoxyz/tempo'
    run=transport.api(f"{base}/actions/runs/{manifest['producer_run_id']}/attempts/{manifest['producer_run_attempt']}")
    need(run.get('id')==manifest['producer_run_id'] and type(run.get('id')) is int)
    need(run.get('run_attempt')==manifest['producer_run_attempt'] and type(run.get('run_attempt')) is int)
    need(run.get('head_sha')==manifest['producer_workflow_sha'] and run.get('event')=='workflow_dispatch')
    need(run.get('path')==manifest['producer_workflow_path'] and run.get('status')=='completed' and run.get('conclusion')=='success')
    need(run.get('repository',{}).get('full_name')=='tempoxyz/tempo')
    artifact=transport.api(f"{base}/actions/artifacts/{item['artifact_id']}")
    need(artifact.get('id')==item['artifact_id'] and type(artifact.get('id')) is int)
    need(artifact.get('name')==item['artifact_name'] and artifact.get('expired') is False)
    need(type(artifact.get('size_in_bytes')) is int and artifact['size_in_bytes']==item['zip_bytes'])
    need(artifact.get('digest')=='sha256:'+item['zip_sha256'])
    linked=artifact.get('workflow_run',{})
    need(type(linked.get('id')) is int and linked.get('id')==manifest['producer_run_id'] and linked.get('head_sha')==manifest['producer_workflow_sha'])
    # Exact attempt is also bound by immutable artifact name and manifest bytes.
    return run,artifact


def extract(archive_path,destination,item,manifest):
    need(not destination.exists() and destination.parent.resolve()==destination.parent)
    destination.mkdir(mode=0o700)
    need(signature(archive_path)=={'bytes':item['zip_bytes'],'sha256':item['zip_sha256']})
    expected={role:{k:manifest['binaries'][role][k] for k in ('bytes','sha256')} for role in ROLES}
    expected['cpu-check']={k:manifest['cpu_check'][k] for k in ('bytes','sha256')}
    raw=manifest_bytes(item);expected['manifest.json']={'bytes':len(raw),'sha256':digest(raw)}
    with zipfile.ZipFile(archive_path) as archive:
        infos=archive.infolist();need(len(infos)==len(MEMBERS) and {i.filename for i in infos}==MEMBERS)
        for entry in infos:
            need(not entry.is_dir() and entry.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED))
            need(not entry.flag_bits&1 and stat.S_IFMT(entry.external_attr>>16) in (0,stat.S_IFREG))
            need(entry.file_size==expected[entry.filename]['bytes'] and 0<entry.compress_size<=item['zip_bytes'])
        for entry in infos:
            target=destination/entry.filename;h=hashlib.sha256();total=0
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as out,archive.open(entry) as source:
                while True:
                    chunk=source.read(min(BLOCK,entry.file_size-total+1))
                    if not chunk:break
                    total+=len(chunk);need(total<=entry.file_size);h.update(chunk);out.write(chunk)
            need({'bytes':total,'sha256':h.hexdigest()}==expected[entry.filename])
    need((destination/'manifest.json').read_bytes()==raw)
    for role in MEMBERS-{'manifest.json'}:(destination/role).chmod(0o500)
    need(signature(archive_path)=={'bytes':item['zip_bytes'],'sha256':item['zip_sha256']})


def inspect_abi(binary):
    with binary.open('rb') as stream:header=stream.read(64)
    need(len(header)==64 and header[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',header,18)[0]==62)
    text=checked(['/usr/bin/readelf','-lW',str(binary)]).decode()
    loaders=re.findall(r'\[Requesting program interpreter: ([^\]]+)\]',text)
    need(loaders in ([],['/lib64/ld-linux-x86-64.so.2']))
    dynamic=checked(['/usr/bin/readelf','-dW',str(binary)]).decode()
    need(not re.search(r'\((RPATH|RUNPATH|AUDIT|DEPAUDIT|FILTER|AUXILIARY)\)',dynamic))
    needed=re.findall(r'\(NEEDED\).*Shared library: \[([^\]]+)\]',dynamic)
    need(len(needed)==len(set(needed)) and set(needed)<=SONAMES)
    versions={};library=None
    for line in checked(['/usr/bin/readelf','-VW',str(binary)]).decode().splitlines():
        found=re.search(r'File: (\S+)\s+Cnt:',line)
        if found:library=found[1];need(library in needed and library not in versions);versions[library]=[]
        found=re.search(r'Name: (\S+)\s+Flags:',line)
        if found and library is not None:versions[library].append(found[1])
    value=dict(elf_class=64,machine=62,little_endian=True,loader='glibc_x86_64' if loaders else 'none',needed=sorted(needed),versions={k:sorted(set(v)) for k,v in sorted(versions.items())})
    validate_abi(value);return value


LOADER = '/lib64/ld-linux-x86-64.so.2'
LOADER_SONAME = 'ld-linux-x86-64.so.2'


def trusted_library(path):
    actual=Path(path).resolve();st=actual.stat()
    need(str(actual).startswith(('/usr/lib/','/lib/')) and stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022)
    return actual


def resolved_libraries(text):
    resolved={}
    for line in text.splitlines():
        # glibc prints its interpreter directly, even when Rust also declares
        # that exact loader as DT_NEEDED. Do not generalize arbitrary paths.
        direct=re.fullmatch(r'\s*/lib64/ld-linux-x86-64\.so\.2 \(0x[0-9a-f]+\)\s*',line)
        found=re.fullmatch(r'\s*(\S+) => (/\S+) \(0x[0-9a-f]+\)\s*',line)
        if direct:
            name,path=LOADER_SONAME,LOADER
        elif found:
            name,path=found.groups();need(name!=LOADER_SONAME)
        else:
            continue
        need(name not in resolved);resolved[name]=trusted_library(path)
    need(LOADER_SONAME in resolved)
    return resolved


def host_abi(binary,expected):
    need(inspect_abi(binary)==expected)
    if expected['loader']=='none':return
    trusted_library(LOADER)
    checked([LOADER,'--verify',str(binary)])
    # --list resolves/verifies version requirements without entering the program.
    resolved=resolved_libraries(checked([LOADER,'--list',str(binary)]).decode())
    need(set(expected['needed'])<=set(resolved))
    for library,requirements in expected['versions'].items():
        available=set(re.findall(r'Name: (\S+)',checked(['/usr/bin/readelf','-VW',str(resolved[library])]).decode()))
        need(set(requirements)<=available)


def cpu_mask(text):
    need(type(text) is str and re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*',text))
    values=set()
    for part in text.split(','):
        pair=list(map(int,part.split('-')));lo=pair[0];hi=pair[-1]
        need(0<=lo<=hi<8192);values.update(range(lo,hi+1))
    need(values);return values


def admit_cpu(checker,masks):
    before=os.sched_getaffinity(0)
    need(before and all(cpu_mask(mask)<=before for mask in masks))
    result=parse(checked([str(checker)]))
    keys(result,('schema','supported','checked','total'))
    need(type(result['schema']) is int and result['schema']==1 and result['supported'] is True)
    need(uint(result['checked'],1)==uint(result['total'],1)==len(before))
    need(os.sched_getaffinity(0)==before)
    return result,sorted(before)


def free_space(directory,required):
    need(shutil.disk_usage('/').free>=required and shutil.disk_usage(directory).free>=required)


def loader_environment(env):
    # Match the admission loader environment; no inherited loader overrides.
    need(not any(key.startswith('LD_') or key=='GLIBC_TUNABLES' for key in env))


def prepare(plan_path,output,token,masks):
    loader_environment(os.environ)
    data=plan_path.read_bytes();plan=validate_plan(data);proof=budget(data)
    need(not output.exists() and output.parent.resolve()==output.parent)
    free_space(output.parent,proof['required_bytes']);output.mkdir(mode=0o700)
    transport=Transport(token);bundles=[];public=[];affinity=None
    for index,item in enumerate(plan['artifacts']):
        manifest=parse(manifest_bytes(item));first=metadata(transport,item,manifest)
        archive=output/f'{index}.zip'
        transport.download(item['artifact_id'],archive,{'bytes':item['zip_bytes'],'sha256':item['zip_sha256']})
        bundle=output/f'bundle-{index}';extract(archive,bundle,item,manifest)
        host_abi(bundle/'cpu-check',manifest['cpu_check']['abi'])
        cpu,mask=admit_cpu(bundle/'cpu-check',masks)
        need(affinity is None or mask==affinity);affinity=mask
        for role in ROLES:host_abi(bundle/role,manifest['binaries'][role]['abi'])
        need(metadata(transport,item,manifest)==first)
        bundles.append(str(bundle));public.append({'artifact_id':item['artifact_id'],'zip_sha256':item['zip_sha256'],'manifest_sha256':item['manifest_sha256'],'cpu':cpu})
        archive.unlink() # Only this newly created, exact verified transport.
    receipt={'schema':1,'mode':BINARY_MODE,'capacity':proof,'artifacts':public}
    (output/'admission.json').write_text(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n')
    (output/'plan.json').write_bytes(data)
    (output/'private.json').write_text(json.dumps({'bundles':bundles,'affinity':affinity}))
    return receipt


def selected(directory,name,runtime,features,profile,no_defaults,masks):
    loader_environment(os.environ)
    need(directory.resolve()==directory)
    data=(directory/'plan.json').read_bytes();plan=validate_plan(data)
    receipt=parse((directory/'admission.json').read_bytes());need(receipt['capacity']==budget(data))
    private=parse((directory/'private.json').read_bytes())
    keys(private,('bundles','affinity'))
    need(type(private['bundles']) is list and len(private['bundles'])==len(plan['artifacts']))
    mask=private['affinity'];need(type(mask) is list and mask and all(type(cpu) is int and 0<=cpu<8192 for cpu in mask) and mask==sorted(set(mask)))
    keys(receipt,('schema','mode','capacity','artifacts'))
    need(type(receipt['schema']) is int and receipt['schema']==1 and receipt['mode']==BINARY_MODE)
    need(type(receipt['artifacts']) is list and len(receipt['artifacts'])==len(plan['artifacts']))
    for row,item in zip(receipt['artifacts'],plan['artifacts']):
        keys(row,('artifact_id','zip_sha256','manifest_sha256','cpu'))
        need(type(row['artifact_id']) is int and all(row[k]==item[k] for k in ('artifact_id','zip_sha256','manifest_sha256')))
        cpu=row['cpu'];keys(cpu,('schema','supported','checked','total'))
        need(type(cpu['schema']) is int and cpu['schema']==1 and cpu['supported'] is True)
        need(uint(cpu['checked'],1)==uint(cpu['total'],1)==len(mask))
    need(set(os.sched_getaffinity(0))<=set(private['affinity']))
    need(all(cpu_mask(mask)<=set(private['affinity']) for mask in masks))
    item,manifest=arm(plan,name);binary=manifest['binaries']['tempo']
    need(runtime==binary['source_sha'] and profile==binary['profile'] and no_defaults is True)
    need(sorted(set(features.split(',')))==binary['features'])
    index=plan['arms'][name];bundle=directory/f'bundle-{index}'
    need(str(bundle)==private['bundles'][index] and bundle.resolve()==bundle)
    for role in ROLES:
        need(signature(bundle/role)=={k:manifest['binaries'][role][k] for k in ('bytes','sha256')})
    free_space(directory,CAPTURE_BYTES)
    tools=directory/'bundle-0'
    for role in ('txgen-tempo','bench'):
        need(signature(tools/role)=={k:manifest['binaries'][role][k] for k in ('bytes','sha256')})
    return {'tempo':str(bundle/'tempo'),'txgen_tempo':str(tools/'txgen-tempo'),'bench':str(tools/'bench')}


def main():
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='command',required=True)
    prep=sub.add_parser('prepare');prep.add_argument('--plan',type=Path,required=True);prep.add_argument('--output',type=Path,required=True)
    select=sub.add_parser('select');select.add_argument('--directory',type=Path,required=True)
    for key in ('arm','runtime','features','profile'):select.add_argument('--'+key,required=True)
    select.add_argument('--no-default-features',action='store_true')
    for child in (prep,select):child.add_argument('--cpus',action='append',required=True)
    args=parser.parse_args()
    try:
        need(os.environ.get('BENCH_BINARY_MODE')==BINARY_MODE)
        plan_data=(args.plan if args.command=='prepare' else args.directory/'plan.json').read_bytes()
        need(digest(plan_data)==os.environ.get('BENCH_PREBUILT_PLAN_SHA256'))
        if args.command=='prepare':result=prepare(args.plan,args.output,os.environ.get('GH_TOKEN'),args.cpus)
        else:result=selected(args.directory,args.arm,args.runtime,args.features,args.profile,args.no_default_features,args.cpus)
        print(json.dumps(result,separators=(',',':')))
    except (Rejected,ValueError,TypeError,KeyError,OSError,subprocess.SubprocessError,zipfile.BadZipFile,RuntimeError):
        raise SystemExit('prebuilt_consumer_rejected') from None


if __name__=='__main__':main()
