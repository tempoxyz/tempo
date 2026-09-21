import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import prebuilt as p
import prebuilt_consumer as c
import capacity_election as election


def fixture():
    abi=dict(elf_class=64,machine=62,little_endian=True,loader='glibc_x86_64',needed=['libc.so.6'],versions={'libc.so.6':['GLIBC_2.2.5']})
    base=dict(source_repository='tempoxyz/tempo',source_sha='1'*40,source_tree='2'*40,cargo_toml_sha256='3'*64,cargo_lock_sha256='4'*64,profile='profiling',default_features=False,features=p.FEATURES,rustflags=p.RUSTFLAGS,cflags=p.CFLAGS,cxxflags=p.CFLAGS,bytes=3,sha256=p.digest(b'abc'),abi=abi)
    binaries={'tempo':base}
    for role in ('txgen-tempo','bench'):binaries[role]={**base,'source_repository':'tempoxyz/txgen','source_sha':p.TOOLS,'profile':'release','default_features':True,'features':[]}
    m=dict(schema=1,path_remap='owned_source_build_toolchain_v1',native_flags_guard='reject_host_native_v1',build_contract='x86_64_v3_locked_v1',producer_repository='tempoxyz/tempo',producer_workflow_path=p.WORKFLOW,producer_workflow_sha='5'*40,producer_run_id=12,producer_run_attempt=2,producer_workflow_sha256='6'*64,producer_script_sha256='7'*64,build_image=p.IMAGE,target=p.TARGET,rust_toolchain=p.TOOLCHAIN,rustc_commit=p.RUSTC_COMMIT,rustc_llvm=p.LLVM,native_compiler={x:{'version':'11.4.0','sha256':'8'*64} for x in ('gcc','gxx')},binaries=binaries,cpu_check=dict(source_sha256='9'*64,compiler_flags=p.CPU_FLAGS,bytes=3,sha256=p.digest(b'abc'),abi={**abi,'loader':'none','needed':[],'versions':{}}),runtime_dependencies={'reth':'a'*40,'commonware':'b'*40},registration={'symbol_verified':True,'call_verified':True,'verifier_sha256':'c'*64})
    raw=json.dumps(m,sort_keys=True,separators=(',',':'))+'\n'
    item=dict(artifact_id=1,artifact_name='bench-prebuilt-v1-12-2',zip_bytes=10240,zip_sha256='d'*64,manifest_sha256=p.digest(raw.encode()),manifest_json=raw)
    plan=dict(schema=1,mode='prebuilt_v1',arms={'baseline':None,'feature':0},artifacts=[item])
    return plan,m


def encoded(plan):return json.dumps(plan,separators=(',',':')).encode()


class Contract(unittest.TestCase):
    def test_budget_is_additive_and_old_compilation_threshold_unchanged(self):
        plan,m=fixture();raw=encoded(plan)
        proof=p.budget(raw)
        self.assertEqual(proof['required_bytes'],p.CAPTURE_BYTES+10240+12+len(plan['artifacts'][0]['manifest_json'].encode())+(1<<20))
        self.assertEqual(election.REQUIRED_MIB,65536)
        self.assertEqual(proof['plan_sha256'],p.digest(raw))

    def test_closed_contract_mutations(self):
        plan,m=fixture()
        for mutate in (lambda x:x.update(schema=True),lambda x:x.update(extra=0),lambda x:x['arms'].update(feature=True),lambda x:x['artifacts'][0].update(zip_bytes=0),lambda x:x['artifacts'][0].update(manifest_json=x['artifacts'][0]['manifest_json']+' '),lambda x:x['arms'].update(feature=None)):
            value=copy.deepcopy(plan);mutate(value)
            with self.assertRaises((p.Rejected,ValueError)):p.validate_plan(encoded(value))
        with self.assertRaises(p.Rejected):p.parse(b'{"schema":1,"schema":1}')
        for mutate in (lambda x:x.update(rust_toolchain='1.96.1'),lambda x:x['binaries']['tempo'].update(rustflags=['-C','target-cpu=native']),lambda x:x['cpu_check'].update(compiler_flags=p.CFLAGS),lambda x:x['registration'].update(call_verified=False)):
            value=copy.deepcopy(m);mutate(value)
            with self.assertRaises(p.Rejected):p.validate_manifest(value)

    def test_compared_arms_require_same_tools_and_build_contract(self):
        plan,m=fixture();second=copy.deepcopy(plan['artifacts'][0]);second['artifact_id']=2
        plan['artifacts'].append(second);plan['arms']['baseline']=1
        p.validate_plan(encoded(plan))
        m['binaries']['bench']['sha256']='e'*64
        second['manifest_json']=json.dumps(m);second['manifest_sha256']=p.digest(second['manifest_json'].encode())
        with self.assertRaises(p.Rejected):p.validate_plan(encoded(plan))

    def test_cpu_all_intended_masks_are_admitted(self):
        report=b'{"schema":1,"supported":true,"checked":4,"total":4}'
        with patch.object(c.os,'sched_getaffinity',return_value={0,1,2,3}),patch.object(c,'checked',return_value=report):
            self.assertEqual(c.admit_cpu(Path('/unused'),['0-1','2-3'])[0]['checked'],4)
            with self.assertRaises(p.Rejected):c.admit_cpu(Path('/unused'),['0-4'])
        for report in (b'{"schema":1,"supported":false,"checked":4,"total":4}',b'{"schema":1,"supported":true,"checked":3,"total":4}'):
            with patch.object(c.os,'sched_getaffinity',return_value={0,1,2,3}),patch.object(c,'checked',return_value=report),self.assertRaises(p.Rejected):c.admit_cpu(Path('/unused'),['0-3'])

    def test_exact_zip_and_unsafe_members(self):
        plan,m=fixture();item=plan['artifacts'][0]
        def archive(extra=None,codec=zipfile.ZIP_STORED):
            out=io.BytesIO()
            with zipfile.ZipFile(out,'w',compression=codec) as z:
                for role in c.MEMBERS:z.writestr(role,item['manifest_json'].encode() if role=='manifest.json' else b'abc')
                if extra:z.writestr(extra,b'abc')
            return out.getvalue()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for n,(extra,codec,valid) in enumerate([(None,zipfile.ZIP_STORED,True),('../escape',zipfile.ZIP_STORED,False),('tempo',zipfile.ZIP_STORED,False),(None,zipfile.ZIP_BZIP2,False)]):
                raw=archive(extra,codec);item['zip_bytes']=len(raw);item['zip_sha256']=p.digest(raw);path=root/f'{n}.zip';path.write_bytes(raw)
                if valid:
                    c.extract(path,root/f'out{n}',item,m)
                    self.assertEqual((root/f'out{n}'/'tempo').read_bytes(),b'abc')
                else:
                    with self.assertRaises(p.Rejected):c.extract(path,root/f'out{n}',item,m)
            self.assertFalse((root.parent/'escape').exists())

    def test_phase_rechecks_binaries_affinity_and_loader_environment(self):
        plan,m=fixture();raw=encoded(plan);item=plan['artifacts'][0]
        cpu={'schema':1,'supported':True,'checked':4,'total':4}
        admission={'schema':1,'mode':'prebuilt_v1','capacity':p.budget(raw),'artifacts':[{k:item[k] for k in ('artifact_id','zip_sha256','manifest_sha256')}|{'cpu':cpu}]}
        with tempfile.TemporaryDirectory() as d,patch.object(c.os,'sched_getaffinity',return_value={0,1,2,3}),patch.object(c,'free_space'):
            root=Path(d);bundle=root/'bundle-0';bundle.mkdir()
            for role in p.ROLES:(bundle/role).write_bytes(b'abc')
            (root/'plan.json').write_bytes(raw);(root/'admission.json').write_text(json.dumps(admission))
            (root/'private.json').write_text(json.dumps({'affinity':[0,1,2,3],'bundles':[str(bundle)]}))
            def select():return c.selected(root,'feature','1'*40,','.join(p.FEATURES),'profiling',True,['0-1','2-3'])
            self.assertEqual(select()['tempo'],str(bundle/'tempo'))
            for role in p.ROLES:
                (bundle/role).write_bytes(b'changed')
                with self.assertRaises(p.Rejected):select()
                (bundle/role).write_bytes(b'abc')
            (bundle/'tempo').unlink();(bundle/'tempo').symlink_to(bundle/'bench')
            with self.assertRaises(p.Rejected):select()
            (bundle/'tempo').unlink();(bundle/'tempo').write_bytes(b'abc')
            with patch.object(c.os,'sched_getaffinity',return_value={0,1,2,3,4}),self.assertRaises(p.Rejected):select()
            for key in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT','GLIBC_TUNABLES'):
                with patch.dict(os.environ,{key:'private'}),self.assertRaises(p.Rejected):select()

    def test_actual_system_elf_loader_resolution_and_mismatched_abi(self):
        binary=Path('/usr/bin/true')
        if not binary.exists():self.skipTest('system ELF absent')
        abi=c.inspect_abi(binary);c.host_abi(binary,abi)
        abi['versions']['libc.so.6'].append('GLIBC_99.99')
        with self.assertRaises(p.Rejected):c.host_abi(binary,abi)

    def test_fixed_loader_resolution_accepts_direct_entry_only(self):
        direct='\t/lib64/ld-linux-x86-64.so.2 (0x1234)\n'
        self.assertEqual(c.resolved_libraries(direct)[c.LOADER_SONAME],Path(c.LOADER).resolve())
        for text in (direct+direct,'/other/ld-linux-x86-64.so.2 (0x1234)\n','ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x1234)\n','/lib64/ld-linux-aarch64.so.1 (0x1234)\n'):
            with self.assertRaises(p.Rejected):c.resolved_libraries(text)
        with patch.object(Path,'stat',return_value=type('S',(),{'st_mode':stat.S_IFREG|0o777,'st_uid':0})()),self.assertRaises(p.Rejected):c.trusted_library(c.LOADER)

    @unittest.skipUnless(shutil.which('nu'),'installed Rust ELF fixture unavailable')
    def test_installed_rust_elf_loader_needed_and_versions_without_execution(self):
        binary=Path(shutil.which('nu'))
        abi=c.inspect_abi(binary)
        # Skip another platform's Nu build; the synthetic direct-line fixture
        # above still checks the exact loader parsing contract everywhere.
        if c.LOADER_SONAME not in abi['needed']:self.skipTest('fixture does not declare loader DT_NEEDED')
        self.assertIn(c.LOADER_SONAME,abi['versions'])
        c.host_abi(binary,abi) # readelf + system loader --verify/--list only.
        wrong=copy.deepcopy(abi);wrong['needed'].append('ld-foreign.so.2')
        with self.assertRaises(p.Rejected):p.validate_abi(wrong)

    def test_prebuilt_election_requires_exact_derived_bytes_and_receipt_proof(self):
        from test_capacity_election import BINDING, receipt
        plan,_=fixture();raw=encoded(plan);proof=p.budget(raw)
        rows=[receipt(i) for i in range(1,6)]
        for row in rows:
            row['prebuilt']=proof.copy()
            for location in row['capacity']['locations'][:2]:location['free_bytes']=proof['required_bytes']-1
        def elect(values):return election.elect(values,**BINDING,slots=5,setup_failed_slots=[],prebuilt_plan=raw.decode())
        self.assertEqual(elect(rows)['status'],2)
        for location in rows[4]['capacity']['locations'][:2]:location['free_bytes']+=1
        self.assertEqual(elect(rows)['selected_slot'],5)
        for bad in ({**proof,'required_bytes':proof['required_bytes']-1},{**proof,'plan_sha256':'0'*64},{**proof,'extra':0}):
            values=copy.deepcopy(rows);values[0]['prebuilt']=bad
            with self.assertRaises(election.InvalidReceipt):elect(values)
        with self.assertRaises(election.InvalidReceipt):election.elect(rows,**BINDING,slots=5,setup_failed_slots=[])
        values=copy.deepcopy(rows);del values[0]['prebuilt']
        with self.assertRaises(election.InvalidReceipt):elect(values)

    def test_download_does_not_forward_token_to_blob_redirect(self):
        import urllib.error
        import urllib.request
        class Response(io.BytesIO):
            status=200
            headers={'Content-Length':'3'}
        for location,valid in [('https://owned.blob.core.windows.net/artifact?secret=1',True),('https://attacker.invalid/artifact',False),('http://owned.blob.core.windows.net/artifact',False)]:
            calls=[]
            class Opener:
                def open(self,request,timeout):
                    calls.append(request)
                    if len(calls)==1:raise urllib.error.HTTPError(request.full_url,302,'',{'Location':location},None)
                    selftest.assertIsNone(request.get_header('Authorization'))
                    return Response(b'abc')
            selftest=self;transport=c.Transport('PRIVATE_TOKEN');transport.opener=Opener()
            with tempfile.TemporaryDirectory() as d:
                if valid:transport.download(1,Path(d)/'bundle.zip',{'bytes':3,'sha256':p.digest(b'abc')})
                else:
                    with self.assertRaises(p.Rejected):transport.download(1,Path(d)/'bundle.zip',{'bytes':3,'sha256':p.digest(b'abc')})
            self.assertEqual(calls[0].get_header('Authorization'),'Bearer PRIVATE_TOKEN')
            self.assertEqual(len(calls),2 if valid else 1)

    def test_authentic_attempt_and_artifact_digest_required(self):
        plan,m=fixture();item=plan['artifacts'][0]
        run={'id':12,'run_attempt':2,'head_sha':'5'*40,'event':'workflow_dispatch','path':p.WORKFLOW,'status':'completed','conclusion':'success','repository':{'full_name':'tempoxyz/tempo'}}
        artifact={'id':1,'name':item['artifact_name'],'expired':False,'size_in_bytes':10240,'digest':'sha256:'+item['zip_sha256'],'workflow_run':{'id':12,'head_sha':'5'*40}}
        class Fake:
            def api(self,path):return run if '/runs/' in path else artifact
        c.metadata(Fake(),item,m)
        for value,key,bad in [(run,'run_attempt',1),(run,'conclusion','failure'),(artifact,'digest','sha256:'+'0'*64),(artifact,'expired',True)]:
            old=value[key];value[key]=bad
            with self.assertRaises(p.Rejected):c.metadata(Fake(),item,m)
            value[key]=old


if __name__=='__main__':unittest.main()
