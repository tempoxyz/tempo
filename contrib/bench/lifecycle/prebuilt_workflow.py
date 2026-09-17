"""Closed workflow adapter; binaries admitted before any portable tool executes."""
import json
import os
from pathlib import Path
import re
import tempfile
from prebuilt import BINARY_MODE, PLAN_PATH, TOOLS, digest, need, validate_plan
from prebuilt_consumer import loader_environment, prepare, selected


def inputs(env):
    loader_environment(env)
    need(env.get('BENCH_BINARY_MODE')==BINARY_MODE)
    for name in ('BENCH_LIFECYCLE','BENCH_NO_SLACK'):need(env.get(name)=='true')
    for name in ('BENCH_FORCE_BLOAT','BENCH_NO_CACHE','BENCH_SAMPLY','BENCH_OTLP','BENCH_VALSCOPE'):need(env.get(name)=='false')
    need(env.get('BENCH_TRACY')=='off' and env.get('BENCH_TXGEN_REF')==TOOLS)
    for name in ('BENCH_BASELINE_FEATURES','BENCH_FEATURE_FEATURES','BENCH_BASELINE_ENV','BENCH_FEATURE_ENV','BENCH_BENCH_ENV'):need(env.get(name,'')=='')
    need(env.get('BENCH_FEATURES')=='jemalloc,asm-keccak,keccak-cache-global')
    sides={'feature':['feature'],'baseline':['baseline'],'comparison':['baseline','feature']}
    need(env.get('BENCH_RUN_SIDE') in sides)
    return sides[env['BENCH_RUN_SIDE']]


def main():
    env=os.environ;required=inputs(env)
    plan_path=Path(PLAN_PATH);data=plan_path.read_bytes()
    need(digest(data)==env.get('BENCH_PREBUILT_PLAN_SHA256'));plan=validate_plan(data)
    need({side for side,index in plan['arms'].items() if index is not None}==set(required))
    for side in required:
        m=json.loads(plan['artifacts'][plan['arms'][side]]['manifest_json'])
        need(m['binaries']['tempo']['source_sha']==env.get('PREBUILT_'+side.upper()+'_REF'))
    workspace=Path(env['GITHUB_WORKSPACE']);need(workspace.resolve()==workspace and re.fullmatch(r'[A-Za-z0-9_/.-]+',str(workspace)))
    parent=Path(tempfile.mkdtemp(prefix='.prebuilt-',dir=workspace));output=parent/'admitted'
    masks=['0-7,16-23','8-15,24-31']
    prepare(plan_path,output,env.get('GH_TOKEN'),masks)
    mapping=None
    for side in required:
        value=selected(output,side,env['PREBUILT_'+side.upper()+'_REF'],env['BENCH_FEATURES'],'profiling',True,masks)
        if mapping is not None:need(value['txgen_tempo']==mapping['txgen_tempo'] and value['bench']==mapping['bench'])
        mapping=value
    values={'BENCH_PREBUILT_DIRECTORY':str(output),'TXGEN_TEMPO_BIN':mapping['txgen_tempo'],'TXGEN_BENCH_BIN':mapping['bench']}
    with open(env['GITHUB_ENV'],'a') as target:
        for name,value in values.items():need('\n' not in value and '\r' not in value);target.write(name+'='+value+'\n')
    print('{"schema":1,"prebuilt_admitted":true}')


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('prebuilt_workflow_rejected') from None
