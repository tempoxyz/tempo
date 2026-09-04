#!/usr/bin/env python3
"""Read-only Linux storage/host metadata and one-second OS counters."""
import json,os,platform,signal,subprocess,sys,time
from pathlib import Path

def read(path):
    try:return Path(path).read_text().strip()
    except OSError:return None

def command(argv):
    try:
        p=subprocess.run(argv,text=True,capture_output=True,timeout=15)
        return {'argv':argv,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    except (OSError,subprocess.TimeoutExpired) as e:return {'argv':argv,'error':str(e)}

if sys.argv[1]=='metadata':
    target,label=sys.argv[2:4]
    block={}
    for p in Path('/sys/class/block').glob('*'):
        fields=['dev','size','ro','queue/scheduler','queue/write_cache','queue/fua','queue/nr_requests','queue/max_sectors_kb','queue/max_hw_sectors_kb','queue/read_ahead_kb','queue/rotational','queue/logical_block_size','queue/physical_block_size','queue/discard_max_bytes','queue/discard_granularity','device/model','device/firmware_rev','device/numa_node']
        block[p.name]={k:read(p/k) for k in fields}
        block[p.name]['slaves']=[s.name for s in (p/'slaves').glob('*')]
        block[p.name]['holders']=[s.name for s in (p/'holders').glob('*')]
    paths=['/proc/meminfo','/proc/swaps','/proc/mounts','/proc/cmdline','/sys/kernel/mm/transparent_hugepage/enabled']
    paths += [str(p) for p in Path('/proc/sys/vm').glob('*') if p.name.startswith('dirty_')]
    data={'timestamp':time.time(),'label':label,'target':target,'hostname':platform.node(),'kernel':platform.release(),'block':block,'files':{p:read(p) for p in paths},'commands':[
      command(['fio','--version']),command(['lscpu','-J']),command(['findmnt','-J','-T',target]),
      command(['lsblk','-b','-J','-o','NAME,KNAME,PATH,TYPE,SIZE,ROTA,MODEL,SERIAL,FSTYPE,MOUNTPOINTS,DISC-GRAN,DISC-MAX,PHY-SEC,LOG-SEC']),
      command(['df','-B1',target]),command(['dmsetup','table','--target','era']),command(['dmsetup','status','--target','era']),command(['lsblk','-f'])]}
    for p in Path('/sys/class/nvme').glob('nvme[0-9]*'):
        node='/dev/'+p.name
        data['commands'].append(command(['nvme','id-ctrl',node,'--output-format=json']))
        data['commands'].append(command(['nvme','get-feature',node,'--feature-id=6','--human-readable']))
        data['commands'].append(command(['nvme','smart-log',node,'--output-format=json']))
    for namespace in Path('/sys/class/block').glob('nvme*n*'):
        if not (namespace/'partition').exists():
            data['commands'].append(command(['nvme','amzn','stats','--details','/dev/'+namespace.name]))
    print(json.dumps(data,indent=2))
elif sys.argv[1]=='sample':
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
    paths=['/proc/diskstats','/proc/meminfo','/proc/vmstat','/proc/pressure/io','/proc/pressure/memory','/proc/stat']
    while True:
        print(json.dumps({'timestamp':time.time(),'files':{p:read(p) for p in paths}}),flush=True)
        time.sleep(1)
else:raise SystemExit('metadata or sample required')
