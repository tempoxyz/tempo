import collections,gzip,json,pathlib,re
root=pathlib.Path(__file__).resolve().parents[3]
out=pathlib.Path(__file__).resolve().parent
results=json.loads((out.parent/'results.json').read_text())
summary={}
for r in results['runs']:
 directory=root/r['directory']; series={}; names=set()
 with gzip.open(directory/'report-feature-1.samples.ndjson.gz','rt') as f:
  for line in f:
   name=line.split('"',4)[3]
   if any(k in name for k in ['trie','save_blocks','mdbx','database','provider','persistence']):names.add(name)
   if not ('save_blocks' in name or ('trie' in name and name.endswith(('_sum','_count')))):continue
   x=json.loads(line)
   if x['labels'].get('node') not in ['a','b']:continue
   if name.endswith('_bucket'):continue
   key=json.dumps([name,x['labels']],sort_keys=True)
   series.setdefault(key,{'name':name,'labels':x['labels'],'points':[]})['points'].append([x['offset_ms'],x['unix_ms'],x['value']])
 selected=[]
 for s in series.values():
  points=[p for p in s['points'] if 600000<=p[0]<=1200000]
  if len(points)<2:continue
  if s['name'].endswith('_sum') and 'save_blocks' in s['name']:
   selected.append({'name':s['name'],'labels':s['labels'],'first':points[0],'last':points[-1],'delta':points[-1][2]-points[0][2]})
 (out/(r['scenario']+'-metrics.json')).write_text(json.dumps({'names':sorted(names),'series':list(series.values())})+'\n')
 summary[r['scenario']]=selected
(out/'persistence-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
# Logs preserve exact timestamps and file/line provenance. Parsing is restricted to relevant targets.
directory=root/results['runs'][1]['directory']
for node in ['a','b']:
 events=[]; inventory=collections.Counter()
 for p in sorted((directory/f'logs-feature-1-{node}'/'dev').glob('reth.log*')):
  with p.open() as f:
   for number,line in enumerate(f,1):
    if not any(s in line for s in ['"target":"providers::db"','"target":"engine::persistence"','"target":"storage::db::mdbx"','"target":"sync::stages','"target":"sync::pipeline','"target":"trie::','"target":"engine::root"']):continue
    x=json.loads(line); target=x.get('target',''); fields=x.get('fields',{}); message=fields.get('message','')
    inventory[(target,message)]+=1
    if target.startswith('trie::') and not any(k in message.lower() for k in ['root','calculat','finished','complete']):continue
    if target=='engine::root' and not any(k in message.lower() for k in ['root','finished','complete']):continue
    events.append({**x,'source':str(p),'line':number})
 events.sort(key=lambda x:x['timestamp'])
 (out/f'events-{node}.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in events))
 (out/f'log-messages-{node}.json').write_text(json.dumps([{'target':k[0],'message':k[1],'count':v} for k,v in inventory.most_common()],indent=2)+'\n')
print(json.dumps(summary,indent=2))
