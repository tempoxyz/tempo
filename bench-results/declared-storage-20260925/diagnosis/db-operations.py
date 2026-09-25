import gzip,json,pathlib
out=pathlib.Path(__file__).resolve().parent
root=out.parents[2]
series={}
with gzip.open(root/'bench-results/20260925-192547-004/report-feature-1.samples.ndjson.gz','rt') as f:
 for line in f:
  if not line.startswith('{"name":"reth_database_operation_calls_total"'):continue
  x=json.loads(line)
  if x['labels'].get('node') not in ['a','b']:continue
  if not any(k in str(x['labels']).lower() for k in ['storage','trie','account']):continue
  if not 600000<=x['offset_ms']<=1200000:continue
  key=json.dumps(x['labels'],sort_keys=True)
  series.setdefault(key,{'labels':x['labels'],'first':x,'last':x})['last']=x
r=[{**s,'delta':s['last']['value']-s['first']['value']} for s in series.values()]
(out/'database-operations.json').write_text(json.dumps(r,indent=2)+'\n')
for x in sorted(r,key=lambda x:-x['delta']):
 if x['delta']>0:print(json.dumps({'labels':x['labels'],'calls':x['delta']}))
