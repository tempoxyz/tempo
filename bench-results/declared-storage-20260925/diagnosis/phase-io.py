import datetime,json,pathlib
out=pathlib.Path(__file__).resolve().parent
root=out.parents[2]
def ms(s):return datetime.datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()*1000
original=root/'bench-results/20260925-192547-004/state-path-observer-feature-1.jsonl'
rows=[json.loads(x) for p in [original,out.parent/'write-postload-observer.jsonl'] for x in p.read_text().splitlines()]
rows.sort(key=lambda x:x['unix_ms'])
result={}
for label,node,start,end in [('builder_stalled_after_load','a','2026-09-25T19:59:00Z','2026-09-25T20:01:00Z'),('follower_merkle_after_load','b','2026-09-25T20:08:00Z','2026-09-25T20:10:00Z')]:
 samples=[r['nodes'][node] for r in rows if ms(start)<=r['nodes'][node]['unix_ms']<=ms(end)]
 a,b=samples[0],samples[-1]; d=a['database_device']; seconds=(b['unix_ms']-a['unix_ms'])/1000
 deltas={k:b['io'][d][k]-a['io'][d][k] for k in ['rbytes','wbytes','rios','wios']}
 metric_deltas={k:b['metrics'][k]-a['metrics'][k] for k in a['metrics'] if k in b['metrics'] and any(s in k for s in ['gas_used_sum','gas_processed_total','total_transactions_sum','state_root_wait_duration_seconds_count'])}
 assert len(set(x['head'] for x in samples))==1
 assert all(v==0 for v in metric_deltas.values())
 result[label]={'from_unix_ms':a['unix_ms'],'to_unix_ms':b['unix_ms'],'seconds':seconds,'head':a['head'],'execution_counter_deltas':metric_deltas,'io':deltas,'read_MB_s':deltas['rbytes']/seconds/1e6,'write_MB_s':deltas['wbytes']/seconds/1e6,'read_IOPS':deltas['rios']/seconds,'mean_read_bytes':deltas['rbytes']/deltas['rios'],'major_faults':b['memory']['pgmajfault']-a['memory']['pgmajfault'],'file_refaults':b['memory']['workingset_refault_file']-a['memory']['workingset_refault_file'],'file_cache_GiB':[a['memory']['file']/2**30,b['memory']['file']/2**30]}
events=[json.loads(x) for x in (out/'events-b.jsonl').read_text().splitlines()]
merkle=[]
for i,x in enumerate(events):
 if x['fields'].get('message')!='Processing chunk':continue
 following=events[i+1:]
 y=next(e for e in following if e['fields'].get('message')=='Updating transaction lookup')
 commits=[e for e in following if x['timestamp']<e['timestamp']<=y['timestamp'] and e['fields'].get('message')=='Commit' and not e['fields'].get('is_read_only')]
 assert len(commits)==1
 c=commits[0]
 merkle.append({'range':x['fields']['chunk_range'],'start':x['timestamp'],'end':c['timestamp'],'wall_seconds':(ms(c['timestamp'])-ms(x['timestamp']))/1000,'final_commit_duration':c['fields']['total_duration'],'start_source':x['source'],'start_line':x['line'],'end_source':c['source'],'end_line':c['line'],'scope':'Incremental root calculation, update application, and commit together; no internal CPU-vs-I/O or read-vs-write time split.'})
result['follower_merkle_stages']=merkle
(out/'phase-io.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
