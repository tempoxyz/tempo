'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {safeURL, parseReport, matches, mount} = require('./app.js');

// Minimal DOM exercises the production rendering and event handlers without a browser dependency.
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.listeners = {}; this.value = ''; this.checked = false; this.disabled = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(' '); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this._text = ''; this.children = items; }
  addEventListener(event, handler) { this.listeners[event] = handler; }
  fire(event) { return this.listeners[event]({target: this}); }
  all(tag) { return this.children.flatMap(c => [...(c.tagName === tag ? [c] : []), ...c.all(tag)]); }
}
function dom() {
  const elements = Object.fromEntries(['reports','report-picker','load-status','snapshot','search','scope','result-count','results'].map(id => [id, new Element('div')]));
  return {elements, createElement: tag => new Element(tag), getElementById: id => elements[id]};
}
function report(sha = 'a'.repeat(40)) {
  return {current_fork:'T13',next_fork:'T14',schema_version: 1, repository: 'test/repository', generated_at: '2026-01-01T00:00:00Z', revision: {requested: 'test-ref', sha, dirty: false, source_digest:'test-digest'}, collection: {status:'partial', warnings:[{code:'fixture',message:'Synthetic test fixture only'}]}, summary:{tips:2,requirements:1,linked:1,reviewed:0,verified:0,warnings:1}, tips:[{
    id:'TIP-TEST', title:'<img src=x onerror=alert(1)>', scheduled_fork:'T13', status:'Accepted', merge_status:'open', inventory:{status:'incomplete',count:1}, coverage:{total:1,linked:1,reviewed:0,verified:0}, spec:{path:'tips/test.md',url:'javascript:alert(1)'}, warnings:[], implementation_prs:[{number:1,state:'open',is_draft:true,url:'https://example.org/pr/1'}], requirements:[{id:'TIP-TEST:R1',statement:'Test invariant',kind:'activation',cases:['before'],implementation_status:'linked',verification_status:'failed',implementations:[{path:'test.rs',line:5,url:'https://example.org/code',gate:'spec.is_t13()',fork:'T13',digest:'code-hash'}],assertions:[{path:'test.rs',line:10,url:'data:text/html,bad',test:'selector',case:'before',digest:'assertion-hash'}],evidence:[{status:'failed',candidate_sha:sha,ci:{job_url:'https://example.org/ci',bad_url:'javascript:alert(1)'},runner:{version:'test'}}],warnings:[]}]}, {id:'TIP-UNKNOWN',title:'Unknown fork',inventory:{status:'reviewed'},coverage:{total:0,linked:0,reviewed:0,verified:0},requirements:[]}]};
}
test('reject malformed envelopes and unsafe source links', () => {
  for (const v of [null,[],{}, {schema_version:2}, {schema_version:1,tips:[null],revision:{}}, {schema_version:1,tips:[],revision:[]}]) assert.throws(()=>parseReport(JSON.stringify(v)));
  assert.throws(()=>parseReport('{bad'));
  for (const url of ['javascript:alert(1)','data:text/html,bad','http://example.org','//example.org','https://user:pass@example.org',{}]) assert.equal(safeURL(url),null);
});
test('latest groups descend, include empty next fork and exclude historical tips', () => {
  const {upgradeForks}=require('./app.js'), r=report();
  r.tips.push({id:'TIP-OLD',scheduled_fork:'T11'}, {id:'TIP-T12',scheduled_fork:'T12'});
  assert.deepEqual(upgradeForks(r),['T14','T13','T12']);
  const d=dom(), app=mount(d,null,'file:'); app.showReport(JSON.stringify(r));
  assert.match(d.elements.results.textContent,/T14 · network upgrade No scheduled TIPs recorded/);
  assert.doesNotMatch(d.elements.results.textContent,/TIP-OLD|TIP-UNKNOWN|Complete:/);
  d.elements.scope.value='all'; d.elements.scope.fire('change');
  assert.match(d.elements.results.textContent,/TIP-OLD/);
  d.elements.search.value='no such tip';d.elements.search.fire('input');
  assert.match(d.elements.results.textContent,/No TIPs match/);
});
test('compact rows preserve separate counts and safe optional evidence drilldowns', () => {
  const d=dom(), app=mount(d,null,'file:'), r=report();
  r.tips[0].requirements[0].review={reviewer_kind:'agent',reviewer:'specialist'};
  app.showReport(JSON.stringify(r));
  assert.match(d.elements.snapshot.textContent,/Source a{12}/);
  assert.match(d.elements.snapshot.textContent,/Provenance.*a{40}/);
  const text=d.elements.results.textContent;
  for(const value of ['Linked 1/1','Reviewed 0/1','Assertions 1/1','Missing links 0','Scheduled T13','Actual guards: spec.is_t13()','agent','specialist','selector','assertion-hash','candidate sha']) assert.ok(text.includes(value),value);
  assert.equal(d.elements.results.all('img').length,0);
  for(const a of d.elements.results.all('a')) assert.ok(a.href.startsWith('https://'));
});
test('unique declared cases exclude stale executions', () => {
  const {caseCoverage}=require('./app.js');
  const r={cases:['a','a','b'], assertions:[{case:'a'},{case:'a'},{case:'other'}], verification_status:'failed', evidence:[{case:'a',outcome:'passed'},{case:'b',outcome:'failed'}]};
  assert.deepEqual(caseCoverage(r),{total:2,linked:1,executed:2,passed:1});
  r.verification_status='stale'; assert.deepEqual(caseCoverage(r),{total:2,linked:1,executed:0,passed:0});
});
test('schema and collection failures clear previous coverage', () => {
  const d=dom(), app=mount(d,null,'file:');
  for (const text of ['{bad',JSON.stringify({...report(),collection:{status:'error'}})]) {
    app.showReport(JSON.stringify(report())); app.showReport(text);
    assert.match(d.elements['load-status'].textContent,/Report unavailable/);
    assert.equal(d.elements.results.textContent,''); assert.equal(d.elements.snapshot.textContent,'');
  }
});
test('portable embedded reports need no fetch and bare file page is unavailable', async () => {
  const d=dom();d.elements['embedded-report']=new Element('script');d.elements['embedded-report'].textContent=JSON.stringify(report());
  await mount(d,()=>{throw Error('unexpected fetch')},'file:').load();
  assert.match(d.elements.results.textContent,/TIP-TEST/);
  const bare=dom();await mount(bare,null,'file:').load();assert.match(bare.elements['load-status'].textContent,/Report unavailable/);
});
test('hosted index is optional; selection loads exact revision and failures clear data', async () => {
  const d=dom(), other=report('b'.repeat(40));
  const index={reports:[{label:'one',url:'one.json',sha:'a'.repeat(40)},{label:'two',url:'two.json',sha:'b'.repeat(40)}]};
  let fail=false;
  const fetcher=async(url,options)=>{assert.equal(options.cache,'no-store'); if(fail) throw Error('offline');return {ok:true,text:async()=>JSON.stringify(url==='index.json'?index:url==='two.json'?other:report())};};
  await mount(d,fetcher,'https:').load(); assert.equal(d.elements['report-picker'].hidden,false);
  d.elements.reports.value='1';await d.elements.reports.fire('change');assert.match(d.elements.snapshot.textContent,/Source b{12}/);
  fail=true;d.elements.reports.value='0';await d.elements.reports.fire('change');
  assert.match(d.elements['load-status'].textContent,/offline/);assert.equal(d.elements.results.textContent,'');
});
test('single report and absent index do not expose a dead report selector', async () => {
  for(const index of [null,{reports:[{label:'only',url:'report.json',sha:'a'.repeat(40)}]}]) {
    const d=dom();d.elements['report-picker'].hidden=true;
    await mount(d,async url=>({ok: url!=='index.json'||!!index,status:404,text:async()=>JSON.stringify(url==='index.json'?index:report())}),'https:').load();
    assert.equal(d.elements['report-picker'].hidden,true);assert.match(d.elements.results.textContent,/TIP-TEST/);
  }
});
test('index SHA mismatch cannot display incorrect evidence', async () => {
  const d=dom(), app=mount(d,null,'file:');
  app.showReport(JSON.stringify(report()),'b'.repeat(40));
  assert.match(d.elements['load-status'].textContent,/differs/);assert.equal(d.elements.results.textContent,'');
});
test('report latest_forks controls defaults even with future scheduled TIPs', () => {
  const {upgradeForks}=require('./app.js'), r=report();
  r.latest_forks=['T14','T13','T12'];
  r.tips.push({id:'TIP-FUTURE',scheduled_fork:'T20'});
  assert.deepEqual(upgradeForks(r),['T14','T13','T12']);
  assert.deepEqual(upgradeForks(r,true),['T20','T14','T13','T12','Unknown / unscheduled']);
  const d=dom();mount(d,null,'file:').showReport(JSON.stringify(r));
  assert.match(d.elements.results.textContent,/T12 · network upgrade No scheduled TIPs recorded/);
  assert.doesNotMatch(d.elements.results.textContent,/TIP-FUTURE/);
});
test('empty inventories stay visibly unknown in collapsed rows', () => {
  const d=dom();d.elements.scope.value='all';
  mount(d,null,'file:').showReport(JSON.stringify(report()));
  const summaries=d.elements.results.all('summary').map(e=>e.textContent);
  const empty=summaries.find(s=>s.includes('TIP-UNKNOWN —'));
  assert.match(empty,/Inventory missing · Coverage unknown/);
  assert.doesNotMatch(empty,/0\/0|Missing links 0/);
});
