'use strict';
const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
(async () => {
  const root = path.resolve(__dirname,'../../..');
  const reportPath = process.env.TIP_DASHBOARD_REPORT || path.join(root,'output/tip-dashboard/report.json');
  const real = JSON.parse(fs.readFileSync(reportPath));
  const out = process.env.TIP_DASHBOARD_UI_OUTPUT || path.join(root,'output/tip-dashboard-ui');
  const browser = await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? {executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE} : {})});
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1000}});
    const errors = []; page.on('pageerror', e => errors.push(String(e)));
    let reportBody = JSON.stringify(real), indexBody = null;
    await page.route('https://dashboard.test/**', async route => {
      const name = new URL(route.request().url()).pathname.slice(1) || 'index.html';
      if (name === 'index.json') return route.fulfill({status:indexBody ? 200 : 404,contentType:'application/json',body:indexBody || '{}'});
      if (name.endsWith('.json')) return route.fulfill({contentType:'application/json',body:reportBody});
      const types = {'index.html':'text/html','app.js':'application/javascript','style.css':'text/css'};
      if (!types[name]) return route.fulfill({status:404,body:''});
      return route.fulfill({contentType:types[name],body:fs.readFileSync(path.join(__dirname,name))});
    });
    await page.goto('https://dashboard.test/');
    await page.waitForFunction(()=>document.querySelector('#load-status').textContent.includes('Read-only'));
    assert.equal(await page.locator('input[type=file]').count(),0);
    assert.equal(await page.locator('#report-picker').isVisible(),false);
    assert.match(await page.locator('#snapshot').textContent(),new RegExp(real.revision.sha.slice(0,12)));
    assert.equal(await page.locator('.snapshot-details').getAttribute('open'),null,'technical details default closed');
    const headerText = await page.locator('#snapshot').innerText();
    assert.doesNotMatch(headerText,/Collection:|Current revision|invalid_evidence|Malformed|empty_inventory|Read-only/);
    assert.ok(!headerText.includes(real.revision.sha.slice(0,12)),'raw commit metadata is secondary');
    if(real.main_comparison?.warnings?.some(w=>w.code==='empty_inventory')) assert.match(headerText,/Main not yet verifiable/);
    await page.locator('.snapshot-details > summary').click();
    assert.ok((await page.locator('.snapshot-details').innerText()).includes(real.revision.sha),'selected commit remains accessible');
    await page.locator('.snapshot-details > summary').click();
    const {upgradeForks} = require('./app.js');
    assert.equal(await page.locator('#results > section').count(),upgradeForks(real).length);
    const next = page.locator('#results > section').filter({has:page.locator('h2',{hasText:real.next_fork})}).first();
    if (!real.tips.some(t=>t.scheduled_fork===real.next_fork)) assert.match(await next.innerText(),/No scheduled TIPs recorded/);
    fs.mkdirSync(out,{recursive:true});
    await page.screenshot({path:path.join(out,'real-dashboard-desktop.png'),fullPage:true});
    await page.locator('#scope').selectOption('all');
    const linked = real.tips.find(t=>t.id === 'TIP-1006' && t.requirements.some(r=>r.implementations.length)) || real.tips.find(t=>t.requirements.some(r=>r.implementations.length));
    assert.ok(linked,'report must contain implementation evidence');
    await page.locator('#search').fill(linked.id);
    const card = page.locator('#results > section > details').filter({has:page.locator(':scope > summary',{hasText:linked.id+' —'})}).first();
    await card.locator(':scope > summary').click();
    await card.locator('.people-details > summary').click();
    if (linked.people?.status === 'complete' || linked.people?.status === 'partial') {
      const visible = await card.locator('.github-people').innerText();
      for (const scope of ['spec', 'implementation']) {
        for (const pr of linked.people[scope]?.pull_requests || []) {
          if (pr.author?.login) assert.ok(visible.includes('@' + pr.author.login), 'real PR author');
          for (const review of pr.reviews || []) {
            if (review.author?.login) assert.ok(visible.includes('@' + review.author.login), 'real submitted reviewer');
          }
        }
      }
    }
    if (real.main_comparison?.status === 'available') {
      assert.ok((await page.locator('#snapshot').textContent()).includes(real.main_comparison.revision.sha.slice(0,12)), 'real main commit');
      if (!linked.main_comparison?.inventory?.count) assert.match(await card.locator('.main-comparison').innerText(), /Coverage unknown/);
    }
    const req = linked.requirements.find(r=>r.implementations.length);
    const detail = card.locator(':scope > details').filter({has:page.locator(':scope > summary',{hasText:req.id+' ·'})}).first();
    await detail.locator(':scope > summary').click();
    const text = await detail.innerText();
    assert.ok(text.includes(req.implementations[0].path));
    assert.ok(text.includes(req.implementations[0].gate));
    if(req.assertions.length) assert.ok(text.includes(req.assertions[0].test));
    assert.match(text,/Assertion-linked cases:/);
    if (req.statement.includes('`')) {
      assert.ok(await detail.locator('.statement code').count() > 0, 'spec inline code renders');
      assert.doesNotMatch(await detail.locator('.statement').innerText(), /`/);
    }
    if(req.review?.reviewer_kind === 'agent') {
      const automated=detail.locator('.automated-provenance');
      assert.equal(await automated.getAttribute('open'),null);
      assert.doesNotMatch(await automated.innerText(),/reviewer kind/);
      await automated.locator('summary').click();
      assert.match(await automated.innerText(),/agent/);
      await automated.locator('summary').click();
    }
    await card.locator('.people-details > summary').click();
    await page.screenshot({path:path.join(out,'showcase-evidence.png'),fullPage:true});
    await page.locator('#search').fill('definitely-no-such-tip');
    assert.match(await page.locator('#results').innerText(),/No TIPs match/);
    await page.locator('#search').fill(''); await page.locator('#scope').selectOption('latest');
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile overflow');
    await page.screenshot({path:path.join(out,'real-dashboard-mobile.png'),fullPage:true});
    indexBody = JSON.stringify({reports:[{label:'Snapshot',url:'one.json',sha:real.revision.sha},{label:'Unavailable snapshot',url:'two.json',sha:'b'.repeat(40)}]});
    await page.reload(); await page.locator('#report-picker').waitFor({state:'visible'});
    reportBody = '{malformed';
    await page.locator('#reports').selectOption('1');
    await page.waitForFunction(()=>document.querySelector('#load-status').textContent.includes('Report unavailable'));
    assert.equal(await page.locator('#results details').count(),0);
    assert.equal(await page.locator('#snapshot').textContent(),'');
    await page.screenshot({path:path.join(out,'error-dashboard.png'),fullPage:true});
    reportBody = JSON.stringify(real);
    await page.locator('#reports').selectOption('0');
    await page.waitForFunction(()=>document.querySelector('#load-status').textContent.includes('Read-only'));
    await page.route('https://dashboard.test/one.json',route=>route.abort('failed'));
    await page.locator('#reports').selectOption('1');
    await page.locator('#reports').selectOption('0');
    await page.waitForFunction(()=>document.querySelector('#load-status').textContent.includes('Report unavailable'));
    assert.equal(await page.locator('#results details').count(),0);
    await page.goto(pathToFileURL(path.join(path.dirname(reportPath),'dashboard.html')).href);
    await page.waitForFunction(()=>document.querySelector('#load-status').textContent.includes('Read-only'));
    assert.ok((await page.locator('#snapshot').textContent()).includes(real.revision.sha.slice(0,12)));
    assert.equal(await page.locator('input[type=file]').count(),0);
    // Synthetic fixtures independently exercise identities, history, trust boundaries and main scope.
    const fixture=JSON.parse(JSON.stringify(real));
    fixture.tips=[JSON.parse(JSON.stringify(linked))]; fixture.latest_forks=[linked.scheduled_fork];
    fixture.main_comparison={status:'available',revision:{sha:'b'.repeat(40),requested:'main',dirty:false},warnings:[]};
    const t=fixture.tips[0], reviewer={login:'reviewer-fixture',account_type:'User',url:'https://github.com/reviewer-fixture'};
    t.declared_authors='<img src=x onerror="window.fixtureXSS=true">';
    t.main_comparison={status:'present',sha:'b'.repeat(40),spec_changed:true,inventory:{status:'missing',count:0},coverage:{total:0,linked:0,reviewed:0,verified:0},scheduled_fork:'T12',merge_status:'merged'};
    t.people={status:'partial',observed_at:'2026-10-08',spec:{status:'complete',contributors:[{login:'bot-fixture',account_type:'Bot',roles:['committer'],commits:[]},{name:'Unmapped contributor',roles:['author']}],pull_requests:[{number:10,title:'Spec fixture',author:{login:'spec-author'},status:'complete',reviews:[{author:reviewer,state:'APPROVED',submitted_at:'2026-01-01',commit_sha:'c'.repeat(40),on_current_head:false,url:'https://github.com/test/review/old'},{author:reviewer,state:'DISMISSED',submitted_at:'2026-02-01',commit_sha:'b'.repeat(40),on_current_head:true,url:'https://github.com/test/review/new'},{author:{login:'requested-only'},state:'PENDING'},{author:{name:'Deleted reviewer'},state:'COMMENTED',submitted_at:'2026-03-01',url:'javascript:alert(1)'}]}]},implementation:{status:'unavailable',contributors:[],pull_requests:[]},warnings:['Fixture unavailable implementation lookup']};
    reportBody=JSON.stringify(fixture); indexBody=null;
    await page.goto('https://dashboard.test/');
    await page.waitForFunction(()=>document.querySelector('#load-status').textContent.includes('Read-only'));
    const fixtureCard=page.locator('#results .tip').first();
    await fixtureCard.locator(':scope > summary').click();
    await fixtureCard.locator('.people-details > summary').click();
    const people=fixtureCard.locator('.github-people');
    const visible=await people.innerText();
    for(const expected of ['GitHub people','Reviews on spec PRs','@spec-author','@bot-fixture · Bot','committer','Unmapped contributor','unmapped GitHub identity','DISMISSED','Deleted reviewer','Implementation · unavailable']) assert.ok(visible.includes(expected),expected);
    assert.doesNotMatch(visible,/APPROVED|requested-only/);
    assert.equal(await people.locator('img').count(),0);
    assert.equal(await page.evaluate(()=>window.fixtureXSS),undefined);
    assert.equal(await people.locator('a[href^="javascript:"]').count(),0);
    assert.equal(await people.locator('a[href="https://github.com/test/review/new"]:visible').count(),1);
    const history=people.locator('.review-history');
    assert.equal(await history.getAttribute('open'),null);
    await history.locator('summary').click();
    assert.match(await history.innerText(),/APPROVED/);
    assert.match(await history.innerText(),/older \/ different PR head/);
    assert.match(await fixtureCard.locator('.main-comparison').innerText(),/TIP present[\s\S]*Spec: changed/);
    assert.match(await fixtureCard.locator('.main-comparison').innerText(),/Main inventory missing · Coverage unknown/);
    assert.match(await page.locator('#snapshot').textContent(),/vs main b{12}/);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'people mobile overflow');
    await page.screenshot({path:path.join(out,'people-main-fixture.png'),fullPage:true});
    // Exercise spacing that the text-only DOM tests cannot detect.
    t.main_comparison.inventory={status:'reviewed',count:2};
    t.main_comparison.coverage={total:2,linked:1,reviewed:0,verified:0};
    reportBody=JSON.stringify(fixture);
    await page.reload();
    await page.waitForFunction(()=>document.querySelector('#load-status').textContent.includes('Read-only'));
    await page.locator('#results .tip > summary').click();
    await page.locator('.people-details > summary').click();
    for (const width of [320,390,768,1440]) {
      await page.setViewportSize({width,height:900});
      const metrics=await page.locator('#results .counts').evaluate(el=>({
        gap:parseFloat(getComputedStyle(el).columnGap),
        boxes:[...el.children].map(e=>{const r=e.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom};})
      }));
      assert.ok(metrics.gap>=12,'coverage has explicit spacing');
      for(let i=1;i<metrics.boxes.length;i++) {
        const a=metrics.boxes[i-1],b=metrics.boxes[i];
        assert.ok(b.top>=a.bottom || b.left>=a.right+12,'coverage values do not run together');
      }
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`expanded overflow at ${width}px`);
    }
    await page.emulateMedia({colorScheme:'dark'});
    await page.screenshot({path:path.join(out,'formatting-dark-fixture.png'),fullPage:true});
    await page.emulateMedia({colorScheme:'light'});
    fixture.main_comparison.status='unavailable';t.people.spec.status='unavailable';t.people.spec.pull_requests=[];
    reportBody=JSON.stringify(fixture);await page.reload();
    await page.waitForFunction(()=>document.querySelector('#load-status').textContent.includes('Read-only'));
    await page.locator('#results .tip > summary').click();
    assert.match(await page.locator('#snapshot').textContent(),/vs main unavailable/);
    assert.match(await page.locator('#results .main-comparison').innerText(),/presence and coverage unknown/);
    assert.doesNotMatch(await page.locator('#results .main-comparison').innerText(),/TIP present/);
    await page.locator('.people-details > summary').click();
    assert.match(await page.locator('.github-people').innerText(),/PR association \/ review data incomplete or unavailable/);
    assert.deepEqual(errors,[]);
    const result = {status:'passed',revision:real.revision,drilldown:{tip:linked.id,requirement:req.id},checks:['read-only controls','latest upgrades','empty configured fork','optional hosted selector','short source SHA','source/guard/assertion drilldown','search','mobile overflow','schema/network failure clears stale evidence','portable bundled dashboard','GitHub people and escaped names','latest submitted review and dismissed old-head history','main coverage scope and unavailable comparison','inline spec code','coverage spacing and expanded layout at 320/390/768/1440px','dark mode rendering','concise header with optional provenance'],limitations:'Browser checks supplied report evidence, not live network activation.'};
    fs.writeFileSync(path.join(out,'browser-results.json'),JSON.stringify(result,null,2)+'\n');
    console.log(JSON.stringify(result));
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exit(1)});
