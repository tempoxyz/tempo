/* No dependencies. Every report value is untrusted text. */
(function (root) {
  'use strict';
  const arr = value => Array.isArray(value) ? value : [];
  const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const str = (value, fallback = 'Unknown') => typeof value === 'string' || typeof value === 'number' ? String(value) : fallback;
  const count = value => Number.isSafeInteger(value) && value >= 0 ? String(value) : 'Unknown';
  const fork = tip => typeof tip.scheduled_fork === 'string' && tip.scheduled_fork.trim() ? tip.scheduled_fork : 'Unknown / unscheduled';
  function safeURL(value) {
    if (typeof value !== 'string') return null;
    try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : null; } catch (_) { return null; }
  }
  function parseReport(text) {
    const report = JSON.parse(text);
    if (!report || report.schema_version !== 1 || !Array.isArray(report.tips) || !report.revision || typeof report.revision !== 'object' || Array.isArray(report.revision)) {
      throw new Error('Expected report schema_version 1, revision object and tips array.');
    }
    if (typeof report.revision.sha !== 'string' || !/^[a-f0-9]{40}$/i.test(report.revision.sha)) throw new Error('Expected an exact 40-character source revision SHA.');
    if (report.tips.some(tip => !tip || typeof tip !== 'object' || Array.isArray(tip))) throw new Error('Every TIP must be an object.');
    return report;
  }
  function reportURL(value) {
    return typeof value === 'string' && (safeURL(value) || (/^(?![./]*\/\/)[a-zA-Z0-9_./-]+\.json$/.test(value) && !value.startsWith('/')));
  }
  function upgradeForks(report, all = false) {
    const configured = [...new Set(arr(report.latest_forks).filter(f => typeof f === 'string' && /^T\d+$/.test(f)))];
    const named = [...new Set([...configured, report.next_fork, report.current_fork, report.default_fork, ...report.tips.map(fork)].filter(f => /^T\d+$/.test(f || '')))];
    named.sort((a,b) => Number(b.slice(1)) - Number(a.slice(1)));
    // Include empty configured forks; historical groups remain opt-in.
    const recent = configured.length ? configured.sort((a,b) => Number(b.slice(1)) - Number(a.slice(1))) : named.slice(0, 3);
    if (!all) return recent;
    return [...named, ...new Set(report.tips.map(fork).filter(f => !named.includes(f)))];
  }
  function statuses(tip) {
    return [tip.status, tip.merge_status, ...arr(tip.requirements).flatMap(r => [obj(r).implementation_status, obj(r).verification_status])].filter(v => typeof v === 'string');
  }
  function hasWarnings(tip) { return arr(tip.warnings).length > 0 || arr(tip.requirements).some(r => arr(obj(r).warnings).length > 0) || obj(tip.inventory).status !== 'reviewed'; }
  function matches(tip, filters) {
    return (!filters.fork || fork(tip) === filters.fork) && (!filters.status || statuses(tip).includes(filters.status)) && (!filters.warnings || hasWarnings(tip)) && (!filters.search || JSON.stringify(tip).toLowerCase().includes(filters.search.toLowerCase()));
  }
  // Counts are unique declared cases within each requirement, never annotation rows.
  function caseCoverage(value) {
    const r = obj(value), declared = new Set(arr(r.cases).filter(c => typeof c === 'string' && c));
    const linked = new Set(arr(r.assertions).map(a => obj(a).case).filter(c => declared.has(c)));
    const evidence = ['stale', 'unknown', 'not_run', 'unexercised'].includes(r.verification_status) ? [] : arr(r.evidence);
    const executed = new Set(evidence.filter(e => ['passed', 'failed'].includes(obj(e).outcome)).map(e => e.case).filter(c => declared.has(c)));
    const passed = new Set(evidence.filter(e => obj(e).outcome === 'passed').map(e => e.case).filter(c => declared.has(c)));
    return {total: declared.size, linked: linked.size, executed: executed.size, passed: passed.size};
  }
  function tipCases(tip) {
    return arr(tip.requirements).reduce((sum, r) => { const c = caseCoverage(r); for (const key of Object.keys(sum)) sum[key] += c[key]; return sum; }, {total:0, linked:0, executed:0, passed:0});
  }
  function caseLabel(c) { return `Assertion-linked cases: ${c.linked}/${c.total} · Executed cases: ${c.executed}/${c.total} · Passed cases: ${c.passed}/${c.total}`; }
  function mount(doc, fetcher, protocol) {
    const el = id => doc.getElementById(id);
    const reports = [];
    let active = null;
    function node(tag, text, cls) {
      const n = doc.createElement(tag);
      if (text !== undefined) n.textContent = str(text, '');
      if (cls) n.className = cls;
      return n;
    }
    function link(value, label) {
      const url = safeURL(value);
      const n = node(url ? 'a' : 'span', label || str(value));
      if (url) { n.href = url; n.target = '_blank'; n.rel = 'noopener noreferrer'; }
      return n;
    }
    function meta(parent, values) {
      const dl = node('dl', undefined, 'meta');
      for (const [key, value] of values) { dl.append(node('dt', key), node('dd', str(value))); }
      parent.append(dl);
    }
    function warnings(parent, values) {
      if (!arr(values).length) return;
      const list = node('ul', undefined, 'warning');
      for (const value of values) list.append(node('li', typeof value === 'string' ? value : [obj(value).code, obj(value).message].filter(Boolean).map(v => str(v)).join(': ') || 'Unspecified warning'));
      parent.append(list);
    }
    // Preserve adapter-specific execution provenance without trusting its shape or HTML.
    function evidenceValue(value, depth = 0) {
      if (value === null || value === undefined) return node('span', 'Unknown');
      if (typeof value !== 'object') return safeURL(value) ? link(value) : node('span', typeof value === 'boolean' ? String(value) : str(value));
      if (depth >= 8) return node('span', JSON.stringify(value));
      if (Array.isArray(value)) {
        const ul = node('ul');
        for (const item of value) { const li = node('li'); li.append(evidenceValue(item, depth + 1)); ul.append(li); }
        if (!value.length) ul.append(node('li', 'None recorded'));
        return ul;
      }
      const dl = node('dl', undefined, 'meta');
      for (const [key, val] of Object.entries(value)) { const dd = node('dd'); dd.append(evidenceValue(val, depth + 1)); dl.append(node('dt', key.replaceAll('_', ' ')), dd); }
      return dl;
    }
    function coverage(parent, value) {
      const c = obj(value), row = node('div', undefined, 'counts');
      for (const [key, label] of [['total', 'Requirements'], ['linked', 'Linked'], ['reviewed', 'Reviewed'], ['verified', 'Verified']]) row.append(node('span', `${label}: ${count(c[key])}`));
      parent.append(row);
    }
    function sourceList(parent, title, items, assertion) {
      parent.append(node('h4', title));
      if (!arr(items).length) { parent.append(node('p', 'None recorded', 'muted')); return; }
      for (const item of items) {
        const v = obj(item), box = node('div', undefined, 'card');
        box.append(link(v.url, `${str(v.path)}:${str(v.line, '?')}`));
        box.append(node('p', assertion ? `Test: ${str(v.test)} · Case: ${str(v.case)}` : `Guard: ${str(v.gate)} · Fork: ${str(v.fork)}`));
        const provenance = node('details'); provenance.append(node('summary', 'Provenance'));
        meta(provenance, assertion ? [['Test', v.test], ['Case', v.case], ['Expected fork', v.fork], ['Source digest', v.digest]] : [['Gate', v.gate], ['Fork', v.fork], ['Source expression', v.source_expression], ['Source digest', v.digest]]);
        box.append(provenance); parent.append(box);
      }
    }
    function automatedReview(parent, value) {
      const d = node('details', undefined, 'automated-provenance');
      d.append(node('summary', 'Automated source checks · provenance'));
      d.append(node('p', 'Verification records, not GitHub approval.', 'muted'), evidenceValue(value || 'No automated check recorded'));
      parent.append(d);
    }
    function account(value) {
      const a = obj(value);
      const label = a.login ? `@${str(a.login)}${a.name ? ' (' + str(a.name) + ')' : ''}` : `${str(a.name, 'Deleted / unavailable account')} · unmapped GitHub identity`;
      return link(a.url, label + (a.account_type === 'Bot' ? ' · Bot' : ''));
    }
    function reviewRow(value) {
      const r = obj(value), row = node('p');
      row.append(account(r.author), node('span', ' · '), link(r.url, str(r.state)), node('span', ` · ${str(r.submitted_at, 'Submission time unavailable')} · Commit ${str(r.commit_sha, 'unknown')} · ${r.on_current_head === true ? 'current PR head' : r.on_current_head === false ? 'older / different PR head' : 'head context unknown'}`));
      return row;
    }
    function peopleScope(parent, label, value) {
      const scope = obj(value), section = node('section', undefined, 'people-scope');
      section.append(node('h4', `${label} · ${str(scope.status, 'unavailable')}`));
      section.append(node('p', label === 'Specification' ? 'Spec file contributors: commit authors / committers at selected revision' : 'Contributors: associated implementation PR commits (authors / committers)', 'muted'));
      for (const value of arr(scope.contributors)) {
        const c = obj(value), row = node('div');
        row.append(account(c), node('span', ` · ${arr(c.roles).map(v => str(v)).join(', ') || 'role unavailable'}`));
        if (arr(c.commits).length) {
          const commits = node('details'); commits.append(node('summary', `${c.commits.length} associated commits`));
          for (const commit of c.commits) { const p = node('p'); p.append(link(obj(commit).url, str(obj(commit).sha))); commits.append(p); }
          row.append(commits);
        }
        section.append(row);
      }
      if (!arr(scope.contributors).length) section.append(node('p', scope.status === 'complete' ? 'No contributors recorded.' : 'Contributor data incomplete or unavailable.', 'muted'));
      section.append(node('p', label === 'Specification' ? 'Reviews on spec PRs' : 'Reviews on implementation PRs', 'muted'));
      for (const value of arr(scope.pull_requests)) {
        const pr = obj(value), box = node('div', undefined, 'card');
        box.append(link(pr.url, `PR #${str(pr.number, '?')} · ${str(pr.title, '')}`), node('p', `${str(pr.state)} · Review data: ${str(pr.status, 'unavailable')} · Decision: ${str(pr.review_decision, 'unavailable')}`));
        const author = node('p', 'PR author: '); author.append(account(pr.author)); box.append(author);
        const reviews = arr(pr.reviews).filter(r => obj(r).submitted_at && obj(r).state !== 'PENDING');
        // Sort by submission time and show the latest submitted record per mapped account.
        // Unmapped identities remain separate: names alone do not establish an account.
        const latest = new Map();
        reviews.forEach((r, i) => {
          const key = obj(r.author).login || `unmapped:${i}`, previous = latest.get(key);
          if (!previous || str(r.submitted_at, '') >= str(previous.submitted_at, '')) latest.set(key, r);
        });
        box.append(node('p', 'Latest submitted review per account', 'muted'));
        for (const r of latest.values()) box.append(reviewRow(r));
        if (!reviews.length) box.append(node('p', pr.status === 'complete' ? 'No submitted reviews recorded.' : 'Submitted review data incomplete or unavailable.'));
        if (reviews.length > latest.size) {
          const history = node('details', undefined, 'review-history'); history.append(node('summary', `All submitted reviews (${reviews.length})`));
          for (const r of reviews) history.append(reviewRow(r));
          box.append(history);
        }
        warnings(box, pr.warnings); section.append(box);
      }
      if (!arr(scope.pull_requests).length) section.append(node('p', scope.status === 'complete' ? 'No associated PRs recorded.' : 'PR association / review data incomplete or unavailable.', 'muted'));
      warnings(section, scope.warnings); parent.append(section);
    }
    function people(parent, tip) {
      const p = obj(tip.people), section = node('section', undefined, 'github-people');
      section.append(node('h3', 'GitHub people'));
      section.append(node('p', `Declared spec authors: ${str(tip.declared_authors, 'Unavailable')}`));
      section.append(node('p', `GitHub data: ${str(p.status, 'unavailable')} · Observed ${str(p.observed_at, 'unknown')}`, 'muted'));
      section.append(node('p', 'Submitted PR reviews describe their recorded commit context; they do not establish approval of this exact specification or implementation. Requested reviewers are not submitted reviews.', 'muted'));
      peopleScope(section, 'Specification', p.spec); peopleScope(section, 'Implementation', p.implementation);
      warnings(section, p.warnings);
      const provenance = node('details'); provenance.append(node('summary', 'People data provenance'), evidenceValue({revision:p.revision, observed_at:p.observed_at})); section.append(provenance);
      parent.append(section);
    }
    function mainRow(tip) {
      const m = obj(tip.main_comparison), row = node('div', undefined, 'main-comparison');
      if (obj(active.main_comparison).status !== 'available' || !['present', 'absent'].includes(m.status)) {
        row.append(node('p', 'Main comparison unavailable · presence and coverage unknown.')); return row;
      }
      const sha = str(m.sha || obj(obj(active.main_comparison).revision).sha).slice(0, 12);
      row.append(node('p', `Main ${sha}: ${m.status === 'absent' ? 'TIP absent' : 'TIP present'} · PR reviews do not establish main presence.`));
      if (m.status === 'present') {
        row.append(node('p', `Spec: ${m.spec_changed === true ? 'changed from current' : m.spec_changed === false ? 'same as current' : 'comparison unknown'} · Scheduled ${str(m.scheduled_fork, 'unknown')} · PR: ${str(m.merge_status, 'unknown')}`));
        if (!Number.isSafeInteger(obj(m.inventory).count) || obj(m.inventory).count <= 0) row.append(node('p', 'Main inventory missing · Coverage unknown'));
        else { row.append(node('p', `Main inventory: ${str(obj(m.inventory).status)} · ${count(obj(m.inventory).count)} requirements`)); coverage(row, m.coverage); }
      }
      return row;
    }
    function requirement(value) {
      const r = obj(value), d = node('details');
      d.append(node('summary', `${str(r.id)} · ${str(r.implementation_status)} · ${str(r.verification_status)}`));
      d.append(node('p', str(r.statement)));
      if (r.spec) d.append(link(r.spec.url, `Specification: ${str(r.spec.path)}:${str(r.spec.line)}`));
      d.append(node('h4', 'Applicability / supersession'));
      d.append(r.applicability ? evidenceValue(r.applicability) : node('p', 'Scope not recorded.'));
      meta(d, [['Kind', r.kind], ['Required cases', arr(r.cases).map(v => str(v)).join(', ') || 'None recorded']]);
      d.append(node('p', caseLabel(caseCoverage(r)), 'case-coverage'));
      automatedReview(d, r.review || r.reviews);
      warnings(d, r.warnings);
      sourceList(d, 'Implementation / code gates', r.implementations, false);
      sourceList(d, 'Assertions', r.assertions, true);
      d.append(node('h4', 'Test attempts'));
      d.append(arr(r.test_attempts).length ? evidenceValue(r.test_attempts) : node('p', 'No matching test attempt recorded.'));
      d.append(node('h4', 'Execution evidence / CI provenance'));
      d.append(arr(r.evidence).length ? evidenceValue(r.evidence) : node('p', 'No execution evidence recorded.'));
      return d;
    }
    function tipCard(tip) {
      const d = node('details', undefined, 'tip'), s = node('summary');
      s.append(node('span', `${str(tip.id)} — ${str(tip.title)}`, 'tip-title'));
      const c = obj(tip.coverage), cases = tipCases(tip);
      const missing = Number.isSafeInteger(c.total) && Number.isSafeInteger(c.linked) ? Math.max(0, c.total - c.linked) : undefined;
      s.append(node('span', `PR: ${str(tip.merge_status)} · ${str(tip.status)}`, 'summary-line'));
      s.append(node('span', (!Number.isSafeInteger(obj(tip.inventory).count) || obj(tip.inventory).count <= 0 || c.total === 0) ? 'Inventory missing · Coverage unknown' : `Linked ${count(c.linked)}/${count(c.total)} · Reviewed ${count(c.reviewed)}/${count(c.total)} · Verified ${count(c.verified)}/${count(c.total)} · Assertions ${cases.linked}/${cases.total} · Missing links ${count(missing)}`, 'summary-line'));
      const guards = [...new Set(arr(tip.requirements).flatMap(r => arr(obj(r).implementations).map(i => obj(i).gate)).filter(g => typeof g === 'string' && g))];
      s.append(node('span', `Scheduled ${fork(tip)} · Actual guards: ${guards.join(', ') || 'None recorded'}`, 'summary-line'));
      d.append(s);
      d.append(node('p', `Inventory: ${str(obj(tip.inventory).status)}. Assertion counts are unique declared cases; reviewed counts do not imply human review. Missing links counts inventoried requirements without implementation links.`, 'muted'));
      d.append(link(obj(tip.spec).url, `Specification: ${str(obj(tip.spec).path)}`));
      d.append(mainRow(tip));
      people(d, tip);
      automatedReview(d, obj(tip.inventory).review || obj(tip.inventory).reviews);
      warnings(d, tip.warnings);
      for (const value of arr(tip.implementation_prs)) {
        const pr = obj(value), box = node('p');
        box.append(link(pr.url, `PR ${str(pr.number, '?')} · ${str(pr.state)}${pr.is_draft === true ? ' · Draft' : ''}`));
        d.append(box);
      }
      if (!arr(tip.requirements).length) d.append(node('p', 'No requirement inventory recorded.'));
      for (const r of arr(tip.requirements)) d.append(requirement(r));
      const provenance = node('details'); provenance.append(node('summary', 'Provenance'), evidenceValue({scheduled_fork_source: tip.scheduled_fork_source, implementation_prs: tip.implementation_prs})); d.append(provenance);
      return d;
    }
    function renderTips() {
      const container = el('results'); container.replaceChildren();
      if (!active) { el('result-count').textContent = ''; return; }
      const keys = upgradeForks(active, el('scope').value === 'all');
      const search = el('search').value.trim();
      const tips = active.tips.filter(t => keys.includes(fork(t)) && matches(t, {search}));
      el('result-count').textContent = `${tips.length} of ${active.tips.length} TIPs shown`;
      if (search && !tips.length) container.append(node('p', 'No TIPs match this search.', 'empty'));
      for (const key of keys) {
        const scheduled = active.tips.filter(t => fork(t) === key), rows = tips.filter(t => fork(t) === key);
        if (search && !rows.length) continue;
        const section = node('section', undefined, 'upgrade');
        const role = /^T\d+[A-Z]?$/.test(key) ? 'network upgrade' : '';
        section.append(node('h2', `${key}${role ? ' · ' + role : ''}`));
        if (!scheduled.length) section.append(node('p', 'No scheduled TIPs recorded', 'empty'));
        for (const tip of rows) section.append(tipCard(tip));
        container.append(section);
      }
    }
    function unavailable(error) {
      active = null;
      el('snapshot').replaceChildren();
      el('results').replaceChildren();
      el('result-count').textContent = '';
      el('load-status').textContent = `Report unavailable: ${error.message || error}`;
    }
    function showReport(text, expectedSHA) {
      try {
        const data = parseReport(text);
        if (expectedSHA && data.revision.sha !== expectedSHA) throw new Error('Report revision differs from hosted index.');
        if (['error', 'failed'].includes(obj(data.collection).status)) throw new Error('Report collection failed; no coverage established.');
        active = data;
        const revision = obj(data.revision), box = el('snapshot'); box.replaceChildren();
        box.append(node('p', `Source ${str(revision.sha).slice(0, 12)}${revision.dirty === true ? ' · local changes included' : ''} · ${str(revision.requested)} · Collection: ${str(obj(data.collection).status)}`, 'source'));
        const main = obj(data.main_comparison), mainRevision = obj(main.revision);
        box.append(node('p', `Current revision ${str(revision.sha).slice(0, 12)}${revision.dirty === true ? ' + local changes' : ''} vs main ${main.status === 'available' ? str(mainRevision.sha).slice(0, 12) : 'unavailable'}`, 'main-comparison'));
        if (main.status === 'available') {
          const only = arr(main.only_on_main).filter(id => typeof id === 'string');
          if (only.length) {
            const mainOnly = node('details');
            mainOnly.append(node('summary', `Only on main: ${only.length} TIPs`), node('p', only.join(', ')));
            box.append(mainOnly);
          }
          if (reportURL(main.url)) {
            const reportLink = node('a', 'Main report · full inventory');
            reportLink.href = main.url; reportLink.target = '_blank'; reportLink.rel = 'noopener noreferrer';
            box.append(reportLink);
          }
        }
        warnings(box, main.warnings);
        const provenance = node('details');
        provenance.append(node('summary', 'Provenance'), evidenceValue({repository:data.repository, revision, main_comparison:main, generated_at:data.generated_at, collection:data.collection})); box.append(provenance);
        el('load-status').textContent = 'Read-only report snapshot';
        renderTips();
        return data;
      } catch (error) { unavailable(error); return null; }
    }
    let request = 0;
    async function loadURL(url, sha) {
      const token = ++request;
      unavailable('Loading report…');
      try {
        const response = await fetcher(url, {cache:'no-store'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const text = await response.text();
        if (token === request) showReport(text, sha);
      } catch (error) { if (token === request) unavailable(error); }
    }
    el('reports').addEventListener('change', () => {
      const selected = reports[Number(el('reports').value)];
      if (selected) return loadURL(selected.url, selected.sha);
    });
    el('search').addEventListener('input', renderTips);
    el('scope').addEventListener('change', renderTips);
    async function load() {
      const embedded = el('embedded-report');
      if (embedded) { showReport(embedded.textContent); return; }
      if (protocol === 'file:') { unavailable('This page has no bundled report. Open the generated portable dashboard or a hosted report.'); return; }
      await loadURL('report.json');
      try {
        const response = await fetcher('index.json', {cache:'no-store'});
        if (!response.ok) return;
        const index = JSON.parse(await response.text());
        const entries = arr(index.reports).filter(r => r && typeof r.label === 'string' && typeof r.sha === 'string' && /^[a-f0-9]{40}$/i.test(r.sha) && reportURL(r.url));
        if (entries.length < 2 || entries.length !== arr(index.reports).length) return;
        reports.push(...entries);
        el('reports').replaceChildren();
        const activeIndex = active ? reports.findIndex(r => r.sha === active.revision.sha) : -1;
        if (activeIndex < 0) { const placeholder = node('option', 'Select hosted report'); placeholder.value = ''; placeholder.disabled = true; el('reports').append(placeholder); }
        reports.forEach((r, i) => { const option = node('option', `${r.label} · ${r.sha.slice(0,12)}`); option.value = String(i); el('reports').append(option); });
        el('reports').value = activeIndex < 0 ? '' : String(activeIndex);
        el('report-picker').hidden = false;
      } catch (_) { /* The optional report index does not replace the loaded report. */ }
    }
    return {load, showReport, renderTips};
  }
  const api = {safeURL, reportURL, parseReport, matches, hasWarnings, fork, upgradeForks, caseCoverage, tipCases, mount};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root.document) api.mount(root.document, root.fetch.bind(root), root.location.protocol).load();
})(typeof window !== 'undefined' ? window : globalThis);
