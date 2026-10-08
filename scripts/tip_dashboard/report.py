#!/usr/bin/env python3
"""Conservative, offline-first TIP inventory and evidence report (stdlib only)."""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

VERSION = 1
EXCLUDED = {'.git', 'target', 'output', 'out', 'node_modules', '__pycache__', '.venv'}
SOURCE_EXT = {'.rs', '.sol', '.py', '.toml', '.json', '.md', '.yml', '.yaml', '.lock', '.js', '.css', '.html', '.sh'}
RID = r'TIP-\d+:[A-Za-z][\w.-]*'
REQ = re.compile(r'<!--\s*@requirement\s+(' + RID + r')\s+([^\n]*?)\s*-->')
LABEL = re.compile(r'^\s*//\s*@(implements|asserts)\s+(' + RID + r')\s+(.+)$')
PR = re.compile(r'https://github\.com/([\w.-]+/[\w.-]+)/pull/(\d+)\b')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def file_digest(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.PIPE)


def included(path):
    return not (set(Path(path).parts) & EXCLUDED)


class Snapshot:
    def __init__(self, repo, revision='WORKTREE'):
        self.repo = Path(repo).resolve()
        self.sha = git(repo, 'rev-parse', '--verify', '--end-of-options', ( 'HEAD' if revision == 'WORKTREE' else revision) + '^{commit}').decode().strip()
        self.files = {}
        self.modes = {}
        if revision == 'WORKTREE':
            paths = git(repo, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().split('\0')
            tracked = set(git(repo, 'ls-files', '-z').decode().split('\0'))
            for path in sorted(set(paths)):
                if not path or not included(path):
                    continue
                if path not in tracked and Path(path).suffix not in SOURCE_EXT:
                    continue
                p = self.repo / path
                if p.is_symlink():
                    self.files[path] = os.readlink(p).encode()
                    self.modes[path] = '120000'
                elif p.is_file():
                    self.files[path] = p.read_bytes()
                    self.modes[path] = '100755' if p.stat().st_mode & 0o111 else '100644'
            # Dirty is explicit, even when a dirty output isn't part of source identity.
            changed = git(repo, 'diff', '--name-only', '-z', 'HEAD').decode().split('\0')
            untracked = [p for p in paths if p not in tracked and Path(p).suffix in SOURCE_EXT]
            self.dirty = any(p and included(p) for p in changed + untracked)
        else:
            self.dirty = False
            archive = git(repo, 'archive', '--format=tar', self.sha)
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                for entry in tar:
                    if not included(entry.name):
                        continue
                    if entry.isfile():
                        self.files[entry.name] = tar.extractfile(entry).read()
                        self.modes[entry.name] = '100755' if entry.mode & 0o111 else '100644'
                    elif entry.issym():
                        self.files[entry.name] = entry.linkname.encode()
                        self.modes[entry.name] = '120000'
        # Git archives omit gitlinks. Bind each selected submodule pin explicitly.
        self.submodules_dirty = []
        tree = git(repo, 'ls-tree', '-rz', self.sha).decode().split('\0')
        for row in tree:
            if not row:
                continue
            info, path = row.split('\t', 1)
            mode, kind, oid = info.split()
            if mode != '160000' or not included(path):
                continue
            self.modes[path] = mode
            if revision == 'WORKTREE' and (self.repo / path / '.git').exists():
                actual = git(self.repo / path, 'rev-parse', 'HEAD').decode().strip()
                if actual != oid or git(self.repo / path, 'status', '--porcelain').strip():
                    self.submodules_dirty.append(path)
                oid = actual
            self.files[path] = oid.encode()
        self.identity = dict(requested=revision, sha=self.sha, dirty=self.dirty,
                             source_digest=digest([[p, self.modes[p], file_digest(b)] for p, b in sorted(self.files.items())]))

    def text(self, path):
        if self.modes.get(path) == '120000':
            return ''  # Never treat symlink targets as annotation-bearing source.
        return self.files.get(path, b'').decode('utf-8', errors='replace')


def identity(repo, revision='WORKTREE'):
    return Snapshot(repo, revision).identity


def snapshot_tool_digest(s=None):
    # The reporting tools can come from a newer checkout than the candidate.
    return digest([[p.name, file_digest(p.read_bytes())]
                   for p in sorted(Path(__file__).parent.glob('*.py'))
                   if not p.name.startswith('test')])


def tool_digest(repo):
    return snapshot_tool_digest()


def attrs(text):
    return dict(re.findall(r'([a-z_]+)=([^\s]+)', text))


def warning(code, message):
    return {'code': code, 'message': message}


def url(s, path, line=None):
    # Dirty working source is deliberately not represented as an immutable GitHub link.
    if s.identity['requested'] == 'WORKTREE' and s.dirty:
        return None
    return 'https://github.com/tempoxyz/tempo/blob/' + s.sha + '/' + path + (f'#L{line}' if line else '')


def canonical_fork(value):
    value = str(value or '').strip().strip('"\'')
    if value.lower() == 'genesis':
        return 'Genesis'
    match = re.fullmatch(r'[Tt](\d+)(?:\.?([A-Za-z]))?', value)
    return 'T' + str(int(match.group(1))) + (match.group(2) or '').upper() if match else None


def fork_number(value):
    fork = canonical_fork(value)
    if fork == 'Genesis':
        return (-1, '')
    match = re.fullmatch(r'T(\d+)([A-Z]?)', fork or '')
    return (int(match.group(1)), match.group(2)) if match else None


def same_identity(left, right):
    return isinstance(left, dict) and isinstance(right, dict) and all(
        k in left and k in right and type(left[k]) is type(right[k]) and left[k] == right[k]
        for k in ('sha', 'source_digest', 'dirty'))


def review_records(rows, key, value):
    return [r for r in rows if isinstance(r, dict) and r.get(key) == value]



def without_fences(text):
    """Ignore example labels while preserving offsets for real spec locations."""
    output, fence = [], None
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        marker = re.match(r"(`{3,}|~{3,})", stripped)
        if marker and fence is None:
            fence = marker.group(1)
            output.append(re.sub(r"[^\n]", " ", line))
        elif fence is not None:
            output.append(re.sub(r"[^\n]", " ", line))
            if marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence):
                fence = None
        else:
            output.append(line)
    return ''.join(output)


def reviewed(rows, key, value, expected):
    matches = review_records(rows, key, value)
    return len(matches) == 1 and matches[0].get('reviewer_kind') in ('agent', 'human') and all(matches[0].get(k) == v for k, v in expected.items()) and all(isinstance(matches[0].get(k), str) and matches[0][k].strip() for k in ('reviewer', 'source'))


def load_reviews(s, warnings):
    try:
        data = json.loads(s.text('tips/verification/reviews.json') or '{}')
        if not isinstance(data, dict) or data.get('schema_version') != 1 or not all(isinstance(data.get(k, []), list) for k in ('inventories', 'requirements')):
            if data:
                warnings.append(warning('invalid_reviews', 'Review metadata has unsupported schema.'))
            return {}
        return data
    except (ValueError, TypeError):
        warnings.append(warning('invalid_reviews', 'Review metadata is not valid JSON.'))
        return {}


def scan(s, github=False):
    warnings, tips, by_id = [], [], {}
    reviews = load_reviews(s, warnings)
    if s.submodules_dirty:
        warnings.append(warning('dirty_submodules', 'Execution evidence unavailable with modified submodules: ' + ', '.join(s.submodules_dirty)))
    for path in sorted(s.files):
        if not re.fullmatch(r'tips/tip-\d+\.md', path):
            continue
        text = s.text(path)
        fm = re.match(r'^---\s*\n(.*?)\n---', text, re.S)
        meta = dict(re.findall(r'^([\w]+):\s*(.*?)\s*$', fm.group(1), re.M)) if fm else {}
        tip_id = 'TIP-' + re.search(r'tip-(\d+)', path).group(1)
        tip = dict(id=tip_id, declared_authors=meta.get('authors', '').strip('"\''), people={'status': 'not_requested'}, title=meta.get('title', tip_id).strip('"\''), status=meta.get('status', 'Unknown'), scheduled_fork=canonical_fork(meta.get('protocolVersion')), scheduled_fork_source=meta.get('protocolVersion'),
                   spec={'path': path, 'url': url(s, path), 'digest': file_digest(s.files[path])}, inventory={'status': 'incomplete', 'count': 0}, implementation_prs=[], merge_status='unknown', implemented_forks=[], coverage={}, warnings=[], requirements=[])
        if fm and len(re.findall(r'^protocolVersion:', fm.group(1), re.M)) > 1:
            tip['scheduled_fork'] = None
            tip['warnings'].append(warning('conflicting_schedule', 'Duplicate canonical protocolVersion fields; schedule is unknown.'))
        if not fm or meta.get('id') != tip_id:
            tip['warnings'].append(warning('frontmatter', 'Missing or inconsistent TIP frontmatter.'))
        if not tip['scheduled_fork']:
            tip['warnings'].append(warning('unscheduled', 'Missing or unrecognized protocolVersion in frontmatter: ' + repr(meta.get('protocolVersion'))))
        for m in REQ.finditer(without_fences(text)):
            a = attrs(m.group(2))
            line_start = text.rfind('\n', 0, m.start()) + 1
            line_end = text.find('\n', m.end())
            line_end = len(text) if line_end < 0 else line_end
            inline = text[line_start:m.start()].strip()
            if inline.startswith('|'):
                paragraph = REQ.sub('', text[line_start:line_end]).strip()
            else:
                # Stop before the next annotation, including contiguous list items.
                paragraph = REQ.split(text[m.end():], maxsplit=1)[0].lstrip('\n').split('\n\n', 1)[0].strip()
            cases = a.get('cases', '').split(',') if a.get('cases') else []
            req = dict(id=m.group(1), statement=paragraph, kind=a.get('kind', 'unknown'), cases=cases, implementations=[], assertions=[], implementation_status='missing', verification_status='not_run', evidence=[], test_attempts=[], warnings=[], spec_digest=tip['spec']['digest'])
            if not paragraph or not cases or len(set(cases)) != len(cases) or not req['id'].startswith(tip_id + ':'):
                req['warnings'].append(warning('invalid_requirement', 'Requirement must belong to this TIP and have a statement and unique named cases.'))
            req['spec'] = dict(path=path, line=text[:m.start()].count('\n') + 1, url=url(s, path, text[:m.start()].count('\n') + 1))
            req['applicability'] = dict(from_fork=canonical_fork(a.get('from')), until_fork=canonical_fork(a.get('until')), superseded_by=a.get('superseded_by'), at_fork={})
            req['applicability']['declared'] = {k: a[k] for k in ('from', 'until', 'superseded_by') if k in a}
            if any(k in a and canonical_fork(a[k]) is None for k in ('from', 'until')) or (a.get('from') and a.get('until') and fork_number(a.get('from')) is not None and fork_number(a.get('until')) is not None and fork_number(a['from']) >= fork_number(a['until'])):
                req['warnings'].append(warning('invalid_scope', 'Scope requires canonical forks with from < until (until is exclusive).'))
            tip['requirements'].append(req)
            by_id.setdefault(req['id'], []).append(req)
        tip['inventory']['count'] = len(tip['requirements'])
        tip['inventory']['review'] = None
        if tip['requirements'] and all(not r['warnings'] for r in tip['requirements']) and reviewed(reviews.get('inventories', []), 'tip', tip_id, {'spec_digest': tip['spec']['digest']}):
            tip['inventory']['status'] = 'reviewed'
            tip['inventory']['review'] = review_records(reviews.get('inventories', []), 'tip', tip_id)[0]
        else:
            tip['warnings'].append(warning('incomplete_inventory', 'Requirement inventory has not been reviewed against this spec digest.'))
        # Explicit implementation metadata and the existing meta-TIP PR paragraphs.
        # Related-work PRs alone never establish an implementation association.
        impl = re.search(r'^implementation[s]?:[^\n]*(?:\n[ \t]+[^\n]*)*', fm.group(1), re.M) if fm else None
        pr_text = (impl.group(0) if impl else '') + '\n' + '\n'.join(re.findall(r'^\*\*PRs?\*\*:[^\n]*(?:\n\[#\d+\][^\n]*)*', text, re.M))
        for repository, number in sorted(set(PR.findall(pr_text))):
            pr = dict(url=f'https://github.com/{repository}/pull/{number}', number=int(number), state='unknown', is_draft=None, merge_commit=None)
            if github:
                try:
                    raw = subprocess.check_output(['gh', 'pr', 'view', number, '--repo', repository, '--json', 'state,isDraft,mergeCommit'], timeout=20, stderr=subprocess.PIPE)
                    data = json.loads(raw)
                    state = str(data.get('state', '')).lower()
                    pr.update(state=state if state in ('open', 'closed', 'merged') else 'unknown', is_draft=data.get('isDraft'), merge_commit=(data.get('mergeCommit') or {}).get('oid'))
                except (OSError, subprocess.SubprocessError, ValueError, AttributeError):
                    tip['warnings'].append(warning('github_unavailable', f'Could not read {pr["url"]}.'))
            tip['implementation_prs'].append(pr)
        if not tip['implementation_prs']:
            tip['warnings'].append(warning('unknown_implementation_prs', 'No implementation PR association declared in this spec.'))
        states = [p['state'] for p in tip['implementation_prs']]
        if states and 'unknown' not in states:
            tip['merge_status'] = 'merged' if all(x == 'merged' for x in states) else 'partially_merged' if 'merged' in states else 'open' if 'open' in states else 'closed'
        tips.append(tip)
    for rid, reqs in by_id.items():
        if len(reqs) != 1:
            for req in reqs:
                req['warnings'].append(warning('duplicate_requirement', f'Duplicate stable ID {rid}.'))
    for path in sorted(s.files):
        if Path(path).suffix not in ('.rs', '.sol'):
            continue
        lines = s.text(path).splitlines()
        for i, line in enumerate(lines):
            m = LABEL.match(line)
            if not m:
                continue
            label, rid, raw = m.groups()
            a = attrs(raw)
            if rid not in by_id or len(by_id[rid]) != 1:
                warnings.append(warning('unresolved_label', f'{path}:{i+1}: unresolved or duplicate {rid}'))
                continue
            req = by_id[rid][0]
            entry = dict(path=path, line=i+1, end_line=len(lines), url=url(s, path, i+1), digest=file_digest(s.files[path]))
            # Entire file is the conservative semantic scope. The next nonempty line
            # must be code; labels do not establish semantics or review by themselves.
            code_index = next((j for j in range(i+1, len(lines)) if lines[j].strip() and not LABEL.match(lines[j])), len(lines))
            adjacent = lines[code_index].strip() if code_index < len(lines) else ''
            expression_lines = []
            for code_line in lines[code_index:code_index+12]:
                expression_lines.append(code_line.strip())
                if ';' in code_line or '{' in code_line or code_line.rstrip().endswith(')'):
                    break
            expression = ' '.join(expression_lines)
            entry.update(source_expression=expression, code_line=code_index+1)
            if not adjacent or adjacent.startswith('//'):
                req['warnings'].append(warning('nonadjacent_label', f'{path}:{i+1}: label must precede code.'))
            if label == 'implements':
                gate = a.get('gate', '')
                fork = re.search(r'\bis_(t\d+[a-z]?)\(', gate, re.I)
                scheduled = re.fullmatch(r'schedule\(since=(T\d+[A-Z]?)\)', gate)
                declared_fork = canonical_fork((scheduled or fork).group(1)) if scheduled or fork else None
                # Dispatch macros use an attribute rather than an is_tN() predicate.
                # Accept only the exact adjacent since-only attribute. Additional
                # conditions, comments and string examples must remain unresolved.
                attribute = re.fullmatch(r'#\[\s*schedule\s*\(\s*since\s*=\s*(T\d+[A-Z]?)\s*\)\s*\]', adjacent)
                actual = ([attribute.group(1)] if attribute else
                          re.findall(r'\bis_(t\d+[a-z]?)\s*\(', expression, re.I))
                actual_forks = sorted(set(canonical_fork(f) for f in actual))
                entry.update(gate=gate, declared_fork=declared_fork, fork=actual_forks[0] if len(actual_forks) == 1 else None)
                compact = re.sub(r'\s+', '', expression.split('//', 1)[0])
                matches_source = bool(attribute) if scheduled else gate in compact
                if gate != 'always' and (not declared_fork or not matches_source or declared_fork != entry['fork']):
                    req['warnings'].append(warning('gate_mismatch', f'{path}:{i+1}: declared gate is not established by adjacent source expression.'))
                if not gate or (gate == 'always' and actual_forks):
                    req['warnings'].append(warning('invalid_gate', f'{path}:{i+1}: missing or invalid activation gate.'))
                req['implementations'].append(entry)
            else:
                entry.update(test=a.get('test'), case=a.get('case'), fork=canonical_fork(a.get('fork')))
                if not entry['test'] or entry['case'] not in req['cases'] or entry['fork'] is None:
                    req['warnings'].append(warning('invalid_assertion', f'{path}:{i+1}: missing test, expected fork, or undeclared case.'))
                if not re.search(r'\b(assert\w*|expect\w*|spec_evidence)\s*[!(]', adjacent):
                    req['warnings'].append(warning('nonassertion_label', f'{path}:{i+1}: label does not precede an assertion.'))
                req['assertions'].append(entry)
    for tip in tips:
        for req in tip['requirements']:
            scope = req['applicability']
            if scope['superseded_by'] and (scope['superseded_by'] == req['id'] or len(by_id.get(scope['superseded_by'], [])) != 1 or not scope['until_fork']):
                req['warnings'].append(warning('unresolved_supersession', 'superseded_by requires a unique different requirement and an explicit exclusive until fork.'))
            if req['kind'] == 'activation' and tip['scheduled_fork'] and any(e['fork'] and e['fork'] != tip['scheduled_fork'] for e in req['implementations']):
                req['warnings'].append(warning('activation_schedule_mismatch', 'Observed activation guard differs from scheduled protocolVersion.'))
            case_forks = {}
            for assertion in req['assertions']:
                case_forks.setdefault(assertion['case'], set()).add(assertion['fork'])
            if any(len(forks) > 1 for forks in case_forks.values()):
                req['warnings'].append(warning('ambiguous_case_fork', 'A case spans different expected forks; declare separate case IDs for each fork obligation.'))
            for field, links in [('source_digest', 'implementations'), ('test_digest', 'assertions')]:
                req[field] = digest(sorted(set((e['path'], e['digest']) for e in req[links])))
            if req['implementations']:
                req['implementation_status'] = 'linked'
            expected = {k: req[k] for k in ('spec_digest', 'source_digest', 'test_digest')}
            if req['implementations'] and not req['warnings'] and reviewed(reviews.get('requirements', []), 'id', req['id'], expected):
                req['implementation_status'] = 'reviewed'
                req['review'] = review_records(reviews.get('requirements', []), 'id', req['id'])[0]
        tip['implemented_forks'] = sorted({e['fork'] for r in tip['requirements'] for e in r['implementations'] if e['fork']})
    return tips, warnings


def context(s, tips):
    requirements = [r for t in tips for r in t['requirements']]
    return dict(identity=s.identity, tool_digest=snapshot_tool_digest(s),
                manifest_digest=digest([{k: r[k] for k in ('id', 'kind', 'cases', 'spec_digest', 'source_digest', 'test_digest')} for r in requirements]),
                checks_digest=digest([{ 'id': r['id'], 'assertions': [{k: v for k, v in a.items() if k != 'url'} for a in r['assertions']]} for r in requirements]))


def evidence_context(repo, revision='WORKTREE'):
    s = Snapshot(repo, revision)
    return context(s, scan(s)[0])


def apply_evidence(tips, envelope, ctx, warnings):
    requirements = [r for t in tips for r in t['requirements']]
    if envelope is None:
        return
    if not isinstance(envelope, dict) or envelope.get('schema_version') != 1:
        warnings.append(warning('invalid_evidence', 'Unsupported evidence schema.'))
        for r in requirements:
            r['verification_status'] = 'unknown'
        return
    if not same_identity(envelope.get('identity'), ctx['identity']) or any(envelope.get(k) != v for k, v in ctx.items() if k != 'identity'):
        warnings.append(warning('stale_evidence', 'Evidence identity or manifest/check/tool digest does not match.'))
        for r in requirements:
            r['verification_status'] = 'stale'
        return
    runner, provenance, attempts = envelope.get('runner'), envelope.get('provenance'), envelope.get('attempts')
    valid = not envelope.get('errors') and not envelope.get('error') and isinstance(runner, dict) and all(isinstance(runner.get(k), str) and runner[k] for k in ('name', 'version')) and isinstance(provenance, dict) and provenance.get('kind') in ('local', 'ci') and isinstance(attempts, list)
    seen = set()
    if valid:
        for attempt in attempts:
            if not isinstance(attempt, dict) or not isinstance(attempt.get('id'), str) or not attempt['id'] or attempt['id'] in seen or not isinstance(attempt.get('test'), str) or attempt.get('outcome') not in ('passed', 'failed', 'skipped') or type(attempt.get('exit_code')) is not int or type(attempt.get('timed_out')) is not bool or not isinstance(attempt.get('markers'), list):
                valid = False
                break
            seen.add(attempt['id'])
            if attempt.get('error') or attempt.get('errors'):
                valid = False
            if attempt['outcome'] == 'passed' and (attempt['exit_code'] != 0 or attempt['timed_out']):
                valid = False
            for marker in attempt['markers']:
                if not isinstance(marker, dict) or any(not isinstance(marker.get(k), str) or not marker[k] for k in ('requirement', 'case', 'test', 'fork')) or marker['test'] != attempt['test']:
                    valid = False
    if not valid:
        warnings.append(warning('invalid_evidence', 'Malformed or contradictory attempt envelope.'))
        for r in requirements:
            r['verification_status'] = 'unknown'
        return
    for tip in tips:
        for r in tip['requirements']:
            passed, outcomes = set(), []
            links = {(a['test'], a['case'], a['fork']) for a in r['assertions']}
            tests = {a['test'] for a in r['assertions']}
            for a in attempts:
                if a['test'] in tests:
                    outcomes.append(a['outcome'])
                    r['test_attempts'].append({k: a.get(k) for k in ('id', 'test', 'outcome', 'exit_code', 'timed_out', 'completed_tests', 'errors')})
                for m in a['markers']:
                    if m['requirement'] != r['id']:
                        continue
                    if (m['test'], m['case'], m['fork']) not in links or m['case'] not in r['cases']:
                        r['warnings'].append(warning('unmatched_marker', 'Marker does not match a declared assertion/case/expected fork.'))
                        continue
                    r['evidence'].append(dict(m, outcome=a['outcome'], attempt=a['id'], runner=runner, provenance=provenance))
                    if a['outcome'] == 'passed':
                        passed.add(m['case'])
            if 'failed' in outcomes:
                r['verification_status'] = 'failed'
            elif passed:
                complete = set(r['cases']) <= passed and r['cases'] and not r['warnings'] and r['implementation_status'] == 'reviewed' and tip['inventory']['status'] == 'reviewed'
                r['verification_status'] = 'verified' if complete else 'partial'
            elif outcomes and all(o == 'skipped' for o in outcomes):
                r['verification_status'] = 'skipped'
            elif outcomes:
                r['verification_status'] = 'unexercised'


def build_report(repo, revision='WORKTREE', evidence=None, github=False):
    s = Snapshot(repo, revision)
    tips, warnings = scan(s, github)
    ctx = context(s, tips)
    if isinstance(evidence, (str, Path)):
        try:
            evidence = json.loads(Path(evidence).read_text())
        except (OSError, ValueError):
            evidence = {}  # Explicit bad evidence cannot silently become not_run.
    apply_evidence(tips, evidence, ctx, warnings)
    if s.submodules_dirty:
        for t in tips:
            for r in t['requirements']:
                r['verification_status'] = 'unknown'
                r['evidence'] = []
    foundry = s.text('tips/verify/foundry.toml')
    profile = re.search(r'^\[profile\.next\]\s*\n(.*?)(?=^\[|\Z)', foundry, re.M | re.S)
    fork = re.search(r'^hardfork\s*=\s*[\"\']tempo:(T\d+)[\"\']', profile.group(1), re.M) if profile else None
    current_profile = re.search(r'^\[profile\.default\]\s*\n(.*?)(?=^\[|\Z)', foundry, re.M | re.S)
    current = re.search(r'^hardfork\s*=\s*[\"\']tempo:(T\d+)[\"\']', current_profile.group(1), re.M) if current_profile else None
    if not fork:
        warnings.append(warning('unknown_next_fork', 'No unambiguous profile.next hardfork.'))
    if not tips or not any(t['requirements'] for t in tips):
        warnings.append(warning('empty_inventory', 'No requirement inventory is available; completeness cannot be established.'))
    forks = sorted({f for t in tips for f in [t['scheduled_fork'], *t['implemented_forks']] if f} | ({fork.group(1)} if fork else set()) | ({current.group(1)} if current else set()) | {a['fork'] for t in tips for r in t['requirements'] for a in r['assertions'] if a['fork']}, key=fork_number)
    for t in tips:
        for r in t['requirements']:
            scope = r['applicability']
            for f in forks:
                invalid = any(w['code'] in ('invalid_scope', 'unresolved_supersession') for w in r['warnings'])
                scope['at_fork'][f] = None if invalid or not scope['from_fork'] else (scope['from_fork'] is None or fork_number(f) >= fork_number(scope['from_fork'])) and (scope['until_fork'] is None or fork_number(f) < fork_number(scope['until_fork']))
        reqs = t['requirements']
        for r in reqs:
            linked = {a['case'] for a in r['assertions'] if a['case'] in r['cases']}
            executed = {e['case'] for e in r['evidence'] if e['outcome'] in ('passed', 'failed')}
            passed = {e['case'] for e in r['evidence'] if e['outcome'] == 'passed'}
            r['assertion_coverage'] = dict(total=len(r['cases']), linked=len(linked), executed=len(executed), passed=len(passed))
            r['missing_assertions'] = sorted(set(r['cases']) - linked)
            r['missing_passing_cases'] = sorted(set(r['cases']) - passed)
            if not r['implementations']:
                r['warnings'].append(warning('missing_implementation', 'No implementation labels at the inspected revision.'))
            if r['missing_assertions']:
                r['warnings'].append(warning('missing_assertions', 'Cases without assertion links: ' + ', '.join(r['missing_assertions'])))
            if r['verification_status'] != 'verified':
                r['warnings'].append(warning('unverified', 'Execution verification status: ' + r['verification_status']))
        t['assertion_coverage'] = {key: sum(r['assertion_coverage'][key] for r in reqs) for key in ('total', 'linked', 'executed', 'passed')}
        t['coverage'] = dict(total=len(reqs), linked=sum(bool(r['implementations']) for r in reqs), reviewed=sum(r['implementation_status'] == 'reviewed' for r in reqs), verified=sum(r['verification_status'] == 'verified' for r in reqs))
    latest = list(dict.fromkeys([f for f in [fork.group(1) if fork else None, current.group(1) if current else None] if f]))
    scheduled = sorted({t['scheduled_fork'] for t in tips if t['scheduled_fork']}, key=fork_number, reverse=True)
    for f in scheduled:
        if len(latest) >= 3:
            break
        if f not in latest and (not current or fork_number(f) < fork_number(current.group(1))):
            latest.append(f)
    warning_count = len(warnings) + sum(len(t['warnings']) + sum(len(r['warnings']) for r in t['requirements']) for t in tips)
    return dict(schema_version=1, generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), repository='tempoxyz/tempo', revision=s.identity, evidence_context=ctx,
                collection={'status': 'warnings' if warning_count else 'complete', 'warnings': warnings}, next_fork=fork.group(1) if fork else None, current_fork=current.group(1) if current else None, latest_forks=latest,
                summary=dict(tips=len(tips), requirements=sum(t['coverage']['total'] for t in tips), **{k: sum(t['coverage'][k] for t in tips) for k in ('linked', 'reviewed', 'verified')}, warnings=warning_count), tips=tips)


def compare_reports(candidate, baseline, requested):
    """Compare independent snapshots; never promote PR evidence into main evidence."""
    available = baseline.get('collection', {}).get('status') != 'error' and bool(baseline.get('revision', {}).get('sha'))
    candidate['main_comparison'] = dict(
        status='available' if available else 'unavailable', revision=baseline.get('revision', {'requested': requested}),
        url='main/report.json', warnings=baseline.get('collection', {}).get('warnings', []),
        only_on_main=sorted({t['id'] for t in baseline.get('tips', [])} - {t['id'] for t in candidate['tips']}) if available else [])
    by_id = {t['id']: t for t in baseline.get('tips', [])}
    for tip in candidate['tips']:
        other = by_id.get(tip['id'])
        comparison = dict(status='unavailable' if not available else 'present' if other else 'absent',
                          sha=baseline.get('revision', {}).get('sha'))
        if other:
            comparison.update(spec_changed=tip['spec']['digest'] != other['spec']['digest'],
                              inventory=other['inventory'], coverage=other['coverage'],
                              scheduled_fork=other['scheduled_fork'], merge_status=other['merge_status'])
        tip['main_comparison'] = comparison
    if not available:
        candidate['collection']['warnings'].append(warning('main_unavailable', 'Main comparison unavailable; no main coverage is established.'))
        if candidate['collection']['status'] != 'error':
            candidate['collection']['status'] = 'warnings'
        candidate['summary']['warnings'] += 1
    return candidate


def enrich_people(report, cache):
    # The CLI lives beside this module even when tooling and candidate checkouts differ.
    import github_people
    github_people.collect_people(report['revision']['sha'], report['tips'], cache=cache)


def markdown_summary(report):
    rev = report['revision']
    lines = ['# TIP dashboard', '', f"Revision: `{rev.get('sha') or 'unavailable'}` ({rev.get('requested')})",
             f"Collection: {report['collection']['status']}", f"Next fork: {report.get('next_fork') or 'unknown'}", '',
             ', '.join(f'{v} {k}' for k, v in report['summary'].items()), '']
    for w in report['collection']['warnings']:
        lines.append(f"- {w['code']}: {w['message']}")
    comparison = report.get('main_comparison')
    if comparison:
        lines += ['', f"Main comparison: {comparison['status']}; commit `{comparison.get('revision', {}).get('sha') or 'unavailable'}`", '',
                  'Main has its own inventory and execution evidence; PR reviews and passing PR tests do not verify main.']
        for w in comparison.get('warnings', []):
            lines.append(f"- Main: {w.get('code')}: {w.get('message')}")
    for tip in report['tips']:
        lines += ['', f"## {tip['id']} — scheduled {tip['scheduled_fork'] or 'unknown'}", '',
                  f"Inventory: {tip['inventory']['status']}; PR state: {tip['merge_status']}; coverage: {tip['coverage']}"]
        main = tip.get('main_comparison')
        if main:
            lines.append(f"- Main: {main['status']}; inventory {main.get('inventory', {}).get('status', 'unknown')}; coverage {main.get('coverage', 'unknown')}")
        if tip.get('declared_authors'):
            lines.append('Declared spec authors: ' + tip['declared_authors'])
        people = tip.get('people', {})
        lines.append('GitHub attribution: ' + people.get('status', 'not_requested'))
        for scope in ('spec', 'implementation'):
            for person in people.get(scope, {}).get('contributors', []):
                lines.append(f"- {scope} contributor: {person.get('login') or person.get('name') or 'unmapped'} ({', '.join(person.get('roles', []))})")
            for pr in people.get(scope, {}).get('pull_requests', []):
                author = pr.get('author') or {}
                lines.append(f"- {scope} PR #{pr['number']}: {pr['url']}; author {author.get('login') or author.get('name') or 'unavailable'}")
                for review in pr.get('reviews', []):
                    reviewer = review.get('author') or {}
                    lines.append(f"  Review {review.get('state')}: {reviewer.get('login') or reviewer.get('name') or 'unavailable'}; {review.get('url')}; commit {review.get('commit_sha') or 'unknown'}")
        for w in tip['warnings']:
            lines.append(f"- {w['code']}: {w['message']}")
        for r in tip['requirements']:
            lines.append(f"- {r['id']}: implementation {r['implementation_status']}; verification {r['verification_status']}; applicable at fork {r['applicability']['at_fork']}")
            passed = {e['case'] for e in r['evidence'] if e['outcome'] == 'passed'}
            missing = [c for c in r['cases'] if c not in passed]
            if missing:
                lines.append('  Missing passing cases: ' + ', '.join(missing))
            for w in r['warnings']:
                lines.append(f"  {w['code']}: {w['message']}")
    return '\n'.join(lines) + '\n\nAnnotation links alone do not establish implementation or verification.\n'


def error_report(revision, exc):
    return dict(schema_version=VERSION, generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                repository='tempoxyz/tempo', revision=dict(requested=revision, sha=None, dirty=None, source_digest=None),
                evidence_context=None, next_fork=None, tips=[],
                collection=dict(status='error', warnings=[warning('collection_error', str(exc))]),
                summary=dict(tips=0, requirements=0, linked=0, reviewed=0, verified=0, warnings=1))


def write_outputs(report, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    temporary = output / 'report.json.tmp'
    temporary.write_text(json.dumps(report, indent=2) + '\n')
    temporary.replace(output / 'report.json')
    summary = report['summary']
    (output / 'summary.md').write_text(markdown_summary(report))
    web = Path(__file__).parent / 'web'
    if web.is_dir():
        for name in ('index.html', 'app.js', 'style.css'):
            shutil.copy2(web / name, output / name)
        portable = (web / 'index.html').read_text().replace('<link rel="stylesheet" href="style.css">', '<style>' + (web / 'style.css').read_text() + '</style>')
        portable = portable.replace('<script defer src="app.js"></script>', '')
        embedded = json.dumps(report, ensure_ascii=False).replace('<', '\\u003c')
        portable = portable.replace('</body>', '<script type="application/json" id="embedded-report">' + embedded + '</script><script>' + (web / 'app.js').read_text() + '</script></body>')
        (output / 'dashboard.html').write_text(portable)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='.')
    parser.add_argument('--revision', default='WORKTREE')
    parser.add_argument('--output', default='output/tip-dashboard')
    parser.add_argument('--evidence')
    parser.add_argument('--github', action='store_true', help='Read PR states and GitHub authors/contributors/reviews (read-only).')
    parser.add_argument('--compare-main', metavar='REVISION', help='Independently inspect a main revision, e.g. origin/main.')
    parser.add_argument('--main-repo', help='Separate main checkout; defaults to --repo.')
    parser.add_argument('--main-evidence', help='Evidence collected at the main commit; never reuses candidate evidence.')
    args = parser.parse_args()
    failed = False
    baseline = None
    people_cache = {}
    try:
        report = build_report(args.repo, args.revision, args.evidence, args.github)
        if args.github:
            enrich_people(report, people_cache)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as exc:
        report = error_report(args.revision, exc)
        failed = True
    if args.compare_main:
        try:
            baseline = build_report(args.main_repo or args.repo, args.compare_main, args.main_evidence, args.github)
            if args.github:
                enrich_people(baseline, people_cache)
        except (OSError, subprocess.SubprocessError, ValueError, TypeError) as exc:
            baseline = error_report(args.compare_main, exc)
        compare_reports(report, baseline, args.compare_main)
    write_outputs(report, args.output)
    if baseline is not None:
        write_outputs(baseline, Path(args.output) / 'main')
        entries = []
        for label, value, location in [('Inspected revision', report, 'report.json'), ('main', baseline, 'main/report.json')]:
            if not failed and value.get('revision', {}).get('sha'):
                entries.append(dict(label=label, url=location, sha=value['revision']['sha']))
        (Path(args.output) / 'index.json').write_text(json.dumps({'reports': entries}, indent=2) + '\n')
    else:
        (Path(args.output) / 'index.json').unlink(missing_ok=True)
    summary = report['summary']
    print(json.dumps(summary, sort_keys=True))
    if os.environ.get('GITHUB_ACTIONS') and (failed or summary['warnings']):
        print('::warning::TIP implementation evidence is incomplete; inspect the dashboard artifact and job summary.')
    if failed:
        parser.exit(2, 'Collection failed; explicit error report and summary written.\n')


if __name__ == '__main__':
    main()
