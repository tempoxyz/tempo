"""Bounded, read-only GitHub attribution. API observations are not code approval.

Only file history is revision-bound; PR metadata is observed live. No emails,
requested reviewers, credentials, or persistent cache are collected.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import json
import re
import subprocess

REPOSITORY = 'tempoxyz/tempo'
MAX_PAGES = 3
WORKERS = 6
PR_URL = re.compile(r'https://github\.com/([\w.-]+/[\w.-]+)/pull/(\d+)(?:\b|/)')
ACTOR = 'login url __typename ... on User { name }'
SIGNATURE = 'name user { login name url __typename }'
COMMIT = 'oid url author { ' + SIGNATURE + ' } committer { ' + SIGNATURE + ' }'
PAGE = 'pageInfo { hasNextPage endCursor }'


def _graphql(query, variables):
    result = subprocess.run(['gh', 'api', 'graphql', '--input', '-'],
                            input=json.dumps(dict(query=query, variables=variables)),
                            text=True, capture_output=True, timeout=35, check=True)
    payload = json.loads(result.stdout)
    if payload.get('errors') or not isinstance(payload.get('data'), dict):
        raise ValueError('GitHub returned an incomplete GraphQL response')
    return payload['data']


def _actor(actor):
    actor = actor or {}
    return dict(login=actor.get('login'), name=actor.get('name'), url=actor.get('url'),
                account_type=actor.get('__typename'))


def _contributors(commits):
    people = {}
    for commit in commits:
        if not commit:
            continue
        for role in ('author', 'committer'):
            signature = commit.get(role) or {}
            person = _actor(signature.get('user'))
            if not person['login']:
                person['name'] = signature.get('name')
            # Unmapped Git names are deliberately distinct from GitHub identities.
            key = ('github', person['login']) if person['login'] else ('git-signature', commit.get('oid'), role)
            row = people.setdefault(key, dict(person, roles=[], commits=[]))
            if role not in row['roles']:
                row['roles'].append(role)
            evidence = dict(sha=commit.get('oid'), url=commit.get('url'))
            if evidence not in row['commits']:
                row['commits'].append(evidence)
    return list(people.values())


def _status(warnings, success):
    return ('partial' if success else 'unavailable') if warnings else 'complete'


def _history(sha, path):
    commits, links, warnings = [], set(), []
    cursor, success = None, False
    query = '''query($owner:String!,$repo:String!,$sha:String!,$path:String!,$cursor:String) {
      repository(owner:$owner,name:$repo) { object(expression:$sha) { ... on Commit {
        history(path:$path,first:30,after:$cursor) { nodes { ''' + COMMIT + '''
          associatedPullRequests(first:10) { nodes { number url } ''' + PAGE + ''' }
        } ''' + PAGE + ''' }
      } } }
    }'''
    for page in range(MAX_PAGES):
        try:
            data = _graphql(query, dict(owner='tempoxyz', repo='tempo', sha=sha, path=path, cursor=cursor))
            connection = data['repository']['object']['history']
            nodes = connection['nodes']
            info = connection['pageInfo']
            commits.extend(nodes)
            success = True
            for node in nodes:
                association = node['associatedPullRequests']
                for pr in association['nodes']:
                    match = PR_URL.fullmatch(pr['url'])
                    if match:
                        links.add((match[1], int(match[2])))
                if association['pageInfo']['hasNextPage']:
                    warnings.append('Associated PRs truncated at 10 for commit ' + node['oid'])
            if not info['hasNextPage']:
                break
            if page == MAX_PAGES - 1 or not info.get('endCursor') or info['endCursor'] == cursor:
                warnings.append('Specification file history truncated after bounded pagination')
                break
            cursor = info['endCursor']
        except (AttributeError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
            warnings.append('Specification file history could not be fully collected from GitHub')
            break
    return dict(commits=commits, links=links, warnings=warnings, status=_status(warnings, success))


def _pr(key):
    repository, number = key
    owner, repo = repository.split('/')
    url = f'https://github.com/{repository}/pull/{number}'
    result = dict(number=number, url=url, title=None, author=_actor(None), state=None,
                  head_sha=None, review_decision=None, reviews=[], contributors=[],
                  observed_at=datetime.now(timezone.utc).isoformat(), status='unavailable', warnings=[])
    commits = []
    variables = dict(owner=owner, repo=repo, number=number)
    metadata = '''query($owner:String!,$repo:String!,$number:Int!) {
      repository(owner:$owner,name:$repo) { pullRequest(number:$number) {
        number url title author { ''' + ACTOR + ''' } state headRefOid reviewDecision
      } }
    }'''
    try:
        pr = _graphql(metadata, variables)['repository']['pullRequest']
        result.update(title=pr['title'], author=_actor(pr.get('author')), state=pr['state'],
                      head_sha=pr['headRefOid'], review_decision=pr.get('reviewDecision'))
    except (AttributeError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        result['warnings'].append('PR metadata unavailable from GitHub')
        return result, commits
    for kind, fields in (
        ('reviews', 'author { ' + ACTOR + ' } state submittedAt url commit { oid }'),
        ('commits', 'commit { ' + COMMIT + ' }'),
    ):
        query = '''query($owner:String!,$repo:String!,$number:Int!,$cursor:String) {
          repository(owner:$owner,name:$repo) { pullRequest(number:$number) { ''' + kind + '''(first:100,after:$cursor) {
            nodes { ''' + fields + ' } ' + PAGE + ' } } } }'
        cursor = None
        seen = set()
        for page in range(MAX_PAGES):
            try:
                pr = _graphql(query, dict(variables, cursor=cursor))['repository']['pullRequest']
                connection = pr[kind]
                info = connection['pageInfo']
                for node in connection['nodes']:
                    if kind == 'commits':
                        commits.append(node['commit'])
                    elif node.get('submittedAt') and node.get('state') in {
                        'APPROVED', 'CHANGES_REQUESTED', 'COMMENTED', 'DISMISSED'
                    }:
                        identity = (node.get('url'), node.get('submittedAt'))
                        if identity in seen:
                            continue
                        seen.add(identity)
                        commit_sha = (node.get('commit') or {}).get('oid')
                        result['reviews'].append(dict(
                            author=_actor(node.get('author')), state=node['state'],
                            submitted_at=node['submittedAt'], commit_sha=commit_sha,
                            url=node.get('url'), on_current_head=(commit_sha == result['head_sha'])
                            if commit_sha and result['head_sha'] else None))
                if not info['hasNextPage']:
                    break
                if page == MAX_PAGES - 1 or not info.get('endCursor') or info['endCursor'] == cursor:
                    result['warnings'].append(f'PR {kind} truncated after bounded pagination')
                    break
                cursor = info['endCursor']
            except (AttributeError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
                result['warnings'].append(f'PR {kind} could not be fully collected from GitHub')
                break
    result['contributors'] = _contributors(commits)
    result['status'] = _status(result['warnings'], True)
    return result, commits


def collect_people(sha, tips, cache=None):
    """Mutate TIP people records; six concurrent reads and a per-call PR cache.

    sha must be the full selected commit SHA, never HEAD or a mutable branch.
    Declared frontmatter authors remain separate, unverified report data.
    Pass one empty dict as cache across sequential candidate/main collections
    to reuse live PR observations, including failures, within a report run.
    History is always collected independently at each selected SHA.
    """
    if not re.fullmatch(r'[0-9a-fA-F]{40}', sha):
        raise ValueError('GitHub people history requires a full selected commit SHA')
    if cache is None:
        cache = {}
    observed = datetime.now(timezone.utc).isoformat()
    paths = sorted({tip['spec']['path'] for tip in tips})
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        histories = dict(zip(paths, pool.map(lambda path: _history(sha, path), paths)))
        implementation = []
        keys = set().union(*(history['links'] for history in histories.values()))
        for tip in tips:
            links, warnings = set(), []
            for pr in tip.get('implementation_prs', []):
                value = pr.get('url', '') if isinstance(pr, dict) else pr
                match = PR_URL.fullmatch(value or '')
                if match:
                    links.add((match[1], int(match[2])))
                else:
                    warnings.append('Implementation PR URL could not be resolved')
            implementation.append((links, warnings))
            keys.update(links)
        ordered = sorted(keys - cache.keys())
        cache.update(zip(ordered, pool.map(_pr, ordered)))
    for tip, (impl_links, impl_warnings) in zip(tips, implementation):
        history = histories[tip['spec']['path']]
        groups = {}
        warnings = []
        for name, links, commits, initial_warnings, success in (
            ('spec', history['links'], history['commits'], history['warnings'], history['status'] != 'unavailable'),
            ('implementation', impl_links, [], impl_warnings, not impl_links and not impl_warnings),
        ):
            group_warnings = list(initial_warnings)
            all_commits = list(commits)
            prs = []
            for key in sorted(links):
                pr, pr_commits = cache[key]
                prs.append(deepcopy(pr))
                # PR history is live and may include other files or later commits.
                # Only implementation attribution intentionally has PR-wide scope.
                if name == 'implementation':
                    all_commits.extend(pr_commits)
                success = success or pr['status'] != 'unavailable'
                group_warnings.extend(f"PR #{pr['number']}: {w}" for w in pr['warnings'])
            groups[name] = dict(status=_status(group_warnings, success),
                                contributors=_contributors(all_commits), pull_requests=prs)
            warnings.extend(f'{name}: {w}' for w in dict.fromkeys(group_warnings))
        observed_any = history['status'] != 'unavailable' or any(
            cache[key][0]['status'] != 'unavailable' for key in history['links'] | impl_links)
        tip['people'] = dict(status=_status(warnings, observed_any),
                             observed_at=observed, revision=sha, warnings=warnings, **groups)
