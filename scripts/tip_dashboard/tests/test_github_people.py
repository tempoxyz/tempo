import sys
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import github_people as gp

SHA = 'a' * 40
USER = {'login': 'tempoxyz-bot', 'name': 'Automation', 'url': 'https://github.com/tempoxyz-bot', '__typename': 'User'}


def commit(oid='c', user=USER, name='Raw Git Author'):
    return dict(oid=oid, url='https://github.com/tempoxyz/tempo/commit/' + oid,
                author=dict(name=name, user=user), committer=dict(name=name, user=user))


def connection(nodes, more=False, cursor='next'):
    return dict(nodes=nodes, pageInfo=dict(hasNextPage=more, endCursor=cursor))


def pr_data(value):
    return {'repository': {'pullRequest': value}}


def review(state='APPROVED', oid='head', submitted='2026-10-08', actor=USER):
    return dict(author=actor, state=state, submittedAt=submitted,
                url=f'https://github.com/tempoxyz/tempo/pull/7935#review-{state}-{oid}', commit={'oid': oid})


class PeopleTests(unittest.TestCase):
    def test_identity_roles_and_commit_dedup_no_human_inference(self):
        rows = gp._contributors([commit(), commit(), commit('d'), commit('e', None), commit('f', None, 'tempoxyz-bot')])
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]['roles'], ['author', 'committer'])
        self.assertEqual(len(rows[0]['commits']), 2)
        self.assertEqual(rows[0]['account_type'], 'User')
        self.assertNotIn('human', str(rows))
        self.assertIsNone(rows[1]['login'])
        self.assertEqual(rows[1]['name'], 'Raw Git Author')
        self.assertIsNone(rows[2]['login'])
        self.assertNotIn('email', str(rows))

    def test_unmapped_names_do_not_establish_shared_identity(self):
        rows = gp._contributors([commit('a', None, 'Alex'), commit('b', None, 'Alex')])
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(len(row['roles']) == 1 and len(row['commits']) == 1 for row in rows))
        self.assertTrue(all(row['login'] is None for row in rows))

    def test_review_with_missing_commit_has_unknown_head_context(self):
        missing = review()
        missing['commit'] = None
        def api(query, variables):
            if 'reviews(' in query:
                return pr_data({'reviews': connection([missing])})
            if 'commits(' in query:
                return pr_data({'commits': connection([])})
            return pr_data(dict(title='Implementation', author=USER, state='OPEN', headRefOid='head'))
        with patch.object(gp, '_graphql', api):
            result, _ = gp._pr(('tempoxyz/tempo', 7935))
        self.assertIsNone(result['reviews'][0]['commit_sha'])
        self.assertIsNone(result['reviews'][0]['on_current_head'])

    def test_history_selected_sha_pagination_association_limit(self):
        calls = []
        def api(query, variables):
            calls.append(variables)
            node = commit(str(len(calls)))
            node['associatedPullRequests'] = connection([{'number': 7881, 'url': 'https://github.com/tempoxyz/tempo/pull/7881'}], more=True)
            return {'repository': {'object': {'history': connection([node], more=len(calls) == 1)}}}
        with patch.object(gp, '_graphql', api):
            result = gp._history(SHA, 'tips/tip-1006.md')
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(c['sha'] == SHA and c['path'] == 'tips/tip-1006.md' for c in calls))
        self.assertEqual(calls[1]['cursor'], 'next')
        self.assertEqual(result['links'], {('tempoxyz/tempo', 7881)})
        self.assertEqual(result['status'], 'partial')

    def test_history_later_failure_retains_evidence(self):
        node = commit()
        node['associatedPullRequests'] = connection([])
        with patch.object(gp, '_graphql', side_effect=[{'repository': {'object': {'history': connection([node], True)}}}, ValueError('error')]):
            result = gp._history(SHA, 'tips/tip-1006.md')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['commits']), 1)
        with patch.object(gp, '_graphql', side_effect=OSError('offline')):
            self.assertEqual(gp._history(SHA, 'tips/tip-1006.md')['status'], 'unavailable')

    def test_reviews_paginate_deleted_bots_stale_dismissed_pending(self):
        calls = {'reviews': 0, 'commits': 0}
        def api(query, variables):
            if 'reviews(' in query:
                calls['reviews'] += 1
                if calls['reviews'] == 1:
                    return pr_data({'reviews': connection([review(), review('APPROVED', 'old'), review('DISMISSED'), review('PENDING'), review('COMMENTED', submitted=None)], True)})
                return pr_data({'reviews': connection([review(), review('COMMENTED', actor=None), review('CHANGES_REQUESTED', actor=dict(USER, __typename='Bot'))])})
            if 'commits(' in query:
                calls['commits'] += 1
                return pr_data({'commits': connection([{'commit': commit()}], calls['commits'] == 1)})
            return pr_data(dict(title='Implementation', author=None, state='MERGED', headRefOid='head', reviewDecision='APPROVED'))
        with patch.object(gp, '_graphql', api):
            result, commits = gp._pr(('tempoxyz/tempo', 7935))
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['contributors'], gp._contributors(commits))
        self.assertTrue(result['observed_at'])
        self.assertEqual(len(result['reviews']), 5)
        self.assertFalse(result['reviews'][1]['on_current_head'])
        self.assertEqual(result['reviews'][2]['state'], 'DISMISSED')
        self.assertIsNone(result['reviews'][3]['author']['login'])
        self.assertEqual(result['reviews'][4]['author']['account_type'], 'Bot')
        self.assertIsNone(result['author']['login'])
        self.assertEqual(calls, {'reviews': 2, 'commits': 2})
        self.assertEqual(len(gp._contributors(commits)[0]['commits']), 1)

    def test_pr_failure_and_bounds(self):
        with patch.object(gp, '_graphql', side_effect=ValueError('API error')):
            result, _ = gp._pr(('tempoxyz/tempo', 7935))
        self.assertEqual(result['status'], 'unavailable')
        def api(query, variables):
            if 'reviews(' in query:
                return pr_data({'reviews': connection([review()], True, (variables['cursor'] or '') + 'x')})
            if 'commits(' in query:
                raise subprocess.TimeoutExpired('gh', 35)
            return pr_data(dict(title='x', author=USER, state='OPEN', headRefOid='head'))
        with patch.object(gp, '_graphql', api) as _:
            result, _ = gp._pr(('tempoxyz/tempo', 7935))
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['warnings']), 2)
        self.assertEqual(len(result['reviews']), 1)

    def test_shared_run_cache_and_invalid_url(self):
        tips = [dict(spec={'path': 'tips/tip-1006.md'}, implementation_prs=[{'url': 'https://github.com/tempoxyz/tempo/pull/7935'}], declared_authors=['Not verified']) for _ in range(2)]
        history = dict(commits=[commit()], links={('tempoxyz/tempo', 7935)}, warnings=[], status='complete')
        pr = dict(number=7935, status='complete', warnings=[], reviews=[])
        with patch.object(gp, '_history', return_value=history) as histories, patch.object(gp, '_pr', return_value=(pr, [commit()])) as prs:
            gp.collect_people(SHA, tips)
        self.assertEqual(histories.call_count, 1)
        self.assertEqual(prs.call_count, 1)
        self.assertEqual(tips[0]['people']['revision'], SHA)
        self.assertEqual(tips[0]['people']['status'], 'complete')
        self.assertEqual(len(tips[0]['people']['spec']['contributors']), 1)
        tips[0]['people']['spec']['pull_requests'][0]['warnings'].append('local')
        self.assertEqual(tips[1]['people']['spec']['pull_requests'][0]['warnings'], [])
        tips[0]['implementation_prs'] = [{'url': 'invalid'}]
        with patch.object(gp, '_history', return_value=history), patch.object(gp, '_pr', return_value=(pr, [])):
            gp.collect_people(SHA, tips[:1])
        self.assertEqual(tips[0]['people']['implementation']['status'], 'unavailable')
        self.assertEqual(tips[0]['people']['status'], 'partial')
        with self.assertRaises(ValueError):
            gp.collect_people('HEAD', tips)

    def test_spec_contributors_exclude_unrelated_and_future_pr_commits(self):
        tips = [dict(spec={'path': 'tips/tip-1006.md'}, implementation_prs=[{'url': 'https://github.com/tempoxyz/tempo/pull/7935'}])]
        history = dict(commits=[commit('selected-file-commit')], links={('tempoxyz/tempo', 7935)}, warnings=[], status='complete')
        future_actor = dict(USER, login='future-pr-author')
        unrelated_actor = dict(USER, login='other-file-author')
        pr_commits = [commit('future-head', future_actor), commit('unrelated-file', unrelated_actor)]
        pr = dict(number=7935, status='complete', warnings=[], reviews=[], author=future_actor,
                  contributors=gp._contributors(pr_commits), observed_at='2026-10-08T12:00:00Z')
        with patch.object(gp, '_history', return_value=history), patch.object(gp, '_pr', return_value=(pr, pr_commits)):
            gp.collect_people(SHA, tips)
        people = tips[0]['people']
        self.assertEqual([p['login'] for p in people['spec']['contributors']], ['tempoxyz-bot'])
        self.assertEqual(people['spec']['contributors'][0]['commits'][0]['sha'], 'selected-file-commit')
        self.assertEqual([p['login'] for p in people['implementation']['contributors']], ['future-pr-author', 'other-file-author'])
        self.assertEqual(people['spec']['pull_requests'][0]['author']['login'], 'future-pr-author')
        self.assertEqual(people['spec']['pull_requests'][0]['contributors'], gp._contributors(pr_commits))
        self.assertEqual(people['spec']['pull_requests'][0]['observed_at'], '2026-10-08T12:00:00Z')

    def test_shared_cache_across_selected_revisions(self):
        tips = [dict(spec={'path': 'tips/tip-1006.md'}, implementation_prs=[{'url': 'https://github.com/tempoxyz/tempo/pull/7935'}])]
        history = dict(commits=[], links=set(), warnings=[], status='complete')
        pr = dict(number=7935, status='unavailable', warnings=['API unavailable'], reviews=[])
        cache = {}
        with patch.object(gp, '_history', return_value=history) as histories, patch.object(gp, '_pr', return_value=(pr, [])) as prs:
            gp.collect_people(SHA, tips, cache=cache)
            gp.collect_people('b' * 40, tips, cache=cache)
        self.assertEqual(prs.call_count, 1)
        self.assertEqual(histories.call_count, 2)
        self.assertEqual(histories.call_args_list[0].args[0], SHA)
        self.assertEqual(histories.call_args_list[1].args[0], 'b' * 40)
        self.assertEqual(tips[0]['people']['revision'], 'b' * 40)
        self.assertEqual(tips[0]['people']['implementation']['status'], 'unavailable')
        self.assertEqual(tips[0]['people']['status'], 'partial')
        self.assertTrue(cache)

    def test_malformed_api_response_does_not_escape(self):
        with patch.object(gp.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '[]')):
            tips = [dict(spec={'path': 'tips/tip-1006.md'}, implementation_prs=[])]
            gp.collect_people(SHA, tips)
        self.assertEqual(tips[0]['people']['status'], 'unavailable')

    def test_total_failure_is_unavailable_even_without_implementation_links(self):
        tips = [dict(spec={'path': 'tips/tip-1006.md'}, implementation_prs=[])]
        with patch.object(gp, '_graphql', side_effect=OSError('offline')):
            gp.collect_people(SHA, tips)
        self.assertEqual(tips[0]['people']['status'], 'unavailable')
        self.assertEqual(tips[0]['people']['spec']['status'], 'unavailable')
        self.assertTrue(tips[0]['people']['warnings'])

    def test_history_page_bound(self):
        def api(query, variables):
            node = commit()
            node['associatedPullRequests'] = connection([])
            return {'repository': {'object': {'history': connection([node], True, (variables['cursor'] or '') + 'x')}}}
        with patch.object(gp, '_graphql', side_effect=api) as api_mock:
            result = gp._history(SHA, 'tips/tip-1006.md')
        self.assertEqual(api_mock.call_count, 3)
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(any('truncated' in warning for warning in result['warnings']))

    def test_graphql_uses_stdin_and_rejects_errors(self):
        with patch.object(gp.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"data": {}, "errors": [{"message": "failure"}]}')) as run:
            with self.assertRaises(ValueError):
                gp._graphql('query', {'sha': SHA})
        self.assertEqual(run.call_args.args[0], ['gh', 'api', 'graphql', '--input', '-'])
        self.assertIn(SHA, run.call_args.kwargs['input'])


if __name__ == '__main__':
    unittest.main()
