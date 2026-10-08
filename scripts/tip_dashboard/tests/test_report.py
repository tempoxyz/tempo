"""Adversarial scanner tests: require provenance, review, and real case coverage."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('tip_report', Path(__file__).parents[1] / 'report.py')
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.run_git('init', '-q')
        self.run_git('config', 'user.email', 'test@example.invalid')
        self.run_git('config', 'user.name', 'Test')
        self.run_git('config', 'commit.gpgsign', 'false')
        self.run_git('config', 'core.hooksPath', '/dev/null')
        self.write('tips/tip-1116.md', '''---
id: TIP-1116
title: Test proposal
status: Draft
protocolVersion: T12
implementation: https://github.com/other-owner/other-repo/pull/27
---
<!-- @requirement TIP-1116:R1 kind=activation cases=before,at,after -->
The behavior MUST activate at T12.

[PR](https://github.com/other-owner/other-repo/pull/27)
''')
        self.write('src/lib.rs', '''// @implements TIP-1116:R1 gate=spec.is_t12()
if spec.is_t12() { execute(); }
// @asserts TIP-1116:R1 case=before test=boundary fork=T11
assert_eq!(before, false);
// @asserts TIP-1116:R1 case=at test=boundary fork=T12
assert_eq!(at, true);
// @asserts TIP-1116:R1 case=after test=boundary fork=T13
assert_eq!(after, true);
''')
        self.write('tips/verify/foundry.toml', '[profile.default]\nhardfork="tempo:T12"\n[profile.next]\nhardfork="tempo:T13"\n')
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'fixture')

    def run_git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.PIPE)

    def write(self, name, content):
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def build(self, **kw):
        return report.build_report(self.repo, **kw)

    def req(self, result=None):
        return (result or self.build())['tips'][0]['requirements'][0]

    def review(self):
        result = self.build()
        r = self.req(result)
        data = {'schema_version': 1, 'inventories': [{'tip': 'TIP-1116', 'spec_digest': r['spec_digest'], 'reviewer': 'fixture-agent', 'reviewer_kind': 'agent', 'source': 'review:fixture'}],
                'requirements': [dict({k: r[k] for k in ('id', 'spec_digest', 'source_digest', 'test_digest')}, reviewer='fixture-agent', reviewer_kind='agent', source='review:fixture')]}
        self.write('tips/verification/reviews.json', json.dumps(data))
        return data

    def envelope(self):
        self.review()
        return dict(schema_version=1, **report.evidence_context(self.repo), runner={'name': 'pilot', 'version': '1'}, provenance={'kind': 'local', 'run_url': None},
                    attempts=[{'id': 'attempt-1', 'test': 'boundary', 'outcome': 'passed', 'exit_code': 0, 'timed_out': False,
                               'markers': [{'requirement': 'TIP-1116:R1', 'case': case, 'test': 'boundary', 'fork': fork} for case, fork in [('before', 'T11'), ('at', 'T12'), ('after', 'T13')]]}])

    def test_unavailable_main_does_not_mask_candidate_failure(self):
        candidate = report.error_report('candidate', ValueError('candidate unavailable'))
        main = report.error_report('main', ValueError('main unavailable'))
        report.compare_reports(candidate, main, 'main')
        self.assertEqual(candidate['collection']['status'], 'error')
        self.assertEqual(candidate['main_comparison']['status'], 'unavailable')
        self.assertEqual(candidate['summary']['verified'], 0)

    def test_inventory_is_schedule_based_not_highest_number(self):
        self.write('tips/tip-9999.md', '---\nid: TIP-9999\nprotocolVersion: T99\n---\nFuture prose\n')
        result = self.build()
        self.assertEqual(result['next_fork'], 'T13')
        self.assertEqual(len(result['tips']), 2)
        self.assertEqual(result['tips'][1]['inventory']['status'], 'incomplete')

    def test_one_case_cannot_stand_for_multiple_forks(self):
        p = self.repo / 'src/lib.rs'
        p.write_text(p.read_text().replace('case=after', 'case=at'))
        r = self.req(self.build(evidence=self.envelope()))
        self.assertIn('ambiguous_case_fork', [w['code'] for w in r['warnings']])
        self.assertNotEqual(r['verification_status'], 'verified')

    def test_source_review_does_not_require_execution_or_assertion_links(self):
        p = self.repo / 'src/lib.rs'
        p.write_text('// @implements TIP-1116:R1 gate=spec.is_t12()\nif spec.is_t12() { execute(); }\n')
        self.review()
        r = self.req()
        self.assertEqual(r['implementation_status'], 'reviewed')
        self.assertEqual(r['verification_status'], 'not_run')
        self.assertEqual(r['assertion_coverage']['linked'], 0)
        self.assertEqual(len(r['missing_assertions']), 3)

    def test_dispatch_schedule_attribute_links_the_actual_activation(self):
        p = self.repo / 'src/lib.rs'
        p.write_text(p.read_text().replace('gate=spec.is_t12()\nif spec.is_t12() { execute(); }',
                                          'gate=schedule(since=T12)\n#[schedule(since = T12)]\nBurnCall => mutate(call),'))
        r = self.req(self.build(evidence=self.envelope()))
        self.assertEqual(r['implementations'][0]['fork'], 'T12')
        self.assertEqual(r['verification_status'], 'verified')
        self.assertEqual(r['warnings'], [])

    def test_dispatch_schedule_wrong_or_unsupported_attribute_never_verifies(self):
        for expression in ['#[schedule(since = T13)]', '#[schedule(since = T12, until = T13)]',
                           '// #[schedule(since = T12)]', 'let text = "#[schedule(since = T12)]";',
                           'schedule(since=T12);', '#[unrelated(since = T12)]']:
            with self.subTest(expression=expression):
                self.write('src/lib.rs', '// @implements TIP-1116:R1 gate=schedule(since=T12)\n' + expression + '\nBurnCall => mutate(call),\n')
                self.review()
                r = self.req()
                self.assertIn('gate_mismatch', [w['code'] for w in r['warnings']])
                self.assertEqual(r['implementation_status'], 'linked')

    def test_dispatch_schedule_cannot_be_labelled_always(self):
        self.write('src/lib.rs', '// @implements TIP-1116:R1 gate=always\n#[schedule(since = T12)]\nBurnCall => mutate(call),\n')
        self.assertIn('invalid_gate', [w['code'] for w in self.req()['warnings']])

    def test_main_comparison_does_not_reuse_candidate_evidence(self):
        candidate = self.build(evidence=self.envelope())
        baseline = self.build(revision='HEAD')
        report.compare_reports(candidate, baseline, 'main')
        self.assertEqual(candidate['tips'][0]['coverage']['verified'], 1)
        self.assertEqual(candidate['tips'][0]['main_comparison']['coverage']['verified'], 0)
        self.assertEqual(candidate['tips'][0]['main_comparison']['inventory']['status'], 'incomplete')
        self.assertEqual(candidate['main_comparison']['revision']['sha'], baseline['revision']['sha'])

    def test_main_comparison_missing_tip_and_unavailable_are_distinct(self):
        candidate, baseline = self.build(), self.build()
        baseline['tips'] = []
        report.compare_reports(candidate, baseline, 'main')
        self.assertEqual(candidate['tips'][0]['main_comparison']['status'], 'absent')
        report.compare_reports(candidate, report.error_report('main', ValueError('missing ref')), 'main')
        self.assertEqual(candidate['tips'][0]['main_comparison']['status'], 'unavailable')
        self.assertNotIn('coverage', candidate['tips'][0]['main_comparison'])
        self.assertIn('main_unavailable', [w['code'] for w in candidate['collection']['warnings']])

    def test_main_spec_changes_and_main_only_tips_remain_visible(self):
        baseline = self.build()
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text() + '\nA new revision.\n')
        candidate = self.build()
        baseline['tips'].append(dict(baseline['tips'][0], id='TIP-9999'))
        report.compare_reports(candidate, baseline, 'main')
        self.assertTrue(candidate['tips'][0]['main_comparison']['spec_changed'])
        self.assertEqual(candidate['main_comparison']['only_on_main'], ['TIP-9999'])
        summary = report.markdown_summary(candidate)
        self.assertIn('Main comparison: available', summary)
        self.assertIn('Main: present', summary)

    def test_annotations_are_never_review_or_execution(self):
        r = self.req()
        self.assertEqual(r['implementation_status'], 'linked')
        self.assertEqual(r['verification_status'], 'not_run')
        self.assertEqual(self.build()['summary']['verified'], 0)

    def test_complete_reviewed_same_context_evidence_verifies(self):
        r = self.req(self.build(evidence=self.envelope()))
        self.assertEqual(r['implementation_status'], 'reviewed')
        self.assertEqual(r['verification_status'], 'verified')
        self.assertEqual(len(r['evidence']), 3)

    def test_unreviewed_execution_is_partial(self):
        envelope = self.envelope()
        (self.repo / 'tips/verification/reviews.json').unlink()
        envelope.update(report.evidence_context(self.repo))
        self.assertEqual(self.req(self.build(evidence=envelope))['verification_status'], 'partial')

    def test_unreviewed_inventory_is_partial(self):
        self.envelope()
        p = self.repo / 'tips/verification/reviews.json'
        data = json.loads(p.read_text())
        data['inventories'] = []
        p.write_text(json.dumps(data))
        envelope = dict(schema_version=1, **report.evidence_context(self.repo), runner={'name': 'pilot', 'version': '1'}, provenance={'kind': 'local'}, attempts=[])
        envelope['attempts'] = [{'id': '1', 'test': 'boundary', 'outcome': 'passed', 'exit_code': 0, 'timed_out': False, 'markers': [{'requirement': 'TIP-1116:R1', 'case': c, 'test': 'boundary', 'fork': 'T12'} for c in ['before', 'at', 'after']]}]
        self.assertEqual(self.req(self.build(evidence=envelope))['verification_status'], 'partial')

    def test_failure_after_markers_overrides_all_passes(self):
        e = self.envelope()
        e['attempts'][0].update(outcome='failed', exit_code=1)
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'failed')
        later = copy.deepcopy(e['attempts'][0])
        later.update(id='2', outcome='passed', exit_code=0)
        e['attempts'].append(later)
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'failed')

    def test_failed_attempt_without_marker_still_fails(self):
        e = self.envelope()
        e['attempts'][0].update(outcome='failed', exit_code=1, markers=[])
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'failed')

    def test_missing_cases_are_partial_and_missing_markers_not_run(self):
        e = self.envelope()
        e['attempts'][0]['markers'].pop()
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'partial')
        e['attempts'][0]['markers'] = []
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'unexercised')

    def test_skipped_has_no_passing_coverage(self):
        e = self.envelope()
        e['attempts'][0].update(outcome='skipped', markers=[])
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'skipped')

    def test_contradictory_exit_or_timeout_is_unknown(self):
        for change in [{'exit_code': 1}, {'timed_out': True}, {'exit_code': False}]:
            with self.subTest(change=change):
                e = self.envelope()
                e['attempts'][0].update(change)
                self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'unknown')

    def test_context_tampering_always_stale(self):
        e = self.envelope()
        for key in ['identity', 'manifest_digest', 'checks_digest', 'tool_digest']:
            with self.subTest(key=key):
                bad = copy.deepcopy(e)
                bad[key] = 'wrong'
                self.assertEqual(self.req(self.build(evidence=bad))['verification_status'], 'stale')

    def test_malformed_envelopes_never_raise_or_pass(self):
        for e in [[], 12, 'missing.json', {'schema_version': 99}]:
            with self.subTest(e=e):
                self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'unknown')
        e = self.envelope()
        for field, value in [('attempts', [None]), ('attempts', {}), ('runner', []), ('provenance', None)]:
            bad = copy.deepcopy(e)
            bad[field] = value
            self.assertEqual(self.req(self.build(evidence=bad))['verification_status'], 'unknown')

    def test_duplicate_attempt_and_mismatched_test_rejected(self):
        e = self.envelope()
        e['attempts'].append(copy.deepcopy(e['attempts'][0]))
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'unknown')
        e['attempts'].pop()
        e['attempts'][0]['markers'][0]['test'] = 'other_test'
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'unknown')

    def test_undeclared_case_does_not_count(self):
        e = self.envelope()
        e['attempts'][0]['markers'][0]['case'] = 'invented'
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'partial')

    def test_unrelated_source_change_stales_evidence(self):
        e = self.envelope()
        self.write('src/unrelated.rs', 'fn protocol_change() {}')
        self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'stale')

    def test_source_change_outside_label_invalidates_review(self):
        self.review()
        p = self.repo / 'src/lib.rs'
        p.write_text(p.read_text() + '\nfn changed_helper() {}\n')
        self.assertEqual(self.req()['implementation_status'], 'linked')

    def test_spec_change_invalidates_review_and_inventory(self):
        self.review()
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text() + '\nAnother rule.\n')
        result = self.build()
        self.assertEqual(self.req(result)['implementation_status'], 'linked')
        self.assertEqual(result['tips'][0]['inventory']['status'], 'incomplete')

    def test_duplicate_reviews_do_not_review(self):
        data = self.review()
        data['requirements'].append(copy.deepcopy(data['requirements'][0]))
        self.write('tips/verification/reviews.json', json.dumps(data))
        self.assertEqual(self.req()['implementation_status'], 'linked')

    def test_blank_reviewer_does_not_review(self):
        data = self.review()
        data['requirements'][0]['reviewer'] = ' '
        self.write('tips/verification/reviews.json', json.dumps(data))
        self.assertEqual(self.req()['implementation_status'], 'linked')

    def test_duplicate_requirement_is_diagnostic(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text() + '\n<!-- @requirement TIP-1116:R1 kind=activation cases=x -->\nDuplicate.\n')
        result = self.build()
        self.assertTrue(any(w['code'] == 'duplicate_requirement' for w in self.req(result)['warnings']))
        self.assertTrue(any(w['code'] == 'unresolved_label' for w in result['collection']['warnings']))

    def test_nonassertion_annotation_never_reviewed(self):
        p = self.repo / 'src/lib.rs'
        p.write_text(p.read_text().replace('assert_eq!(at, true);', 'println!("not an assertion");'))
        self.review()
        self.assertEqual(self.req()['implementation_status'], 'linked')

    def test_selected_git_tree_ignores_worktree(self):
        before = self.build(revision='HEAD')
        self.write('src/lib.rs', '// changed\n')
        after = self.build(revision='HEAD')
        self.assertEqual(before['revision'], after['revision'])
        self.assertEqual(before['tips'], after['tips'])
        self.assertNotEqual(after['revision']['source_digest'], self.build()['revision']['source_digest'])
        self.assertEqual(after['revision']['dirty'], False)

    def test_invalid_revision_raises(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.build(revision='missing-ref')

    def test_dirty_source_has_no_wrong_commit_links(self):
        self.write('src/extra.rs', '// dirty')
        self.assertIsNone(self.req()['implementations'][0]['url'])

    def test_symlink_not_followed(self):
        (self.repo / 'src/external.rs').symlink_to('/etc/passwd')
        snap = report.Snapshot(self.repo)
        self.assertEqual(snap.files['src/external.rs'], b'/etc/passwd')
        self.assertEqual(snap.text('src/external.rs'), '')

    def test_github_owner_repo_comes_from_url(self):
        real = subprocess.check_output
        calls = []
        def fake(command, **kwargs):
            if command[0] == 'gh':
                calls.append(command)
                return b'{"state":"MERGED","isDraft":false,"mergeCommit":{"oid":"abc"}}'
            return real(command, **kwargs)
        with patch.object(subprocess, 'check_output', side_effect=fake):
            result = self.build(github=True)
        self.assertIn('other-owner/other-repo', calls[0])
        self.assertEqual(result['tips'][0]['merge_status'], 'merged')
        self.assertEqual(result['summary']['verified'], 0)

    def test_offline_default_does_not_call_gh(self):
        real = subprocess.check_output
        def fake(command, **kwargs):
            self.assertNotEqual(command[0], 'gh')
            return real(command, **kwargs)
        with patch.object(subprocess, 'check_output', side_effect=fake):
            self.assertEqual(self.build()['tips'][0]['merge_status'], 'unknown')


    def test_wrong_fork_does_not_verify(self):
        e = self.envelope()
        e['attempts'][0]['markers'][0]['fork'] = 'T13'
        r = self.req(self.build(evidence=e))
        self.assertEqual(r['verification_status'], 'partial')
        self.assertTrue(any(w['code'] == 'unmatched_marker' for w in r['warnings']))

    def test_declared_guard_must_match_adjacent_code(self):
        p = self.repo / 'src/lib.rs'
        p.write_text(p.read_text().replace('if spec.is_t12()', 'if spec.is_t13()'))
        self.review()
        r = self.req()
        self.assertEqual(r['implementation_status'], 'linked')
        self.assertEqual(r['implementations'][0]['fork'], 'T13')
        self.assertTrue(any(w['code'] == 'gate_mismatch' for w in r['warnings']))

    def test_collection_and_attempt_errors_invalidate_passed_markers(self):
        for where in ['envelope', 'attempt']:
            e = self.envelope()
            (e if where == 'envelope' else e['attempts'][0])['errors'] = ['collection failed']
            self.assertEqual(self.req(self.build(evidence=e))['verification_status'], 'unknown')

    def test_clean_head_and_worktree_are_same_evidence_identity(self):
        self.review()
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'reviews')
        e = self.envelope()
        result = self.build(revision='HEAD', evidence=e)
        self.assertFalse(e['identity']['dirty'])
        self.assertEqual(self.req(result)['verification_status'], 'verified')
        self.assertEqual(e['checks_digest'], result['evidence_context']['checks_digest'])

    def test_git_revert_does_not_inherit_merged_pr_coverage(self):
        self.review()
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'reviewed implementation')
        before = self.run_git('rev-parse', 'HEAD').decode().strip()
        self.write('src/lib.rs', '// implementation removed in this revision\n')
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'revert implementation')
        result = self.build(revision='HEAD')
        self.assertEqual(result['summary']['linked'], 0)
        self.assertEqual(result['summary']['verified'], 0)
        self.assertEqual(self.build(revision=before)['summary']['reviewed'], 1)

    def test_removed_assertion_leaves_visible_gap(self):
        e = self.envelope()
        p = self.repo / 'src/lib.rs'
        p.write_text(p.read_text().replace('// @asserts TIP-1116:R1 case=after test=boundary fork=T13', '// assertion label removed'))
        r = self.req(self.build(evidence=e))
        self.assertEqual(r['verification_status'], 'stale')
        self.assertEqual(r['missing_assertions'], ['after'])

    def test_supersession_keeps_old_rule_and_explicit_fork_scope(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text().replace('R1 kind=activation', 'R1 from=T12 until=T13 superseded_by=TIP-1116:E2 kind=activation') +
                     '\n<!-- @requirement TIP-1116:E2 from=T13 kind=validation cases=next -->\nReplacement rule.\n')
        r = self.req()
        self.assertEqual(r['applicability']['at_fork']['T12'], True)
        self.assertEqual(r['applicability']['at_fork']['T13'], False)
        self.assertEqual(r['applicability']['superseded_by'], 'TIP-1116:E2')
        self.assertEqual(len(self.build()['tips'][0]['requirements']), 2)

    def test_unscoped_rule_is_not_assumed_applicable_to_all_history(self):
        self.assertIsNone(self.req()['applicability']['at_fork']['T11'])

    def test_empty_reviewed_inventory_is_still_incomplete(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text('---\nid: TIP-1116\nprotocolVersion: T12\n---\nUninventoried prose.\n')
        data = {'schema_version': 1, 'inventories': [{'tip':'TIP-1116', 'spec_digest':report.file_digest(p.read_bytes()), 'reviewer':'fixture', 'reviewer_kind':'agent', 'source':'review:fixture'}]}
        self.write('tips/verification/reviews.json', json.dumps(data))
        result = self.build()
        self.assertEqual(result['tips'][0]['inventory']['status'], 'incomplete')
        self.assertEqual(result['summary']['verified'], 0)

    def test_unknown_schedule_is_not_a_fork_group(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text().replace('protocolVersion: T12', 'protocolVersion: TBD'))
        self.assertIsNone(self.build()['tips'][0]['scheduled_fork'])

    def test_inline_table_and_contiguous_list_keep_their_statements(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text() + '\n| E2 | Existing ID | Rule text. <!-- @requirement TIP-1116:E2 kind=validation cases=rule --> |\n'
                     '\n<!-- @requirement TIP-1116:E3 kind=validation cases=rule -->\n- First rule.\n'
                     '<!-- @requirement TIP-1116:E4 kind=validation cases=rule -->\n- Second rule.\n')
        r = self.build()['tips'][0]['requirements']
        self.assertIn('Rule text.', r[1]['statement'])
        self.assertEqual(r[2]['statement'], '- First rule.')
        self.assertEqual(r[3]['statement'], '- Second rule.')

    def test_prs_paragraph_is_supported_but_related_link_is_not_implementation(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text().replace('implementation: https://github.com/other-owner/other-repo/pull/27\n', '') +
                     '\n**PRs**: [#4](https://github.com/acme/node/pull/4),\n[#5](https://github.com/acme/node/pull/5)\n')
        prs = self.build()['tips'][0]['implementation_prs']
        self.assertEqual([p['number'] for p in prs], [4,5])
        self.assertTrue(all('/acme/node/' in p['url'] for p in prs))

    def test_agent_review_kind_is_visible_and_not_human(self):
        self.review()
        result = self.build()
        self.assertEqual(self.req(result)['review']['reviewer_kind'], 'agent')
        self.assertEqual(result['tips'][0]['inventory']['review']['reviewer_kind'], 'agent')

    def test_cli_failed_revision_replaces_previous_report(self):
        import sys
        out = self.repo / 'output/dashboard'
        out.mkdir(parents=True)
        (out/'report.json').write_text('{"stale_green":true}')
        result = subprocess.run([sys.executable, str(Path(report.__file__)), '--repo', str(self.repo), '--revision', 'missing-ref', '--output', str(out)], capture_output=True)
        self.assertEqual(result.returncode, 2)
        written = json.loads((out/'report.json').read_text())
        self.assertEqual(written['collection']['status'], 'error')
        self.assertEqual(written['tips'], [])
        self.assertNotIn('stale_green', written)

    def test_partial_merge_aggregate_does_not_imply_verified_code(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text() + '\n**PRs**: [#28](https://github.com/other-owner/other-repo/pull/28)\n')
        real = subprocess.check_output
        def fake(command, **kw):
            if command[0] == 'gh':
                state = 'MERGED' if command[3] == '27' else 'OPEN'
                return json.dumps({'state':state, 'isDraft':False, 'mergeCommit':None}).encode()
            return real(command, **kw)
        with patch.object(subprocess, 'check_output', side_effect=fake):
            result = self.build(github=True)
        self.assertEqual(result['tips'][0]['merge_status'], 'partially_merged')
        self.assertEqual(result['summary']['verified'], 0)

    def test_fenced_example_is_not_an_inventory_entry(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text() + '\n```markdown\n<!-- @requirement TIP-1116:E8 kind=validation cases=example -->\nNot a requirement.\n```\n')
        self.assertEqual(len(self.build()['tips'][0]['requirements']), 1)

    def test_conflicting_schedules_are_unknown(self):
        p = self.repo / 'tips/tip-1116.md'
        p.write_text(p.read_text().replace('protocolVersion: T12', 'protocolVersion: T12\nprotocolVersion: T13'))
        tip = self.build()['tips'][0]
        self.assertIsNone(tip['scheduled_fork'])
        self.assertTrue(any(w['code'] == 'conflicting_schedule' for w in tip['warnings']))

    def test_subfork_order_matches_repository_enum(self):
        self.assertEqual(report.canonical_fork('T1.A'), 'T1A')
        self.assertLess(report.fork_number('Genesis'), report.fork_number('T0'))
        self.assertLess(report.fork_number('T1'), report.fork_number('T1A'))
        self.assertLess(report.fork_number('T1C'), report.fork_number('T2'))

    def test_latest_view_comes_from_current_and_next_profiles(self):
        self.write('tips/verify/foundry.toml', '[profile.default]\nhardfork="tempo:T13"\n[profile.next]\nhardfork="tempo:T14"\n')
        result = self.build()
        self.assertEqual(result['current_fork'], 'T13')
        self.assertEqual(result['next_fork'], 'T14')
        self.assertEqual(result['latest_forks'], ['T14', 'T13', 'T12'])
        self.assertFalse(any(t['scheduled_fork']=='T14' for t in result['tips']))


if __name__ == '__main__':
    unittest.main()
