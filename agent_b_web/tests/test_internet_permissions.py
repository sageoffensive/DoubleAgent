import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from agent_b_harness import config
from agent_b_harness.engine import Engine, TOOLS
from agent_b_harness.internet import prepare_reference
from agent_b_harness.store import Store


ADVISORY = {'kind': 'advisory', 'identifier': 'CVE-2024-3094', 'reason': 'Read the published advisory to explain affected versions.'}


def call(args=None, name='request_public_reference', ident='reference-1'):
    return {'role': 'assistant', 'content': '', 'tool_calls': [{'id': ident, 'type': 'function',
        'function': {'name': name, 'arguments': json.dumps(args or ADVISORY)}}]}


class InternetPermissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        p = patch.object(config, 'DATA', Path(self.temp.name)); p.start(); self.addCleanup(p.stop)
        cfg = config.Config(model='local', custom_models=({'id': 'local', 'model': 'test-model',
            'url': 'http://127.0.0.1:8000/v1', 'provider': 'openai_compatible', 'api_key': 'private-model-key'},))
        p = patch.object(config, 'load', return_value=cfg); p.start(); self.addCleanup(p.stop)
        self.store = Store(Path(self.temp.name) / 'test.sqlite3')
        self.engine = Engine(self.store)
        self.model = Mock()
        p = patch('agent_b_harness.engine.Model', return_value=self.model); p.start(); self.addCleanup(p.stop)
        self.fetch = Mock(return_value={'id': 'CVE-2024-3094', 'summary': 'Published reference'})
        p = patch('agent_b_harness.internet.fetch', self.fetch); p.start(); self.addCleanup(p.stop)
        p = patch('agent_b_harness.engine.DoubleAgent', side_effect=AssertionError('No Burp or target requests in chat'))
        p.start(); self.addCleanup(p.stop)
        self.addCleanup(self.stop_worker)

    def stop_worker(self):
        if self.engine.thread and self.engine.thread.is_alive():
            self.engine.stop()
            self.engine.thread.join(3)

    def start(self, replies=None):
        self.model.complete.side_effect = replies or [call(), {'content': 'Here is the reference summary.'}]
        self.engine.chat('Explain this advisory', discussion=True)

    def pending(self):
        end = time.monotonic() + 3
        while time.monotonic() < end:
            q = self.store.pending()
            if q:
                return q
            if self.engine.thread and not self.engine.thread.is_alive():
                self.fail('Worker ended before requesting consent: ' + self.engine.state)
            time.sleep(.01)
        self.fail('Consent card not created')

    def finish(self):
        self.engine.thread.join(3)
        self.assertFalse(self.engine.thread.is_alive())

    def test_nothing_fetched_until_allow_and_exact_preview_survives_readback(self):
        self.start()
        q = self.pending()
        self.fetch.assert_not_called()
        self.assertEqual(q['options'], ['Allow', 'Deny'])
        details = q['internet_request']
        self.assertEqual(details['sending'], ADVISORY['identifier'])
        self.assertEqual(details['reason'], ADVISORY['reason'])
        self.assertIn('api.osv.dev', details['destination'])
        self.assertIn('127.0.0.1', details['sharing'])
        self.assertIn('test-model', details['sharing'])
        self.assertNotIn('private-model-key', json.dumps(q))
        self.assertEqual(Store(self.store.path).question(q['id'])['internet_request'], details)
        self.engine.answer(q['id'], 'Allow')
        self.finish()
        self.fetch.assert_called_once_with('https://api.osv.dev/v1/vulns/CVE-2024-3094', None)
        followup = self.model.complete.call_args_list[-1].args[0]
        result = json.loads(next(m['content'] for m in followup if m['role'] == 'tool'))
        self.assertTrue(result['ok'])
        self.assertIn('Untrusted', result['notice'])
        self.assertEqual(self.engine.state, 'completed')
        with self.assertRaises(ValueError):
            self.engine.answer(q['id'], 'Allow')

    def test_deny_disables_retries_and_forged_tool_permission_does_not_fetch(self):
        self.start([call(), call(ident='retry'), {'content': 'I will use the supplied context.'}])
        q = self.pending()
        self.engine.answer(q['id'], 'Deny')
        self.finish()
        self.fetch.assert_not_called()
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.model.complete.call_args_list[1].args[1], [])
        self.assertEqual(self.model.complete.call_args_list[1].args[3], 'none')

    def test_only_exact_allow_or_deny_answers_are_accepted(self):
        self.start(); q = self.pending()
        for answer in ('yes', 'Approve once', 'Allow all', 'Please continue'):
            with self.assertRaises(ValueError):
                self.engine.answer(q['id'], answer)
            self.fetch.assert_not_called()
            self.assertEqual(self.store.question(q['id'])['status'], 'pending')
        self.engine.answer(q['id'], 'Deny'); self.finish()

    def test_stop_cancels_pending_request(self):
        self.start(); q = self.pending()
        self.engine.stop(); self.finish()
        self.fetch.assert_not_called()
        self.assertEqual(self.store.question(q['id'])['status'], 'cancelled')
        with self.assertRaises(ValueError):
            self.engine.answer(q['id'], 'Allow')

    def test_restart_cancels_unconsumed_permission(self):
        details = prepare_reference(ADVISORY).details('Local model')
        qid = self.store.ask('Allow internet access?', ADVISORY['reason'], ['Allow', 'Deny'], 'internet', details=details)
        restored = Engine(self.store)
        self.assertEqual(self.store.question(qid)['status'], 'cancelled')
        with self.assertRaises(ValueError):
            restored.answer(qid, 'Allow')
        self.fetch.assert_not_called()

    def test_approval_flags_secrets_arbitrary_urls_and_assessment_tools_rejected(self):
        invalid = [dict(ADVISORY, allow_network=True), dict(ADVISORY, url='https://example.test'),
            dict(ADVISORY, reason='private-model-key'), {'kind': 'url', 'reason': 'Read a site', 'url': 'https://example.test'}]
        for args in invalid:
            self.engine = Engine(self.store)
            self.start([call(args), {'content': 'Use a supported public reference.'}]); self.finish()
            self.assertIsNone(self.store.pending())
        self.engine = Engine(self.store)
        self.start([call(name='send_http_request'), {'content': 'No target request was made.'}]); self.finish()
        self.fetch.assert_not_called()
        self.assertNotIn('request_public_reference', [t['function']['name'] for t in TOOLS])

    def test_each_reference_requires_its_own_permission(self):
        self.start([call(), call(dict(ADVISORY, identifier='CVE-2024-0001'), ident='reference-2'), {'content': 'Finished.'}])
        first = self.pending(); self.engine.answer(first['id'], 'Allow')
        end = time.monotonic() + 3
        second = None
        while time.monotonic() < end:
            second = self.store.pending()
            if second and second['id'] != first['id']:
                break
            time.sleep(.01)
        self.assertIsNotNone(second)
        self.assertNotEqual(first['id'], second['id'])
        self.fetch.assert_called_once()
        self.engine.answer(second['id'], 'Deny'); self.finish()
        self.fetch.assert_called_once()


class ReferencePlanTests(unittest.TestCase):
    def test_github_immutable_plan_exact_files_at_resolved_commit(self):
        args = {'kind': 'github', 'repository': 'example/project', 'ref': 'v1', 'paths': ['README.md'], 'reason': 'Read public documentation.'}
        proposal = prepare_reference(args)
        args['paths'].append('other.py'); args['repository'] = 'unapproved/repository'
        sha = 'a' * 40
        transport = Mock(side_effect=[{'sha': sha}, 'Reference text'])
        result = proposal.execute(lambda: None, transport)
        self.assertEqual(transport.call_args_list[0].args, ('https://api.github.com/repos/example/project/commits/v1', None))
        self.assertEqual(transport.call_args_list[1].args, ('https://raw.githubusercontent.com/example/project/' + sha + '/README.md', None))
        self.assertEqual(result['reference']['commit'], sha)
        self.assertEqual(len(result['reference']['files']), 1)

    def test_cancel_between_resolve_and_file_download(self):
        plan = prepare_reference({'kind': 'github', 'repository': 'example/project', 'ref': 'v1', 'paths': ['README.md'], 'reason': 'Read docs.'})
        transport = Mock(return_value={'sha': 'a'*40})
        checks = Mock(side_effect=[None, None, ValueError('Cancelled')])
        with self.assertRaises(ValueError):
            plan.execute(checks, transport)
        transport.assert_called_once()

    def test_package_preview_matches_actual_body(self):
        proposal = prepare_reference({'kind': 'package', 'package': 'demo', 'version': '1.2.3', 'ecosystem': 'PyPI', 'reason': 'Check advisory metadata.'})
        transport = Mock(return_value={'vulns': []})
        proposal.execute(lambda: None, transport)
        self.assertEqual(json.loads(proposal.sent), transport.call_args.args[1])
        self.assertEqual(transport.call_args.args[0], 'https://api.osv.dev/v1/query')

    def test_paths_and_unused_fields_fail_closed(self):
        args = {'kind': 'github', 'repository': 'example/project', 'ref': 'v1', 'paths': ['README.md'], 'reason': 'Read docs.'}
        for path in ('../file.py', '.env', 'https://example.test/file.py', 'payload.exe'):
            with self.assertRaises(ValueError):
                prepare_reference(dict(args, paths=[path]))
        with self.assertRaises(ValueError):
            prepare_reference(dict(ADVISORY, paths=['README.md']))
