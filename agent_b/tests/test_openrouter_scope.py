import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch
from agent_b_harness import config
from agent_b_harness.clients import DoubleAgent, HTTPError, Model
from agent_b_harness.engine import Engine
from agent_b_harness.policy import allow_get, allow_post
from agent_b_harness.store import Store


class OpenRouterTests(unittest.TestCase):
    def test_defaults_https_and_secret_isolation(self):
        values = config._validated_connection('Router', 'vendor/example-model', '', 'openrouter', 'synthetic-key', '')
        self.assertEqual(values['url'], 'https://openrouter.ai/api/v1')
        cfg = config.Config(model='router', custom_models=({'id': 'router', **values},))
        self.assertEqual(config.resolve_model_connection(cfg)['provider'], 'openrouter')
        self.assertNotIn('synthetic-key', str(cfg.public()))
        with self.assertRaises(ValueError):
            config._validated_connection('Router', 'vendor/example-model', 'http://example.test', 'openrouter', 'key', '')
        with patch.object(config, 'SETTINGS', Path('/nonexistent/settings.json')):
            with self.assertRaisesRegex(ValueError, 'API key'):
                config.add_custom_model('Router', 'vendor/example-model', '', provider='openrouter')

    def test_key_check_precedes_public_catalogue(self):
        model = Model('https://openrouter.ai/api/v1', 'synthetic-key', 'vendor/example-model', 5, 512, 'openrouter')
        with patch('agent_b_harness.clients._json_request', side_effect=[{'data': {}}, {'data': [{'id': model.model}]}]) as request:
            result = model.test_connection()
        self.assertTrue(result['ok'])
        self.assertIn('inference was not tested', result['detail'])
        self.assertEqual([call.args[0] for call in request.call_args_list], [model.base + '/key', model.base + '/models'])
        with patch('agent_b_harness.clients._json_request', side_effect=HTTPError(401, {'error': 'unauthorized'})) as request:
            with self.assertRaises(HTTPError):
                model.test_connection()
            self.assertEqual(request.call_count, 1)

    def test_compatible_chat_request(self):
        with patch('agent_b_harness.clients.http.client.HTTPSConnection') as transport:
            response = transport.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = 'application/json'
            response.read.return_value = b'{"choices":[{"message":{"content":"OK"}}]}'
            model = Model('https://openrouter.ai/api/v1', 'synthetic-key', 'vendor/example-model', 5, 512, 'openrouter')
            self.assertEqual(model.complete([{'role': 'user', 'content': 'Say OK'}], [], tool_choice='none')['content'], 'OK')
            call = transport.return_value.request.call_args
            self.assertEqual(call.args[1], '/api/v1/chat/completions')
            self.assertEqual(call.kwargs['headers']['Authorization'], 'Bearer synthetic-key')
            payload = json.loads(call.kwargs['body'])
            self.assertEqual(payload['model'], 'vendor/example-model')
            self.assertEqual(payload['max_tokens'], 512)
            self.assertNotIn('max_completion_tokens', payload)


class ScopeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = Engine(Store(Path(self.directory.name) / 'db.sqlite'))
        self.engine.active_queue = '7'
        self.engine.queue_fetch_mode = True

    def tearDown(self):
        self.directory.cleanup()

    def test_model_approval_and_permission_edits_blocked(self):
        cases = [('/api/agent/request', {'confirmed': True}),
                 ('/api/agent/burp/action', {'arguments': {'confirmed': 'true'}}),
                 ('/api/agent/project-profile', {'allowed_state_changes': ['anything']}),
                 ('/api/agent/confirmations', {'confirmed': True}),
                 ('/api/agent/fixtures', {'consent_scope': '*'}),
                 ('/api/agent/project-profile/import-notes', {}),
                 ('/api/agent/scanner/active', {}), ('/api/agent/scanner/full-app', {})]
        for path, body in cases:
            with self.subTest(path=path), self.assertRaises(ValueError):
                allow_post(path, body)
        client = Mock()
        result, _ = self.engine._tool(client, 'double_agent_post', {
            'path': '/api/agent/request', 'body': {'confirmed': True}})
        self.assertFalse(result['ok'])
        client.post.assert_not_called()
        client.request.assert_not_called()

    def test_backend_denial_cannot_trigger_curl(self):
        class Client:
            def __init__(self): self.posts = []
            def get(self, path): return {'recommended_auth': {}}
            def post(self, path, body):
                self.posts.append((path, body))
                raise HTTPError(403, {'error': 'scope_not_verified', 'scope_guard': {'in_scope': False}})
        client = Client()
        with patch('subprocess.run', side_effect=AssertionError('No target subprocess')):
            result, _ = self.engine._tool(client, 'send_burp_request', {'url': 'https://outside.test/'})
        self.assertFalse(result['ok'])
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(self.engine.target_receipts, [])

    def test_unknown_scope_cannot_be_approved(self):
        for value in (False, None):
            self.assertFalse(self.engine._confirmation_required({
                'error': 'request_confirmation_required', 'scope_guard': {'in_scope': value}}))
        self.assertTrue(self.engine._confirmation_required({
            'error': 'safety_confirmation_required', 'scope_guard': {'in_scope': True}}))

    def test_stale_extension_blocked_before_execution(self):
        client = DoubleAgent('http://127.0.0.1:8777')
        with patch('agent_b_harness.clients._json_request', return_value={'status': 'ok'}) as request:
            with self.assertRaisesRegex(ValueError, 'Reload the extension'):
                client.post('/api/agent/request', {'host': 'example.test'})
            self.assertEqual(request.call_count, 1)
        with patch('agent_b_harness.clients._json_request', side_effect=[
            {'scope_enforcement': {'version': 1, 'fail_closed': True}}, {'status_code': 200}]) as request:
            self.assertEqual(client.post('/api/agent/request', {})['status_code'], 200)
            self.assertEqual(request.call_count, 2)

    def test_queue_request_uses_api_and_records_one_receipt(self):
        class Client:
            def __init__(self): self.posts = []
            def get(self, path):
                return {'commands': [{'command': "curl 'https://example.test/allowed?q=old'"}]}
            def post(self, path, body):
                self.posts.append((path, body))
                return {'status_code': 200, 'url': 'https://example.test/allowed?q=new', 'body': 'OK'}
        client = Client()
        with patch('subprocess.run', side_effect=AssertionError('No target subprocess')):
            result, _ = self.engine._tool(client, 'execute_queue_request', {'queue_id': '7', 'query_parameters': {'q': 'new'}})
        self.assertEqual(result['status_code'], 200)
        self.assertEqual(client.posts[0][0], '/api/agent/request')
        self.assertIn('/allowed?q=new', client.posts[0][1]['request'])
        self.assertEqual(len(self.engine.target_receipts), 1)

    def test_path_confusion_blocked(self):
        for path in ['/api/agent/queue-malicious', '/api/agent/%2e%2e/queue', '/api/agent/queue#hidden', '/api/agent/queue\\x']:
            with self.subTest(path=path), self.assertRaises(ValueError): allow_get(path)

    def test_api_redirect_refused(self):
        destinations = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                destinations.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/outside')
                self.end_headers()
            def log_message(self, *_): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            client = DoubleAgent(f'http://127.0.0.1:{server.server_port}')
            with self.assertRaisesRegex(ValueError, 'redirects are refused'):
                client.get('/api/health')
            self.assertEqual(destinations, ['/api/health'])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__': unittest.main()
