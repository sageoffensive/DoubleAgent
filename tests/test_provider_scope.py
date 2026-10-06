"""Offline provider and scope regression checks against the real extension methods."""
import ast
import io
import json
import unittest
import urllib.parse
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import sys
BURP_SRC = Path(__file__).resolve().parents[1] / "burp" / "src"
sys.path.insert(0, str(BURP_SRC))

from double_agent_scope import validate_destination, validate_raw_destination, validate_request_path

ROOT = BURP_SRC


def load_methods(filename, names, **namespace):
    tree = ast.parse((ROOT / filename).read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace.update(json=json, urlparse=urllib.parse,
                     validate_destination=validate_destination,
                     validate_raw_destination=validate_raw_destination,
                     validate_request_path=validate_request_path)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), filename, 'exec'), namespace)
    return namespace[cls.name]


class ProviderTests(unittest.TestCase):
    def harness(self, responses):
        calls = []
        def open_request(request, timeout):
            calls.append(request)
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return io.BytesIO(json.dumps(value).encode())
        api = SimpleNamespace(Request=urllib.request.Request, urlopen=open_request)
        cls = load_methods('double_agent_extender_part5_chunk2.py',
                           {'_test_openrouter_connection', '_test_openai_connection',
                            '_test_openai_compatible_connection', 'test_ai_connection'}, urllib2=api)
        harness = cls()
        harness.AI_PROVIDER, harness.API_URL = 'OpenRouter', 'https://openrouter.ai/api/v1'
        harness.API_KEY, harness.MODEL = 'synthetic-key', 'vendor/example-model'
        harness.stdout = harness.stderr = SimpleNamespace(println=Mock())
        harness._safe_ascii_text = str
        return harness, calls

    def test_openrouter_checks_key_and_exact_model_without_gpt_filter(self):
        harness, calls = self.harness([{'data': {}}, {'data': [{'id': 'vendor/example-model'}]}])
        self.assertTrue(harness.test_ai_connection())
        self.assertEqual([req.full_url for req in calls], [harness.API_URL + '/key', harness.API_URL + '/models'])
        self.assertEqual(calls[0].get_header('Authorization'), 'Bearer synthetic-key')
        self.assertEqual(harness.MODEL, 'vendor/example-model')

    def test_invalid_key_and_unlisted_model_fail_without_model_replacement(self):
        for values in ([ValueError('denied')], [{'data': {}}, {'data': [{'id': 'another/model'}]}]):
            harness, _ = self.harness(values)
            self.assertFalse(harness.test_ai_connection())
            self.assertEqual(harness.MODEL, 'vendor/example-model')

    def test_refresh_lists_models_before_model_selection(self):
        harness, _ = self.harness([{'data': {}}, {'data': [{'id': 'another/model'}]}])
        self.assertTrue(harness._test_openrouter_connection(require_model=False))
        self.assertEqual(harness.MODEL, 'vendor/example-model')

    def test_missing_key_or_insecure_url_does_not_contact_provider(self):
        for field, value in [('API_KEY', ''), ('API_URL', 'http://openrouter.ai/api/v1')]:
            harness, calls = self.harness([])
            setattr(harness, field, value)
            self.assertFalse(harness.test_ai_connection())
            self.assertEqual(calls, [])

    def test_openai_connection_uses_the_configured_endpoint(self):
        harness, calls = self.harness([{'data': [{'id': 'gpt-4o'}]}])
        harness.AI_PROVIDER, harness.MODEL = 'OpenAI', 'gpt-4o'
        harness.API_URL = 'https://custom.example.test/v1'
        self.assertTrue(harness.test_ai_connection())
        self.assertEqual(calls[0].full_url, harness.API_URL + '/models')

    def test_local_compatible_lists_exact_model_without_key_or_gpt_filter(self):
        harness, calls = self.harness([{'data': [{'id': 'Qwen3.8-Flash-Next'}]}])
        harness.AI_PROVIDER, harness.API_URL = 'OpenAI-compatible', 'http://local.example.test:8888/v1/'
        harness.API_KEY, harness.MODEL = '', 'Qwen3.8-Flash-Next'
        self.assertTrue(harness.test_ai_connection())
        self.assertEqual(harness.available_models, ['Qwen3.8-Flash-Next'])
        self.assertEqual(calls[0].full_url, 'http://local.example.test:8888/v1/models')
        self.assertIsNone(calls[0].get_header('Authorization'))

    def test_local_compatible_requires_selected_model_and_uses_optional_key(self):
        harness, calls = self.harness([{'data': [{'id': 'other-model'}]}])
        harness.AI_PROVIDER, harness.API_URL = 'OpenAI-compatible', 'https://local.example.test/v1'
        harness.API_KEY, harness.MODEL = 'synthetic-key', 'Qwen3.8-Flash-Next'
        self.assertFalse(harness.test_ai_connection())
        self.assertEqual(harness.MODEL, 'Qwen3.8-Flash-Next')
        self.assertEqual(calls[0].get_header('Authorization'), 'Bearer synthetic-key')
        harness, _ = self.harness([{'data': [{'id': 'other-model'}]}])
        harness.AI_PROVIDER, harness.API_URL = 'OpenAI-compatible', 'https://local.example.test/v1'
        self.assertTrue(harness._test_openai_compatible_connection(require_model=False))

    def test_local_compatible_rejects_invalid_base_url_before_request(self):
        for base in ('file:///tmp/v1', 'http://local.example.test/v1?token=secret'):
            harness, calls = self.harness([])
            harness.AI_PROVIDER, harness.API_URL = 'OpenAI-compatible', base
            self.assertFalse(harness.test_ai_connection())
            self.assertEqual(calls, [])

    def test_openrouter_completion_uses_custom_base_bearer_and_max_tokens(self):
        capture = []
        def open_request(request, timeout):
            capture.append(request)
            return io.BytesIO(b'{"choices":[{"message":{"content":"OK"}}]}')
        cls = load_methods('double_agent_extender_part7.py', {'_ask_openai'},
                           urllib2=SimpleNamespace(Request=urllib.request.Request, urlopen=open_request), unicode=str)
        harness = cls()
        harness.AI_PROVIDER, harness.API_URL = 'OpenRouter', 'https://openrouter.ai/api/v1'
        harness.API_KEY, harness.MODEL = 'synthetic-key', 'vendor/example-model'
        harness.MAX_TOKENS, harness.AI_REQUEST_TIMEOUT = 512, 5
        harness._estimate_token_count = lambda text: 1
        harness._sanitize_ai_json_text = lambda text: text
        harness._record_token_usage = Mock()
        self.assertEqual(harness._ask_openai('Say OK'), b'OK')
        request = capture[0]
        self.assertEqual(request.full_url, harness.API_URL + '/chat/completions')
        payload = json.loads(request.data)
        self.assertEqual(payload['model'], harness.MODEL)
        self.assertEqual(payload['max_tokens'], 512)
        self.assertNotIn('max_completion_tokens', payload)

    def test_local_compatible_completion_omits_empty_auth_and_uses_max_tokens(self):
        capture = []
        def open_request(request, timeout):
            capture.append(request)
            return io.BytesIO(b'{"choices":[{"message":{"content":"OK","reasoning_content":"hidden"}}]}')
        cls = load_methods('double_agent_extender_part7.py', {'_ask_openai'},
                           urllib2=SimpleNamespace(Request=urllib.request.Request, urlopen=open_request), unicode=str)
        harness = cls()
        harness.AI_PROVIDER, harness.API_URL = 'OpenAI-compatible', 'http://local.example.test:8888/v1'
        harness.API_KEY, harness.MODEL = '', 'Qwen3.8-Flash-Next'
        harness.MAX_TOKENS, harness.AI_REQUEST_TIMEOUT = 512, 5
        harness._estimate_token_count = lambda text: 1
        harness._sanitize_ai_json_text = lambda text: text
        harness._record_token_usage = Mock()
        self.assertEqual(harness._ask_openai('Say OK'), b'OK')
        self.assertEqual(capture[0].full_url, harness.API_URL + '/chat/completions')
        self.assertIsNone(capture[0].get_header('Authorization'))
        payload = json.loads(capture[0].data)
        self.assertEqual(payload['model'], harness.MODEL)
        self.assertEqual(payload['max_tokens'], 512)
        self.assertNotIn('max_completion_tokens', payload)


class ScopeTests(unittest.TestCase):
    def test_authority_service_port_and_path_must_match(self):
        validate_raw_destination('https://example.test/allowed?q=1', 'example.test', 443, True,
                                 'GET /allowed?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n')
        cases = [
            'GET /excluded HTTP/1.1\r\nHost: example.test\r\n\r\n',
            'GET /allowed?q=1 HTTP/1.1\r\nHost: outside.test\r\n\r\n',
            'GET /allowed?q=1 HTTP/1.1\r\nHost: example.test:8443\r\n\r\n',
            'GET /allowed?q=1 HTTP/1.1\r\nHost: example.test\r\nHost: outside.test\r\n\r\n',
            'GET https://outside.test/allowed?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n',
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                validate_raw_destination('https://example.test/allowed?q=1', 'example.test', 443, True, raw)

    def test_http_and_http2_reject_unknown_scope_even_with_confirmation(self):
        cls = load_methods('double_agent_api_part4_chunk2.py',
                           {'_handle_agent_request', '_handle_agent_request_http2'})
        for in_scope in (None, False):
            for http2 in (False, True):
                harness = cls()
                body = {'host': 'example.test', 'port': 443, 'https': True, 'confirmed': True,
                        'request': 'GET /allowed HTTP/1.1\r\nHost: example.test\r\n\r\n'}
                if http2:
                    body.update(targetHostname='example.test', targetPort=443, usesHttps=True,
                                pseudoHeaders={':method': 'GET', ':path': '/allowed', ':authority': 'example.test'})
                harness._read_body = lambda: body
                harness._coerce_bool = lambda value, default: bool(value)
                harness._limit_text = lambda value, maximum: str(value)[:maximum]
                harness._strip_agent_note_header_from_raw_request = lambda raw: (raw, '')
                harness._split_raw_http_request = lambda raw: {'method': 'GET', 'target': '/allowed'}
                harness._scope_guard_for_url = lambda url: {'in_scope': in_scope, 'requires_confirmation': True}
                harness._safety_gate_for_request = lambda method, url: {}
                harness._send_json = Mock()
                harness._portswigger_mcp_call_tool = Mock(side_effect=AssertionError('Traffic forbidden'))
                harness.extender = SimpleNamespace(callbacks=Mock())
                getattr(harness, '_handle_agent_request_http2' if http2 else '_handle_agent_request')()
                self.assertEqual(harness._send_json.call_args.args[0], 403)
                harness._portswigger_mcp_call_tool.assert_not_called()
                harness.extender.callbacks.makeHttpRequest.assert_not_called()

    def test_mcp_cannot_change_scope_or_use_unreviewed_tools(self):
        cls = load_methods('double_agent_api_part4_chunk2.py', {'_mcp_action_gate'})
        for policy in ({'classification': 'destructive', 'policy_source': 'explicit_registry'},
                       {'classification': 'active', 'policy_source': 'conservative_schema_fallback'}):
            harness = cls()
            harness._mcp_action_policy = lambda capabilities, name: policy
            code, value = harness._mcp_action_gate({}, 'tool', {}, True)
            self.assertEqual(code, 403)
            self.assertEqual(value['error'], 'mcp_action_not_permitted')


if __name__ == '__main__':
    unittest.main()
