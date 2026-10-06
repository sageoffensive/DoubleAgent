import base64
import http.client
import importlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from agent_b_harness import config
from agent_b_harness.research import Research, connection_label


class ResearchHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        with patch.object(config, 'DATA', Path(self.temp.name)):
            self.server = importlib.import_module('agent_b_harness.server')
        self.research = Research(Path(self.temp.name) / 'research.sqlite3', Mock())
        self.cfg = config.Config(model='test', custom_models=({'id':'test','model':'qa-model','url':'http://127.0.0.1:8000/v1','provider':'openai_compatible'},))
        for name, value in [('RESEARCH', self.research), ('ENGINE', Mock(thread=None))]:
            p = patch.object(self.server, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(config, 'load', return_value=self.cfg); p.start(); self.addCleanup(p.stop)
        self.http = self.server.ThreadingHTTPServer(('127.0.0.1', 0), self.server.Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.http.server_port)
        conn.request(method, path, json.dumps(body) if body is not None else None, {'Content-Type':'application/json', **(headers or {})})
        result = conn.getresponse()
        value = result.status, dict(result.getheaders()), result.read()
        conn.close()
        return value

    def test_research_routes_are_same_origin_and_host_protected(self):
        self.assertEqual(self.request('GET','/api/research',headers={'Host':'evil.example'})[0],403)
        self.assertEqual(self.request('POST','/api/research/start',{}, {'Origin':'https://example.test'})[0],403)
        self.assertEqual(self.request('POST','/api/research/start',{}, {'Sec-Fetch-Site':'cross-site'})[0],403)
        self.assertEqual(self.request('POST','/api/research/start',{}, {'Content-Type':'text/plain'})[0],400)

    def test_removed_routes_cannot_fetch_or_share_even_with_old_consent_flags(self):
        with patch.object(self.research, 'start') as start, patch.object(self.server, 'Model') as model:
            for route in ('start', 'preview-dependencies', 'cancel', 'delete'):
                status, _, data = self.request('POST', '/api/research/' + route, {
                    'kind': 'review', 'allow_network': True, 'allow_model': True,
                    'identifier': 'CVE-2024-3094', 'connection_fingerprint': 'old-consent'})
                self.assertEqual(status, 410)
                self.assertIn('removed', json.loads(data)['error'])
            start.assert_not_called()
            model.assert_not_called()
            self.research.request.assert_not_called()

    def test_historical_notes_still_readable_without_network(self):
        job = self.research.start('upload', {'files': [{'name': 'example.py', 'data': base64.b64encode(b'value = 42').decode()}]})
        self.research.worker.join(2)
        ident = job['id']
        status, _, data = self.request('GET', '/api/research/' + ident)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)['status'], 'complete')
        status, headers, data = self.request('GET', '/api/research/' + ident + '/download')
        self.assertEqual(status, 200)
        self.assertIn(b'value = 42', data)
        self.assertTrue(headers['Content-Disposition'].startswith('attachment;'))
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.research.request.assert_not_called()

    def test_removed_ui_and_help(self):
        status, _, data = self.request('GET', '/')
        self.assertEqual(status, 200)
        page = data.decode()
        self.assertNotIn('source-review', page)
        self.assertNotIn('Review together', page)
        self.assertIn('Internet access', page)
        self.assertEqual(self.request('GET', '/source-review.js')[0], 404)
        status, headers, _ = self.request('GET', '/research.html')
        self.assertEqual(status, 303)
        self.assertEqual(headers['Location'], '/')
