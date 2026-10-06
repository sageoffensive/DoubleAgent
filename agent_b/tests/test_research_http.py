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

    def test_local_preview_does_not_fetch_and_start_needs_permission(self):
        status, _, data = self.request('POST','/api/research/preview-dependencies',{'format':'requirements','text':'demo==1.0'})
        self.assertEqual(status,200)
        self.assertEqual(len(json.loads(data)['packages']),1)
        self.research.request.assert_not_called()
        self.assertEqual(self.request('POST','/api/research/start',{'kind':'advisory','identifier':'CVE-2024-3094'})[0],400)

    def test_upload_readback_export_and_scoped_delete(self):
        status, _, data = self.request('POST','/api/research/start',{'kind':'upload','files':[{'name':'example.py','data':base64.b64encode(b'return_value = 42').decode()}]})
        self.assertEqual(status,202)
        ident = json.loads(data)['id']; self.research.worker.join(2)
        status, _, data = self.request('GET','/api/research/'+ident)
        self.assertEqual(status,200); self.assertEqual(json.loads(data)['status'],'complete')
        status, headers, data = self.request('GET','/api/research/'+ident+'/download')
        self.assertEqual(status,200); self.assertIn(b'return_value',data)
        self.assertTrue(headers['Content-Disposition'].startswith('attachment;'))
        self.assertEqual(headers['X-Content-Type-Options'],'nosniff')
        self.assertEqual(self.request('POST','/api/research/delete',{'id':ident})[0],200)
        self.assertEqual(self.request('GET','/api/research/'+ident)[0],404)

    def test_review_consent_and_connection_change_fail_closed(self):
        with patch.object(self.server, 'Model') as model:
            self.assertEqual(self.request('POST','/api/research/start',{'kind':'review','allow_model':False})[0],400)
            self.assertEqual(self.request('POST','/api/research/start',{'kind':'review','allow_model':True,'connection_fingerprint':'stale'})[0],400)
            model.assert_not_called()
        status, _, data = self.request('GET','/api/research')
        self.assertEqual(status,200)
        self.assertNotIn('api_key',json.loads(data)['connection'])

    def test_review_rejects_an_active_assessment(self):
        self.server.ENGINE.thread = Mock()
        self.server.ENGINE.thread.is_alive.return_value = True
        with patch.object(self.server, 'Model') as model:
            self.assertEqual(self.request('POST','/api/research/start',{'kind':'review','allow_model':True})[0],400)
            model.assert_not_called()

    def test_review_http_uses_only_selected_note(self):
        job = self.research.start('upload',{'files':[{'name':'example.py','data':base64.b64encode(b'x = 1').decode()}]})
        self.research.worker.join(2)
        fingerprint = connection_label(config.resolve_model_connection(self.cfg))['fingerprint']
        with patch.object(self.server, 'Model') as model:
            model.return_value.complete.return_value = {'content':'No complete audit performed. Review surrounding usage.'}
            status, _, data = self.request('POST','/api/research/start',{'kind':'review','allow_model':True,'connection_fingerprint':fingerprint,'note_id':job['id']})
            self.assertEqual(status,202); self.research.worker.join(2)
            self.assertEqual(self.research.get(json.loads(data)['id'])['status'],'complete')
            self.assertEqual(model.return_value.complete.call_args.args[1],[])

    def test_ui_is_available_and_source_is_not_rendered_as_html(self):
        for path in ('/', '/source-review.js'):
            self.assertEqual(self.request('GET',path)[0],200)
        script = self.request('GET','/source-review.js')[2].decode()
        self.assertNotIn('innerHTML',script)
        self.assertIn('textContent',script)

    def test_version_is_visible_without_javascript(self):
        from agent_b_harness import DISPLAY_VERSION, __version__
        for path in ('/',):
            status, headers, data = self.request('GET', path)
            self.assertEqual(status, 200)
            self.assertIn(DISPLAY_VERSION.encode(), data)
            self.assertNotIn(b'{{AGENT_B_VERSION}}', data)
            self.assertIn('AgentB/' + __version__, headers['Server'])
            self.assertEqual(int(headers['Content-Length']), len(data))
        with patch.object(self.server, 'DISPLAY_VERSION', 'v9.0.0-beta.1 <test>'):
            for path in ('/',):
                data = self.request('GET', path)[2]
                self.assertIn(b'v9.0.0-beta.1 &lt;test&gt;', data)
                self.assertNotIn(DISPLAY_VERSION.encode(), data)

    def test_review_stays_in_chat_with_visible_target_link(self):
        status, headers, _ = self.request('GET', '/research.html')
        self.assertEqual(status, 303)
        self.assertEqual(headers['Location'], '/')
        page = self.request('GET', '/')[2].decode()
        self.assertIn('id="source-review-panel"', page)
        self.assertIn('id="target-link"', page)
        self.assertNotIn('id="target-link-main"', page)
        self.assertNotIn('href="/research.html"', page)
        self.assertIn('id="composer-status"', page)
        self.assertIn('Privacy &amp; limits', page)
        self.assertEqual(self.request('GET', '/research.js')[0], 404)


if __name__ == '__main__':
    unittest.main()
