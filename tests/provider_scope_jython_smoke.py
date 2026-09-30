# -*- coding: utf-8 -*-
"""Offline Jython compatibility and provider checks; no Burp/model connection."""
import json
import os
import sys
import types
import urllib2
import urlparse
from javax.swing import JComboBox

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "burp", "src")
sys.path.insert(0, ROOT)
for name in ('double_agent_scope.py', 'double_agent_api_part1.py',
             'double_agent_api_part3_chunk2.py', 'double_agent_api_part4_chunk2.py',
             'double_agent_extender_part1_chunk2.py', 'double_agent_extender_part4_chunk2.py',
             'double_agent_extender_part5_chunk2.py', 'double_agent_extender_part7.py'):
    with open(os.path.join(ROOT, name)) as handle:
        compile(handle.read(), name, 'exec')

from double_agent_scope import validate_raw_destination
validate_raw_destination('https://example.test/allowed', 'example.test', 443, True,
                         'GET /allowed HTTP/1.1\r\nHost: example.test\r\n\r\n')
try:
    validate_raw_destination('https://example.test/allowed', 'example.test', 443, True,
                             'GET /excluded HTTP/1.1\r\nHost: example.test\r\n\r\n')
    raise AssertionError('Excluded request path accepted')
except ValueError:
    pass

prelude = types.ModuleType('double_agent_prelude')
prelude.json, prelude.urlparse = json, urlparse
calls = []
class Reply(object):
    def __init__(self, data): self.data = json.dumps(data)
    def read(self): return self.data
    def close(self): pass

def open_request(request, timeout):
    calls.append(request)
    return Reply({'data': {}} if request.get_full_url().endswith('/key')
                 else {'data': [{'id': 'vendor/example-model'}]})
prelude.urllib2 = types.ModuleType('urllib2_stub')
prelude.urllib2.Request, prelude.urllib2.urlopen = urllib2.Request, open_request
sys.modules['double_agent_prelude'] = prelude
api = types.ModuleType('double_agent_api')
api.AgentAPIHandler = object
sys.modules['double_agent_api'] = api
sys.modules['double_agent_ui'] = types.ModuleType('double_agent_ui')
import double_agent_extender_part5_chunk2 as provider
class Log(object):
    def println(self, value): pass
harness = provider.BurpExtenderChunk5Chunk2()
harness.AI_PROVIDER, harness.API_URL = 'OpenRouter', 'https://openrouter.ai/api/v1'
harness.API_KEY, harness.MODEL = 'synthetic-key', 'vendor/example-model'
harness.stdout = harness.stderr = Log()
assert harness.test_ai_connection()
assert [request.get_full_url() for request in calls] == [harness.API_URL + '/key', harness.API_URL + '/models']
combo = JComboBox(['vendor/example-model'])
combo.setEditable(True)
combo.setSelectedItem('another/exact-id')
assert str(combo.getSelectedItem()) == 'another/exact-id'
print('PASS: Jython source compilation, exact path check, OpenRouter authentication/catalogue, editable Swing model selector')
