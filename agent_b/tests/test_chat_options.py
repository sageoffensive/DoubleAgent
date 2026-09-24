import json
import unittest
from unittest.mock import patch

from agent_b_harness.clients import Model
from agent_b_harness.config import Config


class ChatOptionsTests(unittest.TestCase):
    def test_thinking_modes_and_plain_chat_payload(self):
        for mode in (None, True, False):
            with self.subTest(mode=mode), patch('agent_b_harness.clients.http.client.HTTPConnection') as transport:
                response = transport.return_value.getresponse.return_value
                response.status = 200
                response.getheader.return_value = 'application/json'
                response.read.return_value = b'{"choices":[{"message":{"content":"Hello"}}]}'
                model = Model('http://localhost:8000/v1', 'test', 'custom', 5, 128)
                model.thinking = mode
                result = model.complete([{'role': 'user', 'content': 'Hello'}], [], None, 'none')
                payload = json.loads(transport.return_value.request.call_args.kwargs['body'])
                self.assertEqual(result['content'], 'Hello')
                self.assertNotIn('tools', payload)
                self.assertNotIn('tool_choice', payload)
                if mode is None:
                    self.assertNotIn('chat_template_kwargs', payload)
                else:
                    self.assertIs(payload['chat_template_kwargs']['enable_thinking'], mode)

    def test_public_model_capability(self):
        value = Config(custom_models=({'id': 'custom', 'model': 'server-model', 'url': 'http://localhost/v1', 'supports_thinking': True},)).public()
        option = value['model_options'][-1]
        self.assertTrue(option['supports_thinking'])
        self.assertEqual(option['model'], 'server-model')
