"""Real settings validation/rollback methods, with isolated files and no traffic."""
import copy
import ast
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from test_duplicate_queue import load


class SettingsTransactionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.helper = load('double_agent_extender_part4_chunk2.py', {'_validate_settings_draft', '_commit_settings_draft'})
        self.helper._commit_settings_draft.__func__.__globals__['threading'] = threading
        self.draft = dict(AI_PROVIDER='OpenAI-compatible', API_URL='http://localhost:8000/v1', API_KEY='fixture-new',
                          MODEL='fixture', MAX_TOKENS='2048', AI_REQUEST_TIMEOUT='60', ANALYSIS_WORKERS='2',
                          AI_REQUEST_CONCURRENCY='2', MAX_PROXY_QUEUED_ANALYSES='3', PROXY_ANALYSIS_MIN_INTERVAL_SECONDS='1',
                          PROJECT_WORKSPACE_DIR=str(self.root), REMOTE_REPORTING_PIN='12345678',
                          PASSIVE_SCANNING_ENABLED=False, THEME='Dark', VERBOSE=False, CUSTOM_SCAN_PROMPT='')
        for key in self.draft:
            setattr(self.helper, key, 'old-' + key)
        self.helper.REMOTE_REPORTING_PIN_SOURCE = 'secret_file'
        self.helper.API_KEYS_PER_PROVIDER = {'Ollama': 'fixture-old'}
        self.helper.BEDROCK_REGION = 'us-east-1'
        self.helper.semaphore = threading.Semaphore(1)
        self.helper._ai_request_semaphore = threading.Semaphore(1)
        self.helper._project_key_cache = None
        self.helper.config_file = str(self.root / 'config.json')
        self.helper.REMOTE_REPORTING_PIN_FILE = str(self.root / 'pin')
        Path(self.helper.config_file).write_bytes(b'old configuration')
        Path(self.helper.REMOTE_REPORTING_PIN_FILE).write_bytes(b'old pin')
        self.helper._unsafe_persistence_directory = lambda path: False
        self.helper._normalize_project_workspace_dir = Mock(side_effect=lambda path: path)
        self.helper._bedrock_serverless_models = Mock(return_value=['eligible'])
        def pin(value):
            Path(self.helper.REMOTE_REPORTING_PIN_FILE).write_text(value)
            self.helper.REMOTE_REPORTING_PIN = value
        self.helper._store_remote_reporting_pin = Mock(side_effect=pin)
        self.helper.save_config = Mock(return_value=True)

    def tearDown(self):
        self.directory.cleanup()

    def test_all_invalid_drafts_preserve_live_settings_and_files(self):
        cases = [('MODEL', ''), ('MAX_TOKENS', 'bad'), ('MAX_TOKENS', '0'), ('AI_REQUEST_TIMEOUT', '9'),
                 ('ANALYSIS_WORKERS', '11'), ('AI_REQUEST_CONCURRENCY', '0'), ('MAX_PROXY_QUEUED_ANALYSES', '21'),
                 ('PROXY_ANALYSIS_MIN_INTERVAL_SECONDS', 'nan'), ('PROXY_ANALYSIS_MIN_INTERVAL_SECONDS', 'inf'),
                 ('PROJECT_WORKSPACE_DIR', ''), ('REMOTE_REPORTING_PIN', 'invalid'),
                 ('API_URL', 'http://user:secret@localhost/v1'), ('API_URL', 'http://localhost/v1?key=secret')]
        before = {key: getattr(self.helper, key) for key in self.draft}
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.helper._validate_settings_draft(dict(self.draft, **{key: value}))
            self.assertEqual(before, {key: getattr(self.helper, key) for key in self.draft})
        self.helper.save_config.assert_not_called()
        self.helper._store_remote_reporting_pin.assert_not_called()
        self.helper._normalize_project_workspace_dir.assert_not_called()
        self.assertEqual(Path(self.helper.config_file).read_bytes(), b'old configuration')
        self.assertEqual(Path(self.helper.REMOTE_REPORTING_PIN_FILE).read_bytes(), b'old pin')

    def test_provider_validation_does_not_mutate_live_key_map_or_pin(self):
        for fields in [dict(AI_PROVIDER='OpenAI', MODEL='gpt-4'),
                       dict(AI_PROVIDER='Bedrock', MODEL='eligible', API_KEY=''),
                       dict(AI_PROVIDER='Bedrock', MODEL='unlisted')]:
            with self.assertRaises(ValueError):
                self.helper._validate_settings_draft(dict(self.draft, **fields))
        self.assertEqual(self.helper.API_KEYS_PER_PROVIDER, {'Ollama': 'fixture-old'})
        self.helper._store_remote_reporting_pin.assert_not_called()

    def test_save_failure_restores_memory_config_pin_and_semaphores(self):
        previous = dict(self.helper.__dict__)
        def fail():
            Path(self.helper.config_file).write_bytes(b'partial write')
            return False
        self.helper.save_config.side_effect = fail
        with self.assertRaisesRegex(ValueError, 'previous settings were restored'):
            self.helper._commit_settings_draft(self.helper._validate_settings_draft(self.draft))
        for key in list(self.draft) + ['API_KEYS_PER_PROVIDER', 'semaphore', '_ai_request_semaphore', '_project_key_cache']:
            self.assertEqual(getattr(self.helper, key), previous[key])
        self.assertEqual(Path(self.helper.config_file).read_bytes(), b'old configuration')
        self.assertEqual(Path(self.helper.REMOTE_REPORTING_PIN_FILE).read_bytes(), b'old pin')
        self.assertEqual(os.stat(self.helper.config_file).st_mode & 0o777, 0o600)

    def test_pin_failure_restores_previous_state_without_config_save(self):
        self.helper._store_remote_reporting_pin.side_effect = ValueError('PIN storage failed')
        with self.assertRaises(ValueError):
            self.helper._commit_settings_draft(self.helper._validate_settings_draft(self.draft))
        self.helper.save_config.assert_not_called()
        self.assertEqual(self.helper.AI_PROVIDER, 'old-AI_PROVIDER')
        self.assertEqual(Path(self.helper.REMOTE_REPORTING_PIN_FILE).read_bytes(), b'old pin')

    def test_success_commits_validated_values_and_preserves_other_provider_key(self):
        self.helper._commit_settings_draft(self.helper._validate_settings_draft(self.draft))
        self.assertEqual(self.helper.MAX_TOKENS, 2048)
        self.assertEqual(self.helper.API_KEYS_PER_PROVIDER, {'Ollama': 'fixture-old', 'OpenAI-compatible': 'fixture-new'})
        self.helper.save_config.assert_called_once()
        self.assertEqual(Path(self.helper.REMOTE_REPORTING_PIN_FILE).read_text(), '12345678')

    def test_real_config_write_failure_keeps_old_file_and_removes_secret_temp(self):
        helper = load('double_agent_extender_part4.py', {'save_config'})
        helper.save_config.__func__.__globals__['json'] = json
        # Populate the actual persisted attributes without constructing Burp.
        tree = ast.parse((Path(__file__).parents[1] / 'burp/src/double_agent_extender_part4.py').read_text())
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'save_config')
        for node in ast.walk(method):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'self':
                setattr(helper, node.attr, 'fixture')
        helper.config_file = self.helper.config_file
        helper._get_column_widths = lambda: {}
        helper.stdout = helper.stderr = type('Log', (), {'println': lambda *args: None})()
        helper._safe_ascii_text = str
        def fail_dump(value, stream, **kwargs):
            stream.write('partial secret fixture')
            raise OSError('fixture disk failure')
        with patch.object(json, 'dump', side_effect=fail_dump):
            self.assertFalse(helper.save_config())
        self.assertEqual(Path(helper.config_file).read_bytes(), b'old configuration')
        self.assertEqual(list(self.root.glob('.double-agent-config-*')), [])
