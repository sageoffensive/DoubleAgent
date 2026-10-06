"""Exercise the real extension methods offline, without a JVM or target traffic."""
import ast
import copy
import threading
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1] / "burp" / "src"


def load(filename, names):
    tree = ast.parse((ROOT / filename).read_text())
    methods = [node for cls in tree.body if isinstance(cls, ast.ClassDef)
               for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(methods) == len(names)
    cls = ast.ClassDef(name='Harness', bases=[], keywords=[], body=methods, decorator_list=[])
    namespace = {'copy': copy, 'datetime': datetime}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), filename, 'exec'), namespace)
    return namespace['Harness']()


def findings():
    return [{'stable_id': 'daf_a', 'agent_validated_by': 'B', 'agent_status': 'valid'},
            {'stable_id': 'daf_b', 'agent_validated_by': 'A'},
            {'stable_id': 'daf_fp', 'fp': True}]


class DuplicateQueueTests(unittest.TestCase):
    def api(self):
        api = load('double_agent_api_part3_chunk2.py', {'_queue_findings_full', '_build_queue_curl_payload'})
        api.extender = SimpleNamespace(findings_list=findings(), findings_lock_ui=threading.RLock())
        api._serialize_finding = lambda idx, row, include_full: dict(row, id=row['stable_id'], legacy_numeric_id=idx + 1)
        return api

    def test_immutable_ids_in_either_queue_field_resolve_full_population(self):
        api = self.api()
        for field in ('finding_ids', 'finding_stable_ids'):
            self.assertEqual([row['id'] for row in api._queue_findings_full({field: ['daf_b', 'daf_a']})], ['daf_a', 'daf_b'])

    def test_stale_stable_ids_do_not_fall_back_to_unrelated_numeric_positions(self):
        api = self.api()
        self.assertEqual(api._queue_findings_full({'finding_stable_ids': ['daf_missing'], 'finding_ids': [0, 1]}), [])
        self.assertEqual([row['id'] for row in api._queue_findings_full({'finding_ids': [0, '1', 1, 'bad', 99]})], ['daf_a', 'daf_b'])

    def test_detail_reports_unresolved_population_instead_of_silently_returning_empty(self):
        api = self.api()
        endpoint = load('double_agent_api_part2_chunk3.py', {'_handle_get_queue_item'})
        endpoint._get_queue_item_snapshot = lambda qid: {'id': qid, 'source': 'duplicate_review', 'finding_ids': ['daf_a', 'daf_missing']}
        endpoint._queue_findings_full = api._queue_findings_full
        endpoint._queue_operational_metadata = lambda *args: {'safe_to_auto_test': True, 'recommended_transport': 'curl_proxy'}
        endpoint._build_queue_curl_payload = Mock(side_effect=AssertionError('duplicate review cannot build target curl'))
        endpoint._send_json = Mock()
        endpoint._handle_get_queue_item('0')
        status, response = endpoint._send_json.call_args.args
        self.assertEqual(status, 200)
        self.assertEqual(response['linked_findings_resolution'], {'requested_count': 2, 'resolved_count': 1, 'unresolved_stable_ids': ['daf_missing']})
        self.assertFalse(response['next_action']['safe_to_auto_test'])
        self.assertEqual(response['next_action']['recommended_transport'], 'read_only')
        endpoint._build_queue_curl_payload.assert_not_called()

    def test_queue_captures_validated_canonical_and_new_finding_with_immutable_ids(self):
        selector = load('double_agent_extender_part5.py', {'_duplicate_review_finding_ids'})
        selector.findings_lock_ui = threading.RLock()
        selector.findings_list = findings()
        selector._ensure_finding_stable_id = lambda row: row['stable_id']
        selector._finding_hidden_from_normal_view = lambda row: bool(row.get('fp'))
        queue = load('double_agent_extender_part2_chunk3.py', {'_enqueueDuplicateReview'})
        queue._duplicate_review_finding_ids = selector._duplicate_review_finding_ids
        queue.agent_server = object()
        queue.agent_queue_lock = threading.RLock()
        queue.agent_queue_next_id = 0
        queue.agent_queue = []
        queue.agent_server_host, queue.agent_server_port = '127.0.0.1', 9999
        queue.save_agent_queue = queue.log_to_console = queue.refreshUI = queue._focus_agent_tab = Mock()
        self.assertEqual(queue._enqueueDuplicateReview(), 0)
        item = queue.agent_queue[0]
        self.assertEqual(item['finding_ids'], ['daf_a', 'daf_b'])
        self.assertEqual(item['finding_stable_ids'], ['daf_a', 'daf_b'])
        self.assertEqual(item['duplicate_review']['finding_count'], 2)

    def test_stable_ids_survive_index_remapping_after_deletion(self):
        helper = load('double_agent_extender_part4_chunk3.py', {'_remap_finding_ids_after_deleted_indices'})
        self.assertEqual(helper._remap_finding_ids_after_deleted_indices(['daf_a', 'daf_b', 0, 1, 2], [1]), ['daf_a', 'daf_b', 0, 1])
        api = load('double_agent_api_part1_chunk3.py', {'_remap_queue_finding_ids_after_delete'})
        api.extender = SimpleNamespace(agent_queue_lock=threading.RLock(), agent_queue=[{'finding_ids': ['daf_a', 'daf_b', 0, 2]}], save_agent_queue=Mock())
        api._remap_queue_finding_ids_after_delete([1])
        self.assertEqual(api.extender.agent_queue[0]['finding_ids'], ['daf_a', 'daf_b', 0, 1])

    def test_server_completion_checks_population_and_authoritative_deletion_audit(self):
        api = load('double_agent_api_part4.py', {'_duplicate_review_completion_problem'})
        api.extender = SimpleNamespace(findings_lock_ui=threading.RLock(), findings_list=[findings()[0]], finding_audit_log=[{'stable_id': 'daf_b', 'event': 'deleted', 'reason': 'duplicate'}])
        queue = {'source': 'duplicate_review', 'finding_stable_ids': ['daf_a', 'daf_b']}
        report = {'duplicate_review': {'status': 'completed', 'reviewed_finding_ids': ['daf_a', 'daf_b']}}
        self.assertEqual(api._duplicate_review_completion_problem(queue, report), '')
        self.assertTrue(api._duplicate_review_completion_problem(queue, {}))
        self.assertTrue(api._duplicate_review_completion_problem(queue, {'duplicate_review': {'status': 'completed', 'reviewed_finding_ids': ['daf_a']}}))
        api.extender.finding_audit_log = []
        self.assertTrue(api._duplicate_review_completion_problem(queue, report))

    def test_final_result_never_retags_retained_canonical_findings(self):
        api = load('double_agent_api_part4.py', {'_apply_queue_result_to_findings'})
        api._finding_update_map_from_result_body = lambda body: {}
        api.extender = SimpleNamespace(findings_list=findings())
        before = copy.deepcopy(api.extender.findings_list)
        self.assertEqual(api._apply_queue_result_to_findings({'source': 'duplicate_review'}, {}, 'inconclusive', 'Review complete', 'now'), [])
        self.assertEqual(api.extender.findings_list, before)

    def test_duplicate_review_cannot_generate_target_curl(self):
        status, response = self.api()._build_queue_curl_payload({'source': 'duplicate_review'}, [])
        self.assertEqual(status, 409)
        self.assertEqual(response['error'], 'duplicate_review_is_read_only')


if __name__ == '__main__':
    unittest.main()
