"""Exercise findings visibility and operator confirmations without Burp traffic."""
import ast
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from test_duplicate_queue import load
ROOT=Path(__file__).resolve().parents[1] / "burp" / "src"

class FindingsUiTests(unittest.TestCase):
    def helper(self):
        h=load('double_agent_extender_part4_chunk3.py', {'_finding_severity_display', '_finding_hidden_from_normal_view'})
        h._agent_status_value=lambda value: value
        return h

    def test_informational_aliases_have_one_display_and_count_category(self):
        h=self.helper()
        for value in ['Information','Informational','info','INFORMATIONAL',None]:
            self.assertEqual(h._finding_severity_display(value),'Information')
        self.assertEqual(h._finding_severity_display('medium'),'Medium')
        self.assertEqual(h._finding_severity_display('Unknown'),'Unknown')

    def test_show_hidden_reveals_fp_flag_and_fp_status_using_model_row(self):
        tree=ast.parse((ROOT/'double_agent_ui.py').read_text())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='FPRowFilter')
        namespace={'RowFilter':object}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[cls],type_ignores=[])),'filter','exec'),namespace)
        extender=self.helper()
        extender.findings_list=[{'stable_id':'daf_a'}, {'stable_id':'daf_b','fp':True}, {'stable_id':'daf_c','agent_status':'false_positive'}]
        extender.findings_lock_ui=threading.RLock()
        extender._show_fp_findings=False
        filter_=namespace['FPRowFilter'](extender)
        entries=[SimpleNamespace(getIdentifier=lambda index=i: index) for i in [2,0,1]]
        self.assertEqual([filter_.include(e) for e in entries],[False,True,False])
        extender._show_fp_findings=True
        self.assertEqual([filter_.include(e) for e in entries],[True,True,True])
        extender._show_fp_findings=False
        extender.findings_list[1]['fp']=False
        self.assertTrue(filter_.include(entries[2]))

    def delete_helper(self):
        h=load('double_agent_extender_part2_chunk2.py',{'_deleteSelected','_deleteFinding'})
        h.findings_list=[{'stable_id':'daf_a'}, {'stable_id':'daf_b'}]
        h.findings_lock_ui=threading.RLock()
        h._getSelectedModelRows=lambda: [1]
        h._confirmFindingRemoval=Mock(return_value=False)
        h.save_findings=Mock()
        h.refreshUI=Mock()
        h.log_to_console=Mock()
        h.stderr=SimpleNamespace(println=Mock())
        h._safe_ascii_text=str
        return h

    def test_cancel_selected_delete_preserves_findings_and_disk(self):
        h=self.delete_helper()
        h._deleteFinding()
        self.assertEqual(len(h.findings_list),2)
        h.save_findings.assert_not_called()

    def test_delete_keeps_selection_identity_if_background_rows_change(self):
        h=self.delete_helper()
        def confirm(count):
            h.findings_list.pop(0)
            h.findings_list.append({'stable_id':'daf_new'})
            return True
        h._confirmFindingRemoval=confirm
        h._deleteSelected()
        self.assertEqual(h.findings_list,[{'stable_id':'daf_new'}])
        h.save_findings.assert_called_once()

    def test_cancel_clear_preserves_all_state(self):
        h=load('double_agent_extender_part2.py',{'clearFindings'})
        h.findings_lock_ui=h.findings_lock=threading.RLock()
        h.findings_list=[{'stable_id':'daf_a'}]
        h.findings_cache={'saved'}
        h.fp_suppressed={'fp'}
        h._confirmFindingRemoval=Mock(return_value=False)
        h.save_findings=Mock()
        h.clearFindings(None)
        self.assertEqual(h.findings_list,[{'stable_id':'daf_a'}])
        self.assertEqual(h.findings_cache,{'saved'})
        self.assertEqual(h.fp_suppressed,{'fp'})
        h.save_findings.assert_not_called()

if __name__=='__main__': unittest.main()
