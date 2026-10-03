from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ConnectionTestUiTests(unittest.TestCase):
    def test_test_action_is_in_connections_settings_not_editor(self) -> None:
        html = (ROOT / "static" / "index.html").read_text()
        connections = html.split('<section id="settings-models"', 1)[1].split("</section>", 1)[0]
        editor = html.split('<dialog id="model-dialog"', 1)[1].split("</dialog>", 1)[0]

        self.assertIn('id="test-model"', connections)
        self.assertIn('id="connection-test-result"', connections)
        self.assertNotIn('id="test-model"', editor)
        self.assertNotIn('id="connection-test-result"', editor)
        self.assertIn('id="model-status"', editor)

    def test_test_action_uses_selected_saved_connection(self) -> None:
        javascript = (ROOT / "static" / "app.js").read_text()
        handler = javascript.split("$('#test-model').onclick", 1)[1].split("$('#remove-model').onclick", 1)[0]

        self.assertIn("const id = $('#model-choice').value", handler)
        self.assertIn("JSON.stringify({id})", handler)
        self.assertNotIn("new FormData", handler)


if __name__ == "__main__":
    unittest.main()
