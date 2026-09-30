from html.parser import HTMLParser
from pathlib import Path
import unittest


class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.stack, self.ids, self.duplicates = [], {}, []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            if attrs['id'] in self.ids:
                self.duplicates.append(attrs['id'])
            self.ids[attrs['id']] = (tag, attrs, list(self.stack))
        if tag not in {'input', 'meta', 'link', 'img', 'br', 'hr'}:
            self.stack.append((tag, attrs.get('id')))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break


class SettingsTabsTests(unittest.TestCase):
    def setUp(self):
        self.page = Elements((Path(__file__).parents[1] / 'static/index.html').read_text())

    def test_unique_controls_and_accessible_tabs(self):
        self.assertEqual(self.page.duplicates, [])
        for name in ('models', 'skills', 'run'):
            _, tab, _ = self.page.ids['settings-tab-' + name]
            _, panel, _ = self.page.ids['settings-' + name]
            self.assertEqual(tab['role'], 'tab')
            self.assertEqual(tab['type'], 'button')
            self.assertEqual(tab['aria-controls'], panel['id'])
            self.assertEqual(panel['aria-labelledby'], tab['id'])
            self.assertEqual(panel['role'], 'tabpanel')
            self.assertEqual('hidden' in panel.get('class', '').split(), name != 'models')

    def test_editable_controls_stay_in_the_correct_settings_section(self):
        for ident, panel in [('model-choice', 'models'), ('model-url-input', 'models'),
                             ('skill-options', 'skills')]:
            ancestors = self.page.ids[ident][2]
            self.assertIn(('section', 'settings-' + panel), ancestors)
            self.assertIn(('form', 'settings-form'), ancestors)
            self.assertFalse(any(tag == 'aside' for tag, _ in ancestors))

    def test_status_and_target_are_reachable_in_the_sidebar(self):
        for ident in ('burp-state', 'model-state', 'active-skills', 'target-link'):
            self.assertTrue(any(tag == 'aside' for tag, _ in self.page.ids[ident][2]))
        self.assertIn('target-link-main', self.page.ids)

    def test_workspace_tabs_link_to_unique_views(self):
        for name in ('conversation', 'notebook', 'assessment'):
            _, tab, _ = self.page.ids['tab-' + name]
            _, panel, _ = self.page.ids['pane-' + name]
            self.assertEqual(tab['aria-controls'], panel['id'])
            self.assertEqual(panel['aria-labelledby'], tab['id'])
            self.assertEqual(panel['role'], 'tabpanel')
