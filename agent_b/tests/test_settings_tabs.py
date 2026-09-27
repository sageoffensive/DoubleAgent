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
        for name in ('connections', 'skills', 'general'):
            _, tab, _ = self.page.ids['settings-tab-' + name]
            _, panel, _ = self.page.ids['settings-' + name]
            self.assertEqual(tab['role'], 'tab')
            self.assertEqual(tab['type'], 'button')
            self.assertEqual(tab['aria-controls'], panel['id'])
            self.assertEqual(panel['aria-labelledby'], tab['id'])
            self.assertEqual(panel['role'], 'tabpanel')
            self.assertEqual('hidden' in panel, name != 'connections')

    def test_connections_and_skills_are_inside_settings_not_sidebar(self):
        for ident, panel in [('burp-state', 'connections'), ('model-state', 'connections'),
                             ('model-choice', 'connections'), ('active-skills', 'skills'),
                             ('skill-options', 'skills')]:
            ancestors = self.page.ids[ident][2]
            self.assertIn(('section', 'settings-' + panel), ancestors)
            self.assertIn(('form', 'settings-form'), ancestors)
            self.assertFalse(any(tag == 'aside' for tag, _ in ancestors))

    def test_target_remains_in_sidebar(self):
        self.assertTrue(any(tag == 'aside' for tag, _ in self.page.ids['target-link'][2]))
        self.assertNotIn('target-link-main', self.page.ids)
