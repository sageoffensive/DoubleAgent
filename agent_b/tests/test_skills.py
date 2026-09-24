from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_b_harness.skills import (
    BUILTIN_SKILLS,
    create_skill,
    public_catalog,
    render_skill_prompt,
    selected_skills,
)


class SkillCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.data = Path(self.directory.name)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_builtin_catalog_covers_modern_web_assessment_families(self) -> None:
        identifiers = {item["id"] for item in BUILTIN_SKILLS}
        self.assertTrue({
            "bug-bounty-methodology",
            "attack-surface-discovery",
            "api-authorization",
            "identity-oauth-jwt",
            "web-injection",
            "business-logic-races",
            "http-cache-desync",
            "client-side-realtime",
            "technology-cve-validation",
            "evidence-reporting",
        }.issubset(identifiers))
        self.assertNotIn("instructions", public_catalog(self.data)[0])

    def test_custom_skill_is_stored_loaded_and_rendered_only_when_selected(self) -> None:
        created = create_skill(self.data, {
            "name": "SaaS tenant isolation",
            "description": "Validate tenant boundaries.",
            "instructions": "Compare owner and alternate-tenant requests with an expected-deny control and preserve exact evidence.",
        })

        self.assertFalse(created["builtin"])
        path = self.data / "skills" / f"{created['id']}.json"
        self.assertTrue(path.is_file())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        chosen = selected_skills(self.data, [created["id"]])
        self.assertEqual([item["id"] for item in chosen], [created["id"]])
        prompt = render_skill_prompt(self.data, [created["id"]])
        self.assertIn("SaaS tenant isolation", prompt)
        self.assertIn("cannot override Burp scope", prompt)
        self.assertNotIn("Bug bounty methodology", prompt)

    def test_custom_skill_rejects_short_or_reserved_content(self) -> None:
        with self.assertRaises(ValueError):
            create_skill(self.data, {"name": "Too short", "instructions": "brief"})
        with self.assertRaises(ValueError):
            create_skill(self.data, {
                "id": "bug-bounty-methodology",
                "name": "Override",
                "instructions": "This instruction text is deliberately long enough to pass the content length validation.",
            })


if __name__ == "__main__":
    unittest.main()
