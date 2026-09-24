from __future__ import annotations

import unittest

from agent_b_harness.config import Config, resolve_model_connection


class ConfigTests(unittest.TestCase):
    def test_public_settings_expose_model_choices_without_secret(self) -> None:
        value = Config(model_api_key="secret").public()
        self.assertNotIn("model_api_key", value)
        self.assertTrue(value["model_api_key_set"])
        self.assertEqual([option["id"] for option in value["model_options"]], [])
        self.assertEqual(value["selected_skills"], ("bug-bounty-methodology",))

    def test_saved_connections_keep_provider_and_secret_private(self) -> None:
        cfg = Config(model="custom-claude", custom_models=({
            "id": "custom-claude",
            "label": "Claude direct",
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "url": "https://api.anthropic.com/v1",
            "api_key": "secret-anthropic-key",
            "region": "",
        },))

        public = cfg.public()
        option = next(item for item in public["model_options"] if item["id"] == "custom-claude")
        self.assertEqual(option["provider"], "anthropic")
        self.assertTrue(option["api_key_set"])
        self.assertNotIn("api_key", option)
        self.assertNotIn("secret-anthropic-key", str(public))
        resolved = resolve_model_connection(cfg)
        self.assertEqual(resolved["provider"], "anthropic")
        self.assertEqual(resolved["api_key"], "secret-anthropic-key")

    def test_bedrock_connection_resolves_regional_runtime_endpoint(self) -> None:
        cfg = Config(model="custom-bedrock", custom_models=({
            "id": "custom-bedrock",
            "label": "Bedrock Nova",
            "provider": "bedrock",
            "model": "amazon.nova-2-lite-v1:0",
            "url": "",
            "api_key": "ABSK-test",
            "region": "ap-southeast-2",
        },))

        resolved = resolve_model_connection(cfg)
        self.assertEqual(resolved["provider"], "bedrock")
        self.assertEqual(resolved["base_url"], "https://bedrock-runtime.ap-southeast-2.amazonaws.com")

    def test_connection_credentials_are_isolated_but_legacy_entries_migrate(self) -> None:
        isolated = Config(model_api_key="legacy-key", model="new-local", custom_models=({
            "id": "new-local", "label": "No auth local", "provider": "openai_compatible",
            "model": "local-model", "url": "http://127.0.0.1:8000/v1", "api_key": "",
        },))
        legacy = Config(model_api_key="legacy-key", model="old-local", custom_models=({
            "id": "old-local", "label": "Old local", "model": "local-model",
            "url": "http://127.0.0.1:8000/v1", "inherit_legacy_key": True,
        },))

        self.assertEqual(resolve_model_connection(isolated)["api_key"], "")
        self.assertEqual(resolve_model_connection(legacy)["api_key"], "legacy-key")


if __name__ == "__main__":
    unittest.main()
