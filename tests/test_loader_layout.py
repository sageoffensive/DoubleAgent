import os
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / "agent_A_burp" / "DoubleAgent.py"
BURP_SRC = ROOT / "agent_A_burp" / "src"


class LoaderLayoutTests(unittest.TestCase):
    def test_public_loader_finds_private_source_folder(self):
        source = LOADER.read_text()
        bootstrap = source.split(
            "# Burp reloads an extension inside the SAME Jython interpreter",
            1,
        )[0]
        namespace = {"__file__": str(LOADER)}
        exec(compile(bootstrap, str(LOADER), "exec"), namespace)
        self.assertEqual(
            os.path.realpath(namespace["_extension_directory"]),
            os.path.realpath(BURP_SRC),
        )

    def test_configured_directory_without_loader_filename(self):
        bootstrap = LOADER.read_text().split(
            "# Burp reloads an extension inside the SAME Jython interpreter", 1,
        )[0]
        for directory in (ROOT, ROOT / "agent_A_burp", BURP_SRC):
            with self.subTest(directory=directory):
                namespace = {}
                with mock.patch.dict(os.environ, {"DOUBLE_AGENT_EXTENSION_DIR": str(directory)}), mock.patch("sys.path", []):
                    exec(compile(bootstrap, "<burp-loader>", "exec"), namespace)
                self.assertEqual(
                    os.path.realpath(namespace["_extension_directory"]),
                    os.path.realpath(BURP_SRC),
                )

    def test_only_one_public_burp_loader(self):
        self.assertEqual(
            [path.name for path in (ROOT / "agent_A_burp").glob("*.py")],
            ["DoubleAgent.py"],
        )
        self.assertTrue((BURP_SRC / "double_agent_prelude.py").is_file())


if __name__ == "__main__":
    unittest.main()
