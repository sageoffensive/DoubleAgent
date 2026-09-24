import os
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / "burp" / "DoubleAgent.py"
BURP_SRC = ROOT / "burp" / "src"


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

    def test_only_one_public_burp_loader(self):
        self.assertEqual(
            [path.name for path in (ROOT / "burp").glob("*.py")],
            ["DoubleAgent.py"],
        )
        self.assertTrue((BURP_SRC / "double_agent_prelude.py").is_file())


if __name__ == "__main__":
    unittest.main()
