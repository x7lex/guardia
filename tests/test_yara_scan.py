import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from backend.yara_scan import inspect_yara


class YaraTests(unittest.TestCase):
    def test_disabled_rules_do_not_scan(self):
        with patch.dict(os.environ, {"YARA_RULES_PATH": ""}):
            self.assertEqual(inspect_yara("unused")["status"], "disabled")

    def test_configured_rules_use_static_file_match_with_timeout_and_rule_digest(self):
        match = SimpleNamespace(rule="test", namespace="default", tags=[], meta={"malware": True, "confidence": "high"})
        rules = Mock()
        rules.match.return_value = [match]
        module = Mock()
        module.compile.return_value = rules
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.yar"
            path.write_text("rule example { condition: true }")
            with patch.dict(os.environ, {"YARA_RULES_PATH": str(path)}), patch.dict(sys.modules, {"yara": module}):
                result = inspect_yara("sample.exe")
                self.assertEqual(result["status"], "complete")
                self.assertEqual(len(result["rules_sha256"]), 64)
                self.assertTrue(result["matches"][0]["meta"]["malware"])
                module.compile.assert_called_once_with(source=path.read_text(), includes=False)
                rules.match.assert_called_once_with(filepath="sample.exe", timeout=5)
                rules.match.side_effect = RuntimeError("failure")
                self.assertEqual(inspect_yara("sample.exe")["status"], "unavailable")
