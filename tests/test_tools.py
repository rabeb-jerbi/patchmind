"""
tests/test_tools.py
Unit tests for the tool registry, base adapter, and normalized output.

Run from patchmind/ directory:
    python -m pytest tests/test_tools.py -v
"""
import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.base_tool import BaseTool, CATEGORY_SAST, CATEGORY_DEPENDENCY
from tools.tool_registry import ToolRegistry, _detect_languages, _has_docker, _has_iac


# ─── Minimal concrete tool for testing ───────────────────────────────────────

class _DummyTool(BaseTool):
    name        = "dummy"
    description = "Test tool"
    category    = CATEGORY_SAST
    supported_languages  = ["python"]
    supported_file_types = [".py"]

    def is_available(self) -> bool:
        return True

    def run(self, target_path):
        return {"ok": True, "output": '[{"type":"error","line":1,"path":"f.py","message":"oops","message-id":"E001"}]',
                "error": "", "duration": 0.1}

    def parse_output(self, raw_output):
        try:
            data = json.loads(raw_output)
        except Exception:
            return []
        return [self._normalize_finding(
            tool_name=self.name, category=self.category,
            severity="HIGH", cwe="CWE-123",
            file_path=d.get("path",""), line=d.get("line",0),
            message=d.get("message",""), raw=d
        ) for d in data]

    def normalize_result(self):
        pass


class _UnavailableTool(BaseTool):
    name        = "unavailable"
    description = "Not installed"
    category    = CATEGORY_DEPENDENCY
    supported_languages  = []
    supported_file_types = []

    def is_available(self):
        return False

    def run(self, target_path):
        return {"ok": False, "output": "", "error": "not found", "duration": 0}

    def parse_output(self, raw_output):
        return []

    def normalize_result(self):
        pass


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestNormalizeFinding(unittest.TestCase):

    def setUp(self):
        self.tool = _DummyTool()

    def test_normalized_keys(self):
        f = self.tool._normalize_finding(
            tool_name="dummy", category=CATEGORY_SAST,
            severity="high", cwe="CWE-79",
            file_path="app.py", line=42,
            message="XSS detected", recommendation="Escape output",
        )
        self.assertIn("tool", f)
        self.assertIn("severity", f)
        self.assertIn("cwe", f)
        self.assertIn("file", f)
        self.assertIn("line", f)
        self.assertIn("message", f)
        self.assertIn("recommendation", f)
        self.assertIn("raw", f)

    def test_severity_normalization(self):
        cases = [
            ("high",    "HIGH"),
            ("HIGH",    "HIGH"),
            ("warning", "MEDIUM"),
            ("critical","CRITICAL"),
            ("error",   "HIGH"),
            ("note",    "LOW"),
            ("blooper", "UNKNOWN"),
        ]
        for raw, expected in cases:
            f = self.tool._normalize_finding("t", "c", raw, "", "f.py", 0, "msg")
            self.assertEqual(f["severity"], expected, f"raw={raw!r}")

    def test_message_truncated(self):
        long_msg = "x" * 600
        f = self.tool._normalize_finding("t", "c", "high", "", "f.py", 0, long_msg)
        self.assertLessEqual(len(f["message"]), 500)

    def test_cache_key_deterministic(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tf:
            tf.write(b"print('hello')")
            path = tf.name
        try:
            k1 = self.tool._cache_key(path, "dummy")
            k2 = self.tool._cache_key(path, "dummy")
            self.assertEqual(k1, k2)
        finally:
            os.unlink(path)

    def test_cache_key_changes_with_tool_name(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tf:
            tf.write(b"x = 1")
            path = tf.name
        try:
            k1 = self.tool._cache_key(path, "toolA")
            k2 = self.tool._cache_key(path, "toolB")
            self.assertNotEqual(k1, k2)
        finally:
            os.unlink(path)


class TestValidatePath(unittest.TestCase):

    def test_valid_path(self):
        with tempfile.TemporaryDirectory() as ws:
            target = os.path.join(ws, "file.py")
            open(target, "w").close()
            result = _DummyTool._validate_path(target, ws)
            self.assertEqual(result, os.path.realpath(target))

    def test_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as ws:
            evil = os.path.join(ws, "..", "etc", "passwd")
            with self.assertRaises(ValueError):
                _DummyTool._validate_path(evil, ws)


class TestSafeRun(unittest.TestCase):

    def test_shell_false_enforced(self):
        """_safe_run must never use shell=True."""
        tool = _DummyTool()
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = b"ok"
            mock_proc.stderr = b""
            mock_run.return_value = mock_proc
            tool._safe_run(["echo", "hi"])
            _, kwargs = mock_run.call_args
            self.assertFalse(kwargs.get("shell", False))

    def test_missing_binary_returns_ok_false(self):
        tool = _DummyTool()
        result = tool._safe_run(["__nonexistent_binary_xyz__"])
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["error"])

    def test_output_truncated(self):
        from tools.base_tool import MAX_OUTPUT_BYTES
        tool = _DummyTool()
        big = b"A" * (MAX_OUTPUT_BYTES + 10_000)
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = big
            mock_proc.stderr = b""
            mock_run.return_value = mock_proc
            result = tool._safe_run(["echo"])
            self.assertLessEqual(len(result["output"]), MAX_OUTPUT_BYTES)


class TestToolRegistry(unittest.TestCase):

    def setUp(self):
        self.reg = ToolRegistry()
        self.reg.register(_DummyTool())
        self.reg.register(_UnavailableTool())

    def test_get_existing(self):
        t = self.reg.get("dummy")
        self.assertIsNotNone(t)
        self.assertEqual(t.name, "dummy")

    def test_get_missing(self):
        self.assertIsNone(self.reg.get("nonexistent"))

    def test_list_all_contains_both(self):
        names = [t["name"] for t in self.reg.list_all()]
        self.assertIn("dummy", names)
        self.assertIn("unavailable", names)

    def test_list_available_excludes_unavailable(self):
        names = [t["name"] for t in self.reg.list_available()]
        self.assertIn("dummy", names)
        self.assertNotIn("unavailable", names)

    def test_to_info_dict_has_available_key(self):
        info = self.reg.list_all()
        for t in info:
            self.assertIn("available", t)

    def test_recommend_python_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tf:
            tf.write(b"x = 1")
            path = tf.name
        try:
            self.reg.register(_DummyTool())  # bandit/pylint not registered; dummy is python
            recs = self.reg.recommend(path)
            # dummy supports python — should appear
            names = [r["name"] for r in recs]
            self.assertIn("dummy", names)
        finally:
            os.unlink(path)

    def test_run_tool_unavailable(self):
        result = self.reg.run_tool("unavailable", "/tmp", use_cache=False)
        self.assertFalse(result["ok"])

    def test_run_tool_unknown(self):
        result = self.reg.run_tool("ghost", "/tmp", use_cache=False)
        self.assertFalse(result["ok"])
        self.assertIn("Unknown", result["error"])

    def test_run_tool_path_traversal(self):
        with tempfile.TemporaryDirectory() as ws:
            evil = os.path.join(ws, "..", "etc")
            result = self.reg.run_tool("dummy", evil, workspace=ws, use_cache=False)
            self.assertFalse(result["ok"])
            self.assertIn("outside", result["error"])


class TestLanguageDetection(unittest.TestCase):

    def test_py_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tf:
            path = tf.name
        try:
            langs = _detect_languages(path)
            self.assertIn("python", langs)
        finally:
            os.unlink(path)

    def test_js_file(self):
        with tempfile.NamedTemporaryFile(suffix=".js", delete=False) as tf:
            path = tf.name
        try:
            self.assertIn("javascript", _detect_languages(path))
        finally:
            os.unlink(path)

    def test_dockerfile_detection(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "Dockerfile"), "w").close()
            self.assertTrue(_has_docker(d))

    def test_terraform_iac_detection(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "main.tf"), "w").close()
            self.assertTrue(_has_iac(d))


class TestParseOutput(unittest.TestCase):

    def test_parse_valid_json(self):
        tool = _DummyTool()
        raw = '[{"type":"error","line":5,"path":"app.py","message":"bad","message-id":"E001"}]'
        findings = tool.parse_output(raw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 5)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["tool"], "dummy")

    def test_parse_invalid_json(self):
        tool = _DummyTool()
        findings = tool.parse_output("not json at all {{{")
        self.assertEqual(findings, [])

    def test_parse_empty(self):
        tool = _DummyTool()
        findings = tool.parse_output("[]")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
