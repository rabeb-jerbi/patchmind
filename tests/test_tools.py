"""
tests/test_tools.py
Tests for the tool registry, base adapter, and all 7 tool adapters.
All subprocess calls are mocked — no real tools required.
"""
import os
import sys
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.base_tool import BaseTool, CATEGORY_SAST, CATEGORY_DEPENDENCY, CATEGORY_LINT
from tools.tool_registry import ToolRegistry, _detect_languages, _has_docker, _has_iac


# ─── Minimal concrete tool for testing ───────────────────────────────────────

class _DummyTool(BaseTool):
    name = "dummy"
    description = "Test tool"
    category = CATEGORY_SAST
    supported_languages = ["python"]
    supported_file_types = [".py"]

    def is_available(self):
        return True

    def run(self, target_path):
        return {"ok": True, "output": "[]", "error": "", "duration": 0.1}

    def parse_output(self, raw):
        try:
            data = json.loads(raw)
        except Exception:
            return []
        return [self._normalize_finding(
            self.name, self.category, "HIGH", "CWE-123",
            d.get("path", ""), d.get("line", 0), d.get("message", ""),
        ) for d in data]

    def normalize_result(self):
        pass


class _UnavailableTool(BaseTool):
    name = "unavail"
    description = "Not installed"
    category = CATEGORY_DEPENDENCY
    supported_languages = []
    supported_file_types = []

    def is_available(self): return False
    def run(self, p): return {"ok": False, "output": "", "error": "not found", "duration": 0}
    def parse_output(self, r): return []
    def normalize_result(self): pass


# ─── _normalize_finding ───────────────────────────────────────────────────────

class TestNormalizeFinding:
    tool = _DummyTool()

    def test_all_keys_present(self):
        f = self.tool._normalize_finding("t", "SAST", "HIGH", "CWE-79", "f.py", 1, "msg")
        for k in ("tool", "category", "severity", "cwe", "file", "line", "message",
                  "recommendation", "raw"):
            assert k in f

    @pytest.mark.parametrize("raw,expected", [
        ("high", "HIGH"), ("HIGH", "HIGH"), ("warning", "MEDIUM"),
        ("critical", "CRITICAL"), ("error", "HIGH"), ("note", "LOW"),
        ("info", "LOW"), ("blooper", "UNKNOWN"),
    ])
    def test_severity_normalisation(self, raw, expected):
        f = self.tool._normalize_finding("t", "c", raw, "", "f.py", 0, "m")
        assert f["severity"] == expected

    def test_message_truncated_at_500(self):
        f = self.tool._normalize_finding("t", "c", "high", "", "f.py", 0, "x" * 600)
        assert len(f["message"]) <= 500

    def test_recommendation_truncated_at_300(self):
        f = self.tool._normalize_finding("t", "c", "low", "", "f.py", 0, "m", "r" * 400)
        assert len(f["recommendation"]) <= 300


# ─── _cache_key ───────────────────────────────────────────────────────────────

class TestCacheKey:
    tool = _DummyTool()

    def test_deterministic_for_file(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_bytes(b"print('hello')")
        k1 = self.tool._cache_key(str(p), "dummy")
        k2 = self.tool._cache_key(str(p), "dummy")
        assert k1 == k2

    def test_differs_by_tool_name(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_bytes(b"x = 1")
        assert self.tool._cache_key(str(p), "A") != self.tool._cache_key(str(p), "B")

    def test_differs_when_file_changes(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_bytes(b"x = 1")
        k1 = self.tool._cache_key(str(p), "dummy")
        p.write_bytes(b"x = 2")
        k2 = self.tool._cache_key(str(p), "dummy")
        assert k1 != k2

    def test_directory_key(self, tmp_path):
        (tmp_path / "a.py").write_bytes(b"a=1")
        k = self.tool._cache_key(str(tmp_path), "dummy")
        assert len(k) == 32


# ─── _validate_path ───────────────────────────────────────────────────────────

class TestValidatePath:
    def test_valid_path_returned(self, tmp_path):
        f = tmp_path / "f.py"
        f.touch()
        result = _DummyTool._validate_path(str(f), str(tmp_path))
        assert result == os.path.realpath(str(f))

    def test_traversal_rejected(self, tmp_path):
        evil = str(tmp_path / ".." / "etc" / "passwd")
        with pytest.raises(ValueError, match="outside"):
            _DummyTool._validate_path(evil, str(tmp_path))

    def test_workspace_itself_accepted(self, tmp_path):
        result = _DummyTool._validate_path(str(tmp_path), str(tmp_path))
        assert result == os.path.realpath(str(tmp_path))


# ─── _safe_run ────────────────────────────────────────────────────────────────

class TestSafeRun:
    tool = _DummyTool()

    def test_shell_false_enforced(self):
        mock_proc = MagicMock(returncode=0, stdout=b"ok", stderr=b"")
        with patch("subprocess.run", return_value=mock_proc) as m:
            self.tool._safe_run(["echo", "hi"])
            _, kw = m.call_args
            assert kw.get("shell", False) is False

    def test_missing_binary_returns_ok_false(self):
        r = self.tool._safe_run(["__nonexistent_bin_xyz_123__"])
        assert r["ok"] is False
        assert "not found" in r["error"]

    def test_timeout_returns_ok_false(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 1)):
            r = self.tool._safe_run(["sleep", "99"], timeout=1)
        assert r["ok"] is False

    def test_output_capped(self):
        from tools.base_tool import MAX_OUTPUT_BYTES
        big = b"A" * (MAX_OUTPUT_BYTES + 5000)
        mock_proc = MagicMock(returncode=0, stdout=big, stderr=b"")
        with patch("subprocess.run", return_value=mock_proc):
            r = self.tool._safe_run(["echo"])
        assert len(r["output"]) <= MAX_OUTPUT_BYTES

    def test_duration_returned(self):
        mock_proc = MagicMock(returncode=0, stdout=b"", stderr=b"")
        with patch("subprocess.run", return_value=mock_proc):
            r = self.tool._safe_run(["echo"])
        assert "duration" in r
        assert r["duration"] >= 0


# ─── ToolRegistry ────────────────────────────────────────────────────────────

class TestToolRegistry:
    def _reg(self):
        r = ToolRegistry()
        r.register(_DummyTool())
        r.register(_UnavailableTool())
        return r

    def test_get_registered(self):
        assert self._reg().get("dummy") is not None

    def test_get_unregistered_returns_none(self):
        assert self._reg().get("ghost") is None

    def test_list_all_returns_both(self):
        names = {t["name"] for t in self._reg().list_all()}
        assert "dummy" in names
        assert "unavail" in names

    def test_list_available_excludes_unavailable(self):
        names = {t["name"] for t in self._reg().list_available()}
        assert "dummy" in names
        assert "unavail" not in names

    def test_to_info_dict_has_available(self):
        for t in self._reg().list_all():
            assert "available" in t

    def test_run_unknown_tool_returns_error(self):
        r = self._reg().run_tool("ghost", "/tmp", use_cache=False)
        assert r["ok"] is False
        assert "Unknown" in r["error"]

    def test_run_unavailable_tool_returns_error(self):
        r = self._reg().run_tool("unavail", "/tmp", use_cache=False)
        assert r["ok"] is False

    def test_run_traversal_path_rejected(self, tmp_path):
        evil = str(tmp_path / ".." / "etc")
        r = self._reg().run_tool("dummy", evil, workspace=str(tmp_path), use_cache=False)
        assert r["ok"] is False
        assert "outside" in r["error"]

    def test_recommend_python_project(self, tmp_path):
        (tmp_path / "app.py").write_bytes(b"x=1")
        r = ToolRegistry()
        r.register(_DummyTool())
        recs = r.recommend(str(tmp_path))
        names = [rec["name"] for rec in recs]
        assert "dummy" in names

    def test_recommend_returns_reason(self, tmp_path):
        (tmp_path / "app.py").write_bytes(b"x=1")
        r = ToolRegistry()
        r.register(_DummyTool())
        recs = r.recommend(str(tmp_path))
        for rec in recs:
            assert "reason" in rec


# ─── Language / file detection ────────────────────────────────────────────────

class TestDetection:
    def test_py_detected(self, tmp_path):
        (tmp_path / "f.py").touch()
        assert "python" in _detect_languages(str(tmp_path / "f.py"))

    def test_js_detected(self, tmp_path):
        (tmp_path / "f.js").touch()
        assert "javascript" in _detect_languages(str(tmp_path / "f.js"))

    def test_ts_detected(self, tmp_path):
        (tmp_path / "f.ts").touch()
        assert "typescript" in _detect_languages(str(tmp_path / "f.ts"))

    def test_dockerfile_detected(self, tmp_path):
        (tmp_path / "Dockerfile").touch()
        assert _has_docker(str(tmp_path))

    def test_terraform_detected(self, tmp_path):
        (tmp_path / "main.tf").touch()
        assert _has_iac(str(tmp_path))

    def test_no_docker_in_empty_dir(self, tmp_path):
        assert not _has_docker(str(tmp_path))


# ─── Adapter output parsing ───────────────────────────────────────────────────

class TestBanditAdapter:
    def test_parse_valid_output(self):
        from tools.bandit_adapter import BanditTool
        t = BanditTool()
        raw = json.dumps({"results": [
            {"filename": "app.py", "line_number": 5, "issue_severity": "HIGH",
             "issue_confidence": "HIGH", "issue_text": "Use of exec",
             "test_id": "B102", "issue_cwe": {"id": 78, "link": ""}},
        ]})
        findings = t.parse_output(raw)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["line"] == 5

    def test_parse_empty_results(self):
        from tools.bandit_adapter import BanditTool
        findings = BanditTool().parse_output(json.dumps({"results": []}))
        assert findings == []

    def test_parse_invalid_json(self):
        from tools.bandit_adapter import BanditTool
        assert BanditTool().parse_output("not json") == []


class TestPylintAdapter:
    def test_parse_valid_output(self):
        from tools.pylint_adapter import PylintTool
        raw = json.dumps([{
            "type": "error", "module": "app", "path": "app.py",
            "line": 10, "message-id": "E0001", "message": "undefined name",
            "symbol": "undefined-variable"
        }])
        findings = PylintTool().parse_output(raw)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_convention_messages_skipped(self):
        from tools.pylint_adapter import PylintTool
        raw = json.dumps([{
            "type": "convention", "module": "m", "path": "m.py",
            "line": 1, "message-id": "C0114", "message": "Missing docstring",
            "symbol": "missing-module-docstring"
        }])
        # convention is skipped in parse_output
        findings = PylintTool().parse_output(raw)
        assert findings == []


class TestNpmAuditAdapter:
    def test_parse_v7_output(self):
        from tools.npm_audit_adapter import NpmAuditTool
        raw = json.dumps({"vulnerabilities": {
            "lodash": {
                "severity": "high",
                "fixAvailable": True,
                "via": [{"title": "Prototype Pollution", "cwe": ["CWE-1321"],
                          "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-8203"}]
            }
        }})
        findings = NpmAuditTool().parse_output(raw)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_parse_empty(self):
        from tools.npm_audit_adapter import NpmAuditTool
        assert NpmAuditTool().parse_output(json.dumps({"vulnerabilities": {}})) == []


class TestEslintAdapter:
    def test_parse_valid_output(self):
        from tools.eslint_adapter import ESLintTool
        raw = json.dumps([{"filePath": "/app/src/index.js", "messages": [
            {"ruleId": "no-eval", "severity": 2, "message": "eval is dangerous",
             "line": 3, "column": 1}
        ]}])
        findings = ESLintTool().parse_output(raw)
        assert len(findings) == 1
        assert findings[0]["file"].endswith("index.js")

    def test_parse_no_messages(self):
        from tools.eslint_adapter import ESLintTool
        raw = json.dumps([{"filePath": "/f.js", "messages": []}])
        assert ESLintTool().parse_output(raw) == []


class TestPipAuditAdapter:
    def test_parse_valid_output(self):
        from tools.pip_audit_adapter import PipAuditTool
        raw = json.dumps({"dependencies": [
            {"name": "requests", "version": "2.25.0", "vulns": [
                {"id": "PYSEC-2023-74", "description": "SSRF",
                 "aliases": ["CVE-2023-32681"],
                 "fix_versions": ["2.31.0"]}
            ]}
        ]})
        findings = PipAuditTool().parse_output(raw)
        assert len(findings) == 1
        assert "requests" in findings[0]["message"]

    def test_no_vulns_empty(self):
        from tools.pip_audit_adapter import PipAuditTool
        raw = json.dumps({"dependencies": [
            {"name": "flask", "version": "3.0.0", "vulns": []}
        ]})
        assert PipAuditTool().parse_output(raw) == []


class TestTrivyAdapter:
    def test_parse_valid_output(self, tmp_path):
        from tools.trivy_adapter import TrivyTool
        raw = json.dumps({"Results": [
            {"Target": "Dockerfile", "Type": "dockerfile",
             "Vulnerabilities": [
                 {"VulnerabilityID": "CVE-2023-0001",
                  "PkgName": "openssl", "InstalledVersion": "1.1.1",
                  "Severity": "CRITICAL", "Title": "Buffer overflow",
                  "Description": "A buffer overflow..."}
             ]}
        ]})
        findings = TrivyTool().parse_output(raw)
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_parse_no_results(self):
        from tools.trivy_adapter import TrivyTool
        assert TrivyTool().parse_output(json.dumps({"Results": []})) == []


class TestCheckovAdapter:
    def test_parse_valid_output(self):
        from tools.checkov_adapter import CheckovTool
        raw = json.dumps({"results": {"failed_checks": [
            {"check_id": "CKV_AWS_18", "check_type": "terraform",
             "resource": "aws_s3_bucket.example",
             "check_result": {"result": "FAILED"},
             "file_path": "main.tf", "file_line_range": [1, 5],
             "check": {"name": "S3 Bucket not encrypted",
                       "guideline": "https://docs.aws.amazon.com/..."}}
        ]}})
        findings = CheckovTool().parse_output(raw)
        assert len(findings) == 1
        assert "CKV" in findings[0]["message"] or "S3" in findings[0]["message"]

    def test_parse_no_failures(self):
        from tools.checkov_adapter import CheckovTool
        raw = json.dumps({"results": {"failed_checks": []}})
        assert CheckovTool().parse_output(raw) == []


# ─── registry module-level singleton ─────────────────────────────────────────

def test_global_registry_is_populated():
    from tools.tool_registry import registry
    tools = registry.list_all()
    assert len(tools) >= 7
    names = {t["name"] for t in tools}
    for name in ("bandit", "trivy", "checkov", "pip_audit", "eslint", "pylint", "npm_audit"):
        assert name in names


def test_global_registry_recommendation_python(tmp_path):
    from tools.tool_registry import registry
    (tmp_path / "app.py").write_bytes(b"x = 1")
    recs = registry.recommend(str(tmp_path))
    names = [r["name"] for r in recs]
    assert "bandit" in names or "pylint" in names


def test_global_registry_recommendation_js(tmp_path):
    from tools.tool_registry import registry
    (tmp_path / "app.js").write_bytes(b"const x = 1;")
    recs = registry.recommend(str(tmp_path))
    names = [r["name"] for r in recs]
    assert "eslint" in names or "npm_audit" in names


def test_global_registry_recommendation_dockerfile(tmp_path):
    from tools.tool_registry import registry
    (tmp_path / "Dockerfile").write_bytes(b"FROM ubuntu:20.04")
    recs = registry.recommend(str(tmp_path))
    names = [r["name"] for r in recs]
    assert "trivy" in names


def test_global_registry_recommendation_terraform(tmp_path):
    from tools.tool_registry import registry
    (tmp_path / "main.tf").write_bytes(b"resource \"aws_s3_bucket\" \"b\" {}")
    recs = registry.recommend(str(tmp_path))
    names = [r["name"] for r in recs]
    assert "checkov" in names or "trivy" in names
