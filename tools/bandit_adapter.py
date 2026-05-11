"""tools/bandit_adapter.py — Bandit SAST for Python."""
import json
import sys
import os
from typing import List, Dict, Any
from tools.base_tool import BaseTool, CATEGORY_SAST


class BanditTool(BaseTool):
    name        = "bandit"
    description = "Analyse statique de sécurité Python — détecte injections, crypto faible, XSS, etc."
    category    = CATEGORY_SAST
    supported_languages  = ["python"]
    supported_file_types = [".py"]
    default_timeout      = 120
    install_hint         = "pip install bandit"

    def is_available(self) -> bool:
        r = self._safe_run([sys.executable, "-m", "bandit", "--version"], timeout=10)
        return r["ok"] and r["returncode"] == 0

    def run(self, target_path: str) -> Dict[str, Any]:
        cmd = [sys.executable, "-m", "bandit", "-r", target_path, "-f", "json", "-q"]
        result = self._safe_run(cmd)
        if result["ok"]:
            result["findings"] = self.parse_output(result["output"])
        else:
            result["findings"] = []
        return result

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            data = json.loads(raw_output)
        except (json.JSONDecodeError, ValueError):
            return findings

        for r in data.get("results", []):
            issue = r.get("issue_text", "")
            cwe_raw = r.get("issue_cwe", {})
            cwe = f"CWE-{cwe_raw.get('id', '')}" if isinstance(cwe_raw, dict) else str(cwe_raw)
            findings.append(self._normalize_finding(
                tool_name      = self.name,
                category       = self.category,
                severity       = r.get("issue_severity", "MEDIUM"),
                cwe            = cwe,
                file_path      = r.get("filename", ""),
                line           = r.get("line_number", 0),
                message        = issue,
                recommendation = r.get("more_info", ""),
                raw            = r,
            ))
        return findings

    def normalize_result(self) -> None:
        pass  # normalization done inside parse_output
