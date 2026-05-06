"""tools/pip_audit_adapter.py — pip-audit for Python dependency CVEs."""
import json
import sys
from typing import List, Dict, Any
from tools.base_tool import BaseTool, CATEGORY_DEPENDENCY


class PipAuditTool(BaseTool):
    name        = "pip_audit"
    description = "Audit des dépendances Python — CVE via PyPI Advisory Database."
    category    = CATEGORY_DEPENDENCY
    supported_languages  = ["python"]
    supported_file_types = [".txt", ".toml", ".cfg"]
    default_timeout      = 120

    def is_available(self) -> bool:
        r = self._safe_run([sys.executable, "-m", "pip_audit", "--version"], timeout=10)
        return r["ok"] and r["returncode"] == 0

    def run(self, target_path: str) -> Dict[str, Any]:
        import os
        # If target_path is a requirements.txt run against it, else scan the dir
        if os.path.isfile(target_path) and target_path.endswith(".txt"):
            cmd = [sys.executable, "-m", "pip_audit", "-r", target_path, "-f", "json"]
        else:
            cmd = [sys.executable, "-m", "pip_audit", "-f", "json"]
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

        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                cwe = ""
                for alias in vuln.get("aliases", []):
                    if alias.upper().startswith("CWE"):
                        cwe = alias; break
                findings.append(self._normalize_finding(
                    tool_name      = self.name,
                    category       = self.category,
                    severity       = "HIGH",
                    cwe            = cwe,
                    file_path      = "requirements.txt",
                    line           = 0,
                    message        = f"{dep.get('name')} {dep.get('version')}: {vuln.get('id','')} — {vuln.get('description','')[:150]}",
                    recommendation = f"Fix version: {vuln.get('fix_versions', ['?'])[0] if vuln.get('fix_versions') else 'unknown'}",
                    raw            = {**dep, "vuln": vuln},
                ))
        return findings

    def normalize_result(self) -> None:
        pass
