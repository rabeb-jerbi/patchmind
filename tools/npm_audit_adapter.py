"""tools/npm_audit_adapter.py — npm audit for JavaScript dependencies."""
import json
import shutil
import os
from typing import List, Dict, Any
from tools.base_tool import BaseTool, CATEGORY_DEPENDENCY


_SEV_NPM = {"critical": "CRITICAL", "high": "HIGH",
            "moderate": "MEDIUM",   "low": "LOW", "info": "INFO"}


class NpmAuditTool(BaseTool):
    name        = "npm_audit"
    description = "Audit des dépendances npm — CVE et vulnérabilités connues."
    category    = CATEGORY_DEPENDENCY
    supported_languages  = ["javascript", "typescript"]
    supported_file_types = ["package.json"]
    default_timeout      = 120

    def is_available(self) -> bool:
        return shutil.which("npm") is not None

    def run(self, target_path: str) -> Dict[str, Any]:
        # npm audit must run in the directory that contains package.json
        if os.path.isfile(target_path):
            cwd = os.path.dirname(target_path)
        elif os.path.isdir(target_path):
            cwd = target_path
        else:
            return {"ok": False, "error": "Invalid target path", "findings": []}

        cmd = ["npm", "audit", "--json"]
        result = self._safe_run(cmd, cwd=cwd)
        # npm audit exits 1 when vulnerabilities found — output is still valid JSON
        result["ok"] = bool(result["output"])
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

        # npm audit v7+ format
        vulns = data.get("vulnerabilities", {})
        for pkg_name, info in vulns.items():
            severity = info.get("severity", "unknown")
            for via in info.get("via", []):
                if not isinstance(via, dict):
                    continue
                cwe_list = via.get("cwe", [])
                cwe = cwe_list[0] if cwe_list else ""
                findings.append(self._normalize_finding(
                    tool_name      = self.name,
                    category       = self.category,
                    severity       = _SEV_NPM.get(severity, "UNKNOWN"),
                    cwe            = cwe,
                    file_path      = "package.json",
                    line           = 0,
                    message        = f"{pkg_name}: {via.get('title', via.get('url', ''))}",
                    recommendation = f"Fix available: {info.get('fixAvailable', False)}",
                    raw            = {"pkg": pkg_name, "via": via},
                ))
        return findings

    def normalize_result(self) -> None:
        pass
