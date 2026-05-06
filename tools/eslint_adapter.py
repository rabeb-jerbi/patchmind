"""tools/eslint_adapter.py — ESLint for JavaScript/TypeScript."""
import json
import shutil
from typing import List, Dict, Any
from tools.base_tool import BaseTool, CATEGORY_SAST


_SEV_MAP = {1: "LOW", 2: "HIGH"}


class ESLintTool(BaseTool):
    name        = "eslint"
    description = "Analyse statique JavaScript/TypeScript — sécurité et qualité de code."
    category    = CATEGORY_SAST
    supported_languages  = ["javascript", "typescript"]
    supported_file_types = [".js", ".jsx", ".ts", ".tsx", ".mjs"]
    default_timeout      = 120

    def is_available(self) -> bool:
        return shutil.which("eslint") is not None

    def run(self, target_path: str) -> Dict[str, Any]:
        cmd = ["eslint", target_path, "-f", "json", "--no-error-on-unmatched-pattern"]
        result = self._safe_run(cmd)
        # ESLint exits 1 when it finds issues — that's still "ok" output
        result["ok"] = result["output"] != "" or result["returncode"] in (0, 1)
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

        for file_result in data:
            fpath = file_result.get("filePath", "")
            for msg in file_result.get("messages", []):
                rule = msg.get("ruleId") or ""
                # Map security-related ESLint rules to rough CWEs
                cwe = _rule_to_cwe(rule)
                severity_num = msg.get("severity", 1)
                findings.append(self._normalize_finding(
                    tool_name      = self.name,
                    category       = self.category,
                    severity       = _SEV_MAP.get(severity_num, "MEDIUM"),
                    cwe            = cwe,
                    file_path      = fpath,
                    line           = msg.get("line", 0),
                    message        = f"[{rule}] {msg.get('message','')}",
                    recommendation = msg.get("suggestions", [{}])[0].get("desc", "") if msg.get("suggestions") else "",
                    raw            = msg,
                ))
        return findings

    def normalize_result(self) -> None:
        pass


def _rule_to_cwe(rule: str) -> str:
    _map = {
        "no-eval":               "CWE-95",
        "no-new-func":           "CWE-95",
        "no-script-url":         "CWE-79",
        "no-unsafe-innerhtml":   "CWE-79",
        "no-sql-injection":      "CWE-89",
        "security/detect-eval-with-expression": "CWE-95",
        "security/detect-non-literal-regexp":   "CWE-1333",
        "security/detect-object-injection":     "CWE-94",
        "security/detect-possible-timing-attacks": "CWE-208",
    }
    return _map.get(rule, "")
