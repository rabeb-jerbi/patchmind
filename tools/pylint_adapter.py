"""tools/pylint_adapter.py — Pylint for Python code quality."""
import json
import sys
from typing import List, Dict, Any
from tools.base_tool import BaseTool, CATEGORY_LINT


_TYPE_SEV = {"error": "HIGH", "warning": "MEDIUM", "refactor": "LOW",
             "convention": "INFO", "fatal": "CRITICAL"}


class PylintTool(BaseTool):
    name        = "pylint"
    description = "Détection d'erreurs Python et qualité de code (PEP8, bugs, variables non utilisées…)."
    category    = CATEGORY_LINT
    supported_languages  = ["python"]
    supported_file_types = [".py"]
    default_timeout      = 120
    install_hint         = "pip install pylint"

    def is_available(self) -> bool:
        r = self._safe_run([sys.executable, "-m", "pylint", "--version"], timeout=10)
        return r["ok"] and r["returncode"] == 0

    def run(self, target_path: str) -> Dict[str, Any]:
        cmd = [
            sys.executable, "-m", "pylint",
            target_path,
            "--output-format=json",
            "--disable=C,R",          # skip convention+refactor — keep errors+warnings
            "--score=no",
        ]
        result = self._safe_run(cmd)
        # Pylint exits 0 (clean), 1-32 (issues found) — all are valid output
        result["ok"] = result["output"].strip().startswith("[") or result["returncode"] == 0
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

        for msg in data:
            msg_type = msg.get("type", "warning")
            # Skip convention/refactor noise
            if msg_type in ("convention", "refactor"):
                continue
            findings.append(self._normalize_finding(
                tool_name      = self.name,
                category       = self.category,
                severity       = _TYPE_SEV.get(msg_type, "MEDIUM"),
                cwe            = "",
                file_path      = msg.get("path", ""),
                line           = msg.get("line", 0),
                message        = f"[{msg.get('message-id','')}] {msg.get('message','')}",
                recommendation = msg.get("symbol", ""),
                raw            = msg,
            ))
        return findings

    def normalize_result(self) -> None:
        pass
