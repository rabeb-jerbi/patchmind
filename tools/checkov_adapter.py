"""tools/checkov_adapter.py — Checkov IaC scanner."""
import json
import sys
from typing import List, Dict, Any
from tools.base_tool import BaseTool, CATEGORY_IAC


class CheckovTool(BaseTool):
    name        = "checkov"
    description = "Analyse IaC : Terraform, Kubernetes, CloudFormation, Dockerfile."
    category    = CATEGORY_IAC
    supported_languages  = ["terraform", "yaml"]
    supported_file_types = [".tf", ".hcl", ".yaml", ".yml", ".json"]
    default_timeout      = 120

    def is_available(self) -> bool:
        r = self._safe_run([sys.executable, "-m", "checkov", "--version"], timeout=10)
        return r["ok"] and r["returncode"] == 0

    def run(self, target_path: str) -> Dict[str, Any]:
        cmd = [sys.executable, "-m", "checkov", "-d", target_path,
               "-o", "json", "--quiet"]
        result = self._safe_run(cmd)
        if result["ok"]:
            result["findings"] = self.parse_output(result["output"])
        else:
            result["findings"] = []
        return result

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        findings = []
        # checkov may output multiple JSON objects when multiple frameworks run
        raw_output = raw_output.strip()
        if not raw_output:
            return findings
        # Take the first valid JSON object
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            # Try to extract first {...}
            start = raw_output.find("{")
            if start == -1:
                return findings
            try:
                data = json.loads(raw_output[start:])
            except json.JSONDecodeError:
                return findings

        results = data if isinstance(data, list) else [data]
        for block in results:
            for check in block.get("results", {}).get("failed_checks", []):
                findings.append(self._normalize_finding(
                    tool_name      = self.name,
                    category       = self.category,
                    severity       = check.get("check_result", {}).get("result", "FAILED"),
                    cwe            = "",
                    file_path      = check.get("repo_file_path", check.get("file_path", "")),
                    line           = check.get("file_line_range", [0])[0] if check.get("file_line_range") else 0,
                    message        = f"[{check.get('check_id','')}] {check.get('check','').get('name','')}",
                    recommendation = check.get("guideline", ""),
                    raw            = check,
                ))
        return findings

    def normalize_result(self) -> None:
        pass
