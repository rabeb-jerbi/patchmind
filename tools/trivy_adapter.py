"""tools/trivy_adapter.py — Trivy for containers and filesystems."""
import json
from typing import List, Dict, Any
from tools.base_tool import BaseTool, CATEGORY_CONTAINER


_SEV_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
            "MEDIUM": "MEDIUM", "LOW": "LOW", "UNKNOWN": "UNKNOWN"}


class TrivyTool(BaseTool):
    name        = "trivy"
    description = "Scan de vulnérabilités : images Docker, systèmes de fichiers, IaC."
    category    = CATEGORY_CONTAINER
    supported_languages  = []
    supported_file_types = [".dockerfile", ".yaml", ".yml", ".tf"]
    default_timeout      = 180
    install_hint         = "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"

    def is_available(self) -> bool:
        r = self._safe_run(["trivy", "--version"], timeout=10)
        return r["ok"] and r["returncode"] == 0

    def run(self, target_path: str) -> Dict[str, Any]:
        cmd = ["trivy", "fs", "--format", "json", "--quiet", target_path]
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

        for target in data.get("Results", []):
            target_file = target.get("Target", "")
            for vuln in target.get("Vulnerabilities") or []:
                cve_id = vuln.get("VulnerabilityID", "")
                findings.append(self._normalize_finding(
                    tool_name      = self.name,
                    category       = self.category,
                    severity       = vuln.get("Severity", "UNKNOWN"),
                    cwe            = vuln.get("CweIDs", [""])[0] if vuln.get("CweIDs") else "",
                    file_path      = target_file,
                    line           = 0,
                    message        = f"{cve_id}: {vuln.get('Title', vuln.get('Description','')[:120])}",
                    recommendation = vuln.get("FixedVersion", ""),
                    raw            = vuln,
                ))
            for mis in target.get("Misconfigurations") or []:
                findings.append(self._normalize_finding(
                    tool_name      = self.name,
                    category       = "IaC",
                    severity       = mis.get("Severity", "MEDIUM"),
                    cwe            = "",
                    file_path      = target_file,
                    line           = mis.get("CauseMetadata", {}).get("StartLine", 0),
                    message        = mis.get("Title", ""),
                    recommendation = mis.get("Resolution", ""),
                    raw            = mis,
                ))
        return findings

    def normalize_result(self) -> None:
        pass
