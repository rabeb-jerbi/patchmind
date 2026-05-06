"""
tools/tool_registry.py
Central registry for all tool adapters.  Handles discovery, recommendation,
and safe execution with result caching backed by the ToolExecution DB table.
"""
import os
import time
from typing import Dict, List, Optional, Any

from tools.base_tool import BaseTool

# File-type → language heuristic map
_EXT_LANG: Dict[str, str] = {
    ".py":   "python",  ".pyw": "python",
    ".js":   "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts":   "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go":   "go",
    ".rb":   "ruby",
    ".php":  "php",
    ".rs":   "rust",
    ".c":    "c",      ".cpp": "cpp",   ".h": "c",
    ".tf":   "terraform", ".hcl": "terraform",
    ".yaml": "yaml",   ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
}

_DOCKER_NAMES = {"dockerfile", "dockerfile.dev", "dockerfile.prod"}

# Recommendation reasons
_REASONS: Dict[str, str] = {
    "bandit":    "Analyse statique de sécurité Python (injection, crypto faible, etc.)",
    "pylint":    "Détection d'erreurs et qualité de code Python",
    "pip_audit": "Audit des dépendances Python pour les CVE connues",
    "eslint":    "Analyse statique JavaScript/TypeScript (sécurité + qualité)",
    "npm_audit": "Audit des dépendances npm pour les vulnérabilités connues",
    "trivy":     "Scan de vulnérabilités : images Docker, systèmes de fichiers",
    "checkov":   "Analyse IaC : Terraform, Kubernetes, CloudFormation",
}


class ToolRegistry:
    """Singleton registry — access via `registry` module-level instance."""

    def __init__(self) -> None:
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_all(self) -> List[Dict[str, Any]]:
        return [t.to_info_dict() for t in self._tools.values()]

    def list_available(self) -> List[Dict[str, Any]]:
        return [t.to_info_dict() for t in self._tools.values() if t.is_available()]

    def recommend(self, target_path: str) -> List[Dict[str, Any]]:
        """
        Inspect *target_path* (file or directory) and return a prioritised list
        of tools with a recommendation reason.
        """
        langs   = _detect_languages(target_path)
        has_docker = _has_docker(target_path)
        has_iac    = _has_iac(target_path)

        recs: List[Dict[str, Any]] = []

        def _add(name: str):
            t = self._tools.get(name)
            if t:
                recs.append({
                    **t.to_info_dict(),
                    "reason": _REASONS.get(name, ""),
                })

        if "python" in langs:
            _add("bandit"); _add("pylint"); _add("pip_audit")
        if "javascript" in langs or "typescript" in langs:
            _add("eslint"); _add("npm_audit")
        if has_docker:
            _add("trivy")
        if has_iac:
            _add("checkov"); _add("trivy")

        # De-duplicate while preserving order
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for r in recs:
            if r["name"] not in seen:
                seen.add(r["name"]); unique.append(r)
        return unique

    def run_tool(self, name: str, target_path: str,
                 username: str = None, workspace: str = None,
                 use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute tool *name* against *target_path* safely.

        - Validates path is inside *workspace* (if provided).
        - Returns cached DB result if unchanged content + same tool.
        - Logs execution to ToolExecution table.
        """
        tool = self._tools.get(name)
        if tool is None:
            return {"ok": False, "error": f"Unknown tool: {name!r}", "findings": []}

        if not tool.is_available():
            return {"ok": False, "error": f"{name!r} is not installed", "findings": [],
                    "install_hint": f"pip install {name}  # or check tool docs"}

        # Path validation
        if workspace:
            try:
                target_path = tool._validate_path(target_path, workspace)
            except ValueError as e:
                return {"ok": False, "error": str(e), "findings": []}

        cache_key = tool._cache_key(target_path, name)

        # Check DB cache
        if use_cache:
            cached = _load_cache(cache_key)
            if cached:
                return {"ok": True, "findings": cached["findings_json"] or [],
                        "from_cache": True, "duration": 0}

        # Execute
        result = tool.run(target_path)
        findings = tool.parse_output(result.get("output", "")) if result.get("ok") else []
        result["findings"] = findings

        # Persist to DB
        _save_execution(
            username    = username,
            tool_name   = name,
            target_path = target_path,
            status      = "success" if result.get("ok") else "failed",
            findings    = findings,
            cache_key   = cache_key,
            duration_ms = int(result.get("duration", 0) * 1000),
            error       = result.get("error", ""),
        )
        return result


# ── Path detection helpers ────────────────────────────────────────

def _detect_languages(path: str) -> set:
    langs: set = set()
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        lang = _EXT_LANG.get(ext)
        if lang:
            langs.add(lang)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in
                       ("node_modules", ".git", "venv", "__pycache__", "dist", "build")]
            for fn in files:
                ext = os.path.splitext(fn)[1].lower()
                lang = _EXT_LANG.get(ext)
                if lang:
                    langs.add(lang)
    return langs


def _has_docker(path: str) -> bool:
    if os.path.isfile(path):
        return os.path.basename(path).lower() in _DOCKER_NAMES
    for root, _, files in os.walk(path):
        for fn in files:
            if fn.lower() in _DOCKER_NAMES:
                return True
    return False


def _has_iac(path: str) -> bool:
    iac_exts = {".tf", ".hcl"}
    iac_names = {"kubernetes.yaml", "k8s.yaml", "kustomization.yaml",
                 "cloudformation.yaml", "cloudformation.json"}
    if os.path.isfile(path):
        return (os.path.splitext(path)[1].lower() in iac_exts or
                os.path.basename(path).lower() in iac_names)
    for root, _, files in os.walk(path):
        for fn in files:
            if (os.path.splitext(fn)[1].lower() in iac_exts or
                    fn.lower() in iac_names):
                return True
    return False


# ── DB cache helpers ──────────────────────────────────────────────

def _load_cache(cache_key: str):
    try:
        from database.db import get_db_session
        from database.models import ToolExecution
        db = get_db_session()
        return (db.query(ToolExecution)
                  .filter_by(cache_key=cache_key, status="success")
                  .order_by(ToolExecution.executed_at.desc())
                  .first())
    except Exception:
        return None


def _save_execution(username, tool_name, target_path, status,
                    findings, cache_key, duration_ms, error):
    try:
        from database.db import get_db_session
        from database.models import ToolExecution
        db = get_db_session()
        row = ToolExecution(
            username       = username,
            tool_name      = tool_name,
            target_path    = target_path,
            status         = status,
            findings_count = len(findings),
            findings_json  = findings,
            cache_key      = cache_key,
            duration_ms    = duration_ms,
            error_message  = error[:500] if error else None,
        )
        db.add(row)
        db.commit()
    except Exception:
        pass


# ── Module-level singleton ────────────────────────────────────────

registry = ToolRegistry()


def _register_all() -> None:
    """Import and register every adapter.  Call once at startup."""
    from tools.bandit_adapter    import BanditTool
    from tools.trivy_adapter     import TrivyTool
    from tools.checkov_adapter   import CheckovTool
    from tools.pip_audit_adapter import PipAuditTool
    from tools.eslint_adapter    import ESLintTool
    from tools.pylint_adapter    import PylintTool
    from tools.npm_audit_adapter import NpmAuditTool

    for cls in (BanditTool, TrivyTool, CheckovTool, PipAuditTool,
                ESLintTool, PylintTool, NpmAuditTool):
        registry.register(cls())


_register_all()
