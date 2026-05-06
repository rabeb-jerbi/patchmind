"""
tools/base_tool.py
Abstract base class every security tool adapter must implement.
"""
import os
import subprocess
import hashlib
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

# Normalized severity levels
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")

# Tool categories
CATEGORY_SAST       = "SAST"
CATEGORY_DEPENDENCY = "Dependency"
CATEGORY_IAC        = "IaC"
CATEGORY_CONTAINER  = "Container"
CATEGORY_LINT       = "Lint"

# Hard cap on subprocess output read (bytes)
MAX_OUTPUT_BYTES = 2 * 1024 * 1024   # 2 MB


def _normalize_severity(raw: str) -> str:
    """Map arbitrary severity string to one of the canonical levels."""
    s = (raw or "").upper()
    if s in ("CRITICAL", "BLOCKER"):          return "CRITICAL"
    if s in ("HIGH", "ERROR", "MAJOR"):       return "HIGH"
    if s in ("MEDIUM", "WARNING", "MODERATE","MINOR"): return "MEDIUM"
    if s in ("LOW", "NOTE", "INFO", "HINT"):  return "LOW"
    if s in ("INFORMATIONAL", "NEGLIGIBLE"):  return "INFO"
    return "UNKNOWN"


class BaseTool(ABC):
    """
    Contract every tool adapter must satisfy.

    Subclasses set class-level attributes and implement:
      is_available()   -> bool
      run(path)        -> dict   (raw subprocess result)
      parse_output()   -> list[dict]   (normalized findings)
    """

    # ── Required class-level metadata ────────────────────────────
    name: str               = ""
    description: str        = ""
    category: str           = CATEGORY_SAST
    supported_languages: List[str]    = []
    supported_file_types: List[str]   = []
    default_timeout: int    = 120      # seconds

    # ── Helpers available to subclasses ──────────────────────────

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the tool binary / module is present."""

    @abstractmethod
    def run(self, target_path: str) -> Dict[str, Any]:
        """
        Execute the tool against *target_path*.

        Returns:
            {
              "ok":       bool,
              "output":   str,        # raw stdout (truncated at MAX_OUTPUT_BYTES)
              "error":    str,        # stderr or exception message
              "duration": float,      # wall-clock seconds
              "findings": list[dict], # normalized results
            }
        """

    @abstractmethod
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse tool-specific raw JSON/text output into normalized dicts."""

    # ── Shared utilities ─────────────────────────────────────────

    def _safe_run(self, cmd: List[str], cwd: str = None,
                  timeout: int = None) -> Dict[str, Any]:
        """
        Execute *cmd* (a list — never shell=True) and return a result dict.
        Output is capped at MAX_OUTPUT_BYTES to prevent memory exhaustion.
        """
        timeout = timeout or self.default_timeout
        t0 = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                shell=False,           # never shell=True
            )
            raw = proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            err = proc.stderr[:4096].decode("utf-8", errors="replace")
            return {
                "ok":       True,
                "returncode": proc.returncode,
                "output":   raw,
                "error":    err,
                "duration": round(time.time() - t0, 2),
            }
        except FileNotFoundError:
            return {"ok": False, "output": "", "error": f"{cmd[0]!r} not found in PATH",
                    "duration": round(time.time() - t0, 2)}
        except subprocess.TimeoutExpired:
            return {"ok": False, "output": "", "error": f"Timed out after {timeout}s",
                    "duration": timeout}
        except Exception as exc:
            return {"ok": False, "output": "", "error": str(exc),
                    "duration": round(time.time() - t0, 2)}

    @staticmethod
    def _normalize_finding(tool_name: str, category: str,
                            severity: str, cwe: str,
                            file_path: str, line: int,
                            message: str, recommendation: str = "",
                            raw: dict = None) -> Dict[str, Any]:
        """Return a finding in the canonical normalized format."""
        return {
            "tool":           tool_name,
            "category":       category,
            "severity":       _normalize_severity(severity),
            "cwe":            cwe or "",
            "file":           file_path or "",
            "line":           int(line) if line else 0,
            "message":        (message or "")[:500],
            "recommendation": (recommendation or "")[:300],
            "raw":            raw or {},
        }

    @staticmethod
    def _cache_key(target_path: str, tool_name: str) -> str:
        """Stable cache key: md5(file_bytes + tool_name) or md5(dir_tree + tool_name)."""
        h = hashlib.md5(usedforsecurity=False)
        h.update(tool_name.encode())
        if os.path.isfile(target_path):
            try:
                with open(target_path, "rb") as f:
                    h.update(f.read(1024 * 1024))   # first 1 MB
            except OSError:
                h.update(target_path.encode())
        else:
            # For directories, hash the sorted list of (relative_path, mtime, size)
            for root, _, files in os.walk(target_path):
                for fn in sorted(files):
                    fp = os.path.join(root, fn)
                    try:
                        st = os.stat(fp)
                        h.update(f"{fp}:{st.st_mtime}:{st.st_size}".encode())
                    except OSError:
                        pass
        return h.hexdigest()

    @staticmethod
    def _validate_path(target_path: str, user_workspace: str) -> str:
        """
        Resolve and confirm that *target_path* is inside *user_workspace*.
        Raises ValueError on path traversal attempts.
        """
        real_target    = os.path.realpath(target_path)
        real_workspace = os.path.realpath(user_workspace)
        if not (real_target == real_workspace or
                real_target.startswith(real_workspace + os.sep)):
            raise ValueError(
                f"Target path '{target_path}' is outside the user workspace"
            )
        return real_target

    def to_info_dict(self) -> Dict[str, Any]:
        """Serialisable metadata for /api/tools."""
        return {
            "name":                self.name,
            "description":         self.description,
            "category":            self.category,
            "supported_languages": self.supported_languages,
            "supported_file_types": self.supported_file_types,
            "available":           self.is_available(),
        }
