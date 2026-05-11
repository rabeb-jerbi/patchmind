"""
scanner/cwe_resolver.py
Centralized CWE resolution with a priority chain:
  1. Explicit CWE string already normalised  (e.g. "CWE-79")
  2. Rule-ID → CWE mapping  (Bandit B-codes, Semgrep check_id patterns)
  3. Tool-type mapping       (GitLeaks type, ZAP alert names)
  4. Regex extraction from raw string        (e.g. "CWE-079: XSS")
  5. Fallback                                ("CWE-UNKNOWN")

Public API
----------
resolve_cwe(finding: dict) -> str
    Returns a normalised "CWE-NNN" string (never empty).

display_cwe(cwe: str, message: str = "") -> str
    Human-readable label; replaces CWE-UNKNOWN with a friendlier phrase.
"""
import re

# ── Bandit rule → CWE ─────────────────────────────────────────────────────────
_BANDIT_CWE: dict = {
    "B101": "CWE-703",  "B102": "CWE-78",   "B103": "CWE-732",
    "B104": "CWE-605",  "B105": "CWE-259",  "B106": "CWE-259",
    "B107": "CWE-259",  "B108": "CWE-377",  "B110": "CWE-391",
    "B112": "CWE-391",  "B201": "CWE-94",   "B202": "CWE-94",
    "B301": "CWE-502",  "B302": "CWE-502",  "B303": "CWE-327",
    "B304": "CWE-327",  "B305": "CWE-327",  "B306": "CWE-377",
    "B307": "CWE-78",   "B308": "CWE-80",   "B310": "CWE-601",
    "B311": "CWE-338",  "B312": "CWE-319",  "B313": "CWE-611",
    "B314": "CWE-611",  "B315": "CWE-611",  "B316": "CWE-611",
    "B317": "CWE-611",  "B318": "CWE-611",  "B319": "CWE-611",
    "B320": "CWE-611",  "B321": "CWE-319",  "B322": "CWE-78",
    "B323": "CWE-295",  "B324": "CWE-327",  "B325": "CWE-295",
    "B401": "CWE-327",  "B402": "CWE-319",  "B403": "CWE-502",
    "B404": "CWE-78",   "B405": "CWE-611",  "B406": "CWE-611",
    "B407": "CWE-611",  "B408": "CWE-611",  "B409": "CWE-611",
    "B410": "CWE-611",  "B411": "CWE-79",   "B412": "CWE-601",
    "B413": "CWE-327",  "B501": "CWE-295",  "B502": "CWE-295",
    "B503": "CWE-326",  "B504": "CWE-326",  "B505": "CWE-326",
    "B506": "CWE-1236", "B507": "CWE-295",  "B601": "CWE-78",
    "B602": "CWE-78",   "B603": "CWE-78",   "B604": "CWE-78",
    "B605": "CWE-78",   "B606": "CWE-78",   "B607": "CWE-78",
    "B608": "CWE-89",   "B609": "CWE-78",   "B610": "CWE-89",
    "B611": "CWE-89",   "B612": "CWE-78",   "B701": "CWE-79",
    "B702": "CWE-79",   "B703": "CWE-79",
}

# ── Semgrep rule_id keyword patterns → CWE (checked in order) ────────────────
_SEMGREP_PATTERNS: list = [
    (r"sql[_-]?inject|sqli\b",                    "CWE-89"),
    (r"\bxss\b|cross.site.script|direct.jinja",   "CWE-79"),
    (r"command.inject|shell.inject|exec\b",        "CWE-78"),
    (r"path.travers|dir.travers",                  "CWE-22"),
    (r"\bssrf\b|server.side.request",              "CWE-918"),
    (r"hardcoded.pass|hardcoded.secret|hardcoded.cred", "CWE-259"),
    (r"hardcoded.key|hardcoded.token",             "CWE-798"),
    (r"weak.crypto|insecure.hash|md5\b|sha1\b",   "CWE-327"),
    (r"insecure.deser|pickle\b",                   "CWE-502"),
    (r"open.redirect|url.redirect",                "CWE-601"),
    (r"\bxxe\b|xml.external",                      "CWE-611"),
    (r"\bcsrf\b|cross.site.req",                   "CWE-352"),
    (r"timing.attack|time.attack",                 "CWE-208"),
    (r"\bjwt\b|token.verify",                      "CWE-287"),
    (r"\bcors\b|cross.origin",                     "CWE-942"),
    (r"race.condition|toctou",                     "CWE-362"),
    (r"integer.overflow|int.overflow",             "CWE-190"),
    (r"buffer.overflow|buffer.overrun",            "CWE-120"),
    (r"format.string",                             "CWE-134"),
    (r"log.inject|log.forging",                    "CWE-117"),
    (r"insecure.random|weak.random",               "CWE-338"),
    (r"debug.mode|debug.true",                     "CWE-94"),
    (r"secret\b|api.key|access.key",               "CWE-798"),
    (r"trust.boundary|input.valid",                "CWE-501"),
    (r"null.deref|null.pointer",                   "CWE-476"),
    (r"use.after.free",                            "CWE-416"),
    (r"out.of.bounds",                             "CWE-125"),
    (r"div.*zero|division.*zero",                  "CWE-369"),
]

# ── GitLeaks / secret scanner type → CWE ──────────────────────────────────────
_GITLEAKS_CWE: dict = {
    "SECRET":   "CWE-798",
    "API_KEY":  "CWE-798",
    "PASSWORD": "CWE-259",
    "TOKEN":    "CWE-798",
    "PRIVATE_KEY": "CWE-312",
}

# ── CWE number → short label (for display) ────────────────────────────────────
_CWE_LABELS: dict = {
    "CWE-22":  "Path Traversal",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-80":  "Basic XSS",
    "CWE-89":  "SQL Injection",
    "CWE-94":  "Code Injection",
    "CWE-117": "Log Injection",
    "CWE-120": "Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Format String Vulnerability",
    "CWE-190": "Integer Overflow",
    "CWE-208": "Timing Attack",
    "CWE-259": "Hardcoded Credentials",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Certificate Validation Failure",
    "CWE-312": "Cleartext Credential Storage",
    "CWE-319": "Cleartext Transmission",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Weak Cryptographic Algorithm",
    "CWE-338": "Insecure Pseudo-Random Number Generator",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-369": "Divide by Zero",
    "CWE-377": "Insecure Temporary File",
    "CWE-391": "Unchecked Error Condition",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-501": "Trust Boundary Violation",
    "CWE-502": "Insecure Deserialization",
    "CWE-601": "Open Redirect",
    "CWE-605": "Multiple Binds to Same Port",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-703": "Improper Exception Handling",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-798": "Hardcoded Credentials / Secret",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive CORS Policy",
    "CWE-1236": "CSV Injection",
}

# ── Beginner-friendly explanations ────────────────────────────────────────────
_CWE_EXPLAIN: dict = {
    "CWE-22":  "The app uses user-supplied data to build file paths without validation, allowing attackers to access files outside the intended directory.",
    "CWE-78":  "User input is passed directly to a system command, letting attackers run arbitrary OS commands.",
    "CWE-79":  "Untrusted data is included in HTML output without escaping, allowing attackers to inject malicious scripts into the browser.",
    "CWE-89":  "User input is embedded in a database query without sanitisation, allowing attackers to manipulate the query and access or modify data.",
    "CWE-94":  "User input is executed as code, allowing attackers to run arbitrary code on the server.",
    "CWE-259": "A password or secret is embedded directly in source code, making it visible to anyone with access to the code.",
    "CWE-295": "The application does not properly verify SSL/TLS certificates, enabling man-in-the-middle attacks.",
    "CWE-312": "Sensitive data such as passwords is stored without encryption.",
    "CWE-327": "A known weak or broken cryptographic algorithm is used, making encrypted data easier to compromise.",
    "CWE-338": "A non-cryptographic random number generator is used where strong randomness is required.",
    "CWE-352": "The application does not include unpredictable tokens in state-changing requests, allowing attackers to trick users into performing unintended actions.",
    "CWE-362": "Two operations depend on a shared resource but are not properly synchronised, allowing attackers to alter the resource between the check and use.",
    "CWE-502": "The application deserialises untrusted data without validation, potentially executing attacker-controlled code.",
    "CWE-601": "The application redirects users to an attacker-controlled URL without validating the target.",
    "CWE-611": "The XML parser processes external entity references, allowing attackers to read local files or perform SSRF.",
    "CWE-798": "A secret key, API token, or credential is hard-coded or committed to the repository.",
    "CWE-918": "The server makes HTTP requests to a URL derived from user input, allowing attackers to probe internal services.",
    "CWE-942": "The CORS policy is too permissive, allowing any origin to read sensitive responses.",
}


# ── Regex for extracting a CWE number from raw strings ────────────────────────
_CWE_RE = re.compile(r'\bCWE-0*(\d+)\b', re.IGNORECASE)


def _normalise(raw: str) -> str:
    """Extract and normalise a CWE-NNN string from *raw*."""
    m = _CWE_RE.search(raw)
    return f"CWE-{m.group(1)}" if m else ""


def resolve_cwe(finding: dict) -> str:
    """
    Return a normalised CWE string for *finding*.
    Priority:
      1. finding["cwe"] if it already contains a valid CWE number
      2. Bandit rule code in finding["rule"]
      3. Semgrep check_id / rule keyword match
      4. GitLeaks / secret type
      5. Regex extraction from any string field
      6. "CWE-UNKNOWN"
    """
    # 1. Explicit CWE field
    raw_cwe = str(finding.get("cwe", "") or "").strip()
    if raw_cwe and "UNKNOWN" not in raw_cwe.upper():
        extracted = _normalise(raw_cwe)
        if extracted:
            return extracted

    # 2. Bandit B-code
    rule = str(finding.get("rule", "") or "").strip().upper()
    for code, cwe in _BANDIT_CWE.items():
        if code in rule:
            return cwe

    # 3. Semgrep rule_id keyword patterns
    rule_lower = rule.lower()
    for pattern, cwe in _SEMGREP_PATTERNS:
        if re.search(pattern, rule_lower):
            return cwe

    # 4. GitLeaks / tool type
    ftype = str(finding.get("type", "") or "").upper()
    if ftype in _GITLEAKS_CWE:
        return _GITLEAKS_CWE[ftype]

    # 5. Regex extraction from message or raw_cwe
    for field in ("message", "cwe", "rule"):
        val = str(finding.get(field, "") or "")
        extracted = _normalise(val)
        if extracted:
            return extracted

    return "CWE-UNKNOWN"


def display_cwe(cwe: str, message: str = "") -> str:
    """
    Human-readable CWE label.  CWE-UNKNOWN is replaced with 'Security issue
    detected' (or the tool's own message if provided).
    """
    if not cwe or cwe.upper() in ("CWE-UNKNOWN", "UNKNOWN", ""):
        return message.strip()[:80] if message.strip() else "Security issue detected"
    label = _CWE_LABELS.get(cwe, "")
    return f"{cwe} – {label}" if label else cwe


def explain_vuln(cwe: str, message: str = "") -> str:
    """
    Return a beginner-friendly one-sentence explanation for *cwe*.
    Falls back to the tool message or a generic phrase.
    """
    explanation = _CWE_EXPLAIN.get(cwe, "")
    if explanation:
        return explanation
    if message.strip():
        return message.strip()
    return "A security weakness was detected in this code. Review carefully before deploying."
