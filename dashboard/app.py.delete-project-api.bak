import sys
import os
import json
import threading
import shutil
import zipfile
import tempfile
import re
import io
import base64
import time
import secrets
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, Response
from markupsafe import Markup
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import pyotp, qrcode
    TOTP_SUPPORTED = True
except ImportError:
    TOTP_SUPPORTED = False

try:
    import rarfile
    for _p in [r"C:\Program Files\WinRAR\UnRAR.exe",
               r"C:\Program Files (x86)\WinRAR\UnRAR.exe"]:
        if os.path.exists(_p): rarfile.UNRAR_TOOL = _p; break
    RAR_SUPPORTED = True
except ImportError:
    RAR_SUPPORTED = False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.json_io import read_json as _read_json, write_json as _write_json

# ── Database ──────────────────────────────────────────────────────
from database.init_db import init_schema
from database.db      import get_db_session, close_db_session
from database.models  import (User as DBUser, Project as DBProject,
                               ProjectMember as DBProjectMember,
                               ProjectInvitation as DBProjectInvitation,
                               AccessRequest as DBAccessRequest,
                               Metric as DBMetric, AuditLog as DBAuditLog,
                               Comment as DBComment,
                               VulnAssignment as DBAssignment,
                               FalsePositive as DBFalsePositive,
                               ToolExecution as DBToolExecution)

# ── Tool registry ─────────────────────────────────────────────────
from tools.tool_registry import registry as _tool_registry

from scanner.scanner          import run_scan
from scanner.gitleaks_scanner import run_gitleaks
from scanner.snyk_scanner     import run_snyk
from scanner.cwe_resolver     import resolve_cwe, display_cwe, explain_vuln
try:
    from scanner.zap_scanner import run_zap, run_zap_on_file
    ZAP_OK = True
except ImportError:
    ZAP_OK = False
    run_zap_on_file = None
from enricher.enricher        import get_cves_by_cwe
from generator.generator      import generate_patch
from validator.validator      import validate_patch
from metrics.metrics          import PatchMindMetrics

# Multi-LLM consensus (optional — falls back to single generate_patch)
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from llm_consensus import consensus_patch
    CONSENSUS_OK = True
except ImportError:
    CONSENSUS_OK = False

# RBAC — hard fail: a silent no-op would remove all access control
try:
    from rbac import require_role, require_permission, has_permission, ROLES as RBAC_ROLES, PERMISSIONS as RBAC_PERMISSIONS
    RBAC_OK = True
except ImportError as _rbac_err:
    raise RuntimeError(
        f"RBAC module failed to import ({_rbac_err}). "
        "Aborting startup to prevent authorization bypass. "
        "Ensure rbac.py exists and is importable."
    ) from _rbac_err

# Intelligence + Intégrations (import optionnel)
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from intelligence  import analyze_trends, benchmark_user, predict_risk
    from integrations  import send_all_notifications
    INTELLIGENCE_OK = True
except ImportError:
    INTELLIGENCE_OK = False

app = Flask(__name__)

# ── Secret key — mandatory, no insecure fallback ──────────────────
_secret = os.environ.get('PATCHMIND_SECRET')
if not _secret:
    raise RuntimeError(
        "PATCHMIND_SECRET environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret

# ── Session / cookie security ─────────────────────────────────────
app.permanent_session_lifetime = timedelta(hours=8)
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax',
    # Set PATCHMIND_HTTPS=1 in production (HTTPS only).  Kept off by default
    # so the app works on plain HTTP in development without config changes.
    SESSION_COOKIE_SECURE   = os.environ.get('PATCHMIND_HTTPS', '').lower() in ('1', 'true', 'yes'),
    MAX_CONTENT_LENGTH      = 100 * 1024 * 1024,
)

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE = os.path.join(BASE_DIR, 'data', 'users.json')
DATA_DIR   = os.path.join(BASE_DIR, 'data', 'users')

# ── EMAIL CONFIG ──
EMAIL_SENDER   = os.environ.get('PATCHMIND_EMAIL', 'votre.email@gmail.com')
EMAIL_PASSWORD = os.environ.get('PATCHMIND_EMAIL_PASSWORD', 'votre_app_password')
EMAIL_ENABLED  = EMAIL_SENDER != 'votre.email@gmail.com'

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'data', 'analyses'), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'dashboard', 'static', 'avatars'), exist_ok=True)

# ── Database initialisation (create tables, seed admin if empty) ──
init_schema()

# ── Release DB session at end of each request ─────────────────────
app.teardown_appcontext(close_db_session)

# ── Jinja2 icon() helper — SVG cached in memory after first read ──────────────
_icon_cache: dict = {}

def icon(name, size=18, cls='icon'):
    cache_key = f"{name}:{size}:{cls}"
    if cache_key not in _icon_cache:
        path = os.path.join(BASE_DIR, 'dashboard', 'static', 'icons', f'{name}.svg')
        if os.path.exists(path):
            with open(path, encoding='utf-8') as f:
                svg = f.read()
            svg = svg.replace('<svg ', f'<svg class="{cls}" style="width:{size}px;height:{size}px;vertical-align:middle;flex-shrink:0;" ')
            _icon_cache[cache_key] = Markup(svg)
        else:
            _icon_cache[cache_key] = Markup(
                f'<span style="width:{size}px;height:{size}px;display:inline-block"></span>'
            )
    return _icon_cache[cache_key]

app.jinja_env.globals['icon'] = icon

AUDIT_FILE  = os.path.join(BASE_DIR, 'data', 'audit_log.json')
AUDIT_MAX   = 10000

# ── JSON error handlers — API routes must never return HTML error pages ───────

_API_PREFIXES = (
    '/api/', '/admin/api/', '/projects/api/',
    '/project-invitations/', '/admin/requests/',
)

@app.errorhandler(400)
def _err_400(e):
    if any(request.path.startswith(p) for p in _API_PREFIXES):
        return jsonify({"ok": False, "error": str(e.description or "Bad request")}), 400
    return e

@app.errorhandler(401)
def _err_401(e):
    if any(request.path.startswith(p) for p in _API_PREFIXES):
        return jsonify({"ok": False, "error": "Non authentifié"}), 401
    return e

@app.errorhandler(403)
def _err_403(e):
    if any(request.path.startswith(p) for p in _API_PREFIXES):
        return jsonify({"ok": False, "error": "Accès refusé"}), 403
    return e

@app.errorhandler(404)
def _err_404(e):
    if any(request.path.startswith(p) for p in _API_PREFIXES):
        return jsonify({"ok": False, "error": "Ressource introuvable"}), 404
    return e

@app.errorhandler(500)
def _err_500(e):
    if any(request.path.startswith(p) for p in _API_PREFIXES):
        app.logger.exception(e)
        return jsonify({"ok": False, "error": "Erreur interne du serveur"}), 500
    return e


# ── Secure HTTP headers ───────────────────────────────────────────────────────
@app.after_request
def _set_security_headers(response):
    # Prevent MIME-type sniffing
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    # Block embedding in frames (clickjacking)
    response.headers.setdefault('X-Frame-Options', 'DENY')
    # Limit referrer leakage
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    # CSP: allows inline styles/scripts and the CDN/font origins used by templates
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'self';"
    )
    return response

# ── Audit log — DB-backed ─────────────────────────────────────────────────────

def audit_log(event: str, user: str = None, details: dict = None):
    """Insert one audit entry into the DB.  Never raises."""
    ev_user = "anonymous"
    ev_ip   = ""
    try:
        ev_user = user or session.get('username', 'anonymous')
        ev_ip   = request.remote_addr or ""
    except RuntimeError:
        pass
    try:
        db = get_db_session()
        db.add(DBAuditLog(
            ts      = datetime.now(),
            event   = event,
            user    = ev_user,
            ip      = ev_ip,
            details = details or {},
        ))
        db.commit()
    except Exception:
        pass

SUPPORTED_EXTENSIONS = [
    '.py','.js','.jsx','.ts','.tsx','.java','.php',
    '.go','.rb','.cpp','.c','.kt','.swift','.rs'
]

# ══════════════════════════════════════════════════════════════════
# BRUTE-FORCE PROTECTION
# ══════════════════════════════════════════════════════════════════
_login_attempts = {}   # ip -> {count, locked_until}
MAX_ATTEMPTS  = 5
LOCKOUT_MIN   = 15

def is_locked(ip):
    e = _login_attempts.get(ip, {})
    if e.get('locked_until') and datetime.now() < e['locked_until']:
        remaining = int((e['locked_until'] - datetime.now()).total_seconds() / 60) + 1
        return True, remaining
    return False, 0

def record_fail(ip):
    e = _login_attempts.setdefault(ip, {'count':0,'locked_until':None})
    e['count'] += 1
    if e['count'] >= MAX_ATTEMPTS:
        e['locked_until'] = datetime.now() + timedelta(minutes=LOCKOUT_MIN)
        e['count'] = 0

def reset_attempts(ip):
    _login_attempts.pop(ip, None)

# ── Generic per-IP, per-action rate limiter ───────────────────────
_rate_store: dict = {}   # "{ip}:{action}" -> {calls, window_start}
_rate_lock = threading.Lock()

def _rate_check(ip: str, action: str, max_calls: int, window_sec: int) -> bool:
    """Return True if request is within limit, False if rate-limited."""
    key = f"{ip}:{action}"
    now = time.time()
    with _rate_lock:
        entry = _rate_store.get(key)
        if entry is None or now - entry['window_start'] >= window_sec:
            _rate_store[key] = {'calls': 1, 'window_start': now}
            return True
        entry['calls'] += 1
        return entry['calls'] <= max_calls

# ══════════════════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════════════════

# ── Users — DB-backed with 5 s TTL in-memory cache ───────────────────────────
_users_lock      = threading.Lock()
_users_cache: dict = {}
_users_cache_ts: float = 0.0
_USERS_TTL = 5.0


def load_users() -> dict:
    """Return {username: user_dict} from DB, with 5 s TTL cache."""
    global _users_cache, _users_cache_ts
    now = time.time()
    with _users_lock:
        if _users_cache and (now - _users_cache_ts) < _USERS_TTL:
            return dict(_users_cache)
        db = get_db_session()
        rows = db.query(DBUser).all()
        data = {r.username: r.to_dict() for r in rows}
        _users_cache    = data
        _users_cache_ts = now
        return dict(data)


def save_users(u: dict) -> None:
    """Upsert all users in *u* dict into the DB and invalidate the cache."""
    global _users_cache, _users_cache_ts
    db = get_db_session()
    for username, data in u.items():
        row = db.query(DBUser).filter_by(username=username).first()
        if row:
            row.update_from_dict(data)
        else:
            db.add(DBUser.from_dict(username, data))
    db.commit()
    with _users_lock:
        _users_cache    = {}
        _users_cache_ts = 0.0

def get_user_upload_dir(u):
    d = os.path.join(DATA_DIR, u, 'uploads')
    os.makedirs(d, exist_ok=True); return d

def get_user_metrics_path(u):
    d = os.path.join(DATA_DIR, u)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, 'metrics.json')

# ══════════════════════════════════════════════════════════════════
# AUTH DECORATORS
# ══════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def dec(*a,**kw):
        if 'username' not in session:
            if request.is_json or request.method != 'GET' or request.path.startswith('/api/'):
                return jsonify({"error":"Non authentifié"}), 401
            return redirect('/login')
        if not session.get('2fa_ok') and session.get('need_2fa'):
            return redirect('/verify-2fa')
        if session.get('must_change_pw') and request.endpoint != 'change_password':
            if request.is_json or request.method != 'GET':
                return jsonify({"error":"Vous devez changer votre mot de passe"}), 403
            return redirect('/change-password')
        return f(*a,**kw)
    return dec

def admin_required(f):
    @wraps(f)
    def dec(*a,**kw):
        if session.get('role') != 'admin':
            return jsonify({"error":"Accès refusé"}), 403
        return f(*a,**kw)
    return dec

def current_user(): return session.get('username')

# ══════════════════════════════════════════════════════════════════
# 2FA HELPERS
# ══════════════════════════════════════════════════════════════════

def generate_totp_secret():
    return pyotp.random_base32() if TOTP_SUPPORTED else None

def get_totp_uri(secret, username):
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="PatchMind")

def verify_totp(secret, code):
    if not TOTP_SUPPORTED: return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def generate_qr_b64(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()

# ══════════════════════════════════════════════════════════════════
# PIPELINE
# ══════════════════════════════════════════════════════════════════

_pipelines = {}

def get_pipeline(u):
    if u not in _pipelines:
        _pipelines[u] = {
            "running":  False, "progress": 0,
            "status":   "idle",   # idle | running | completed | completed_with_warnings | failed
            "results":  [], "metrics": {}, "logs": [],
            "gitleaks": [],
            "snyk":     [],
            "job_id":   None,
        }
    return _pipelines[u]

def logp(u, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    get_pipeline(u)["logs"].append(f"[{ts}] {msg}")
    print(f"[{u}] {msg}")

def get_supported_files(folder):
    out = []
    for root,dirs,files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in
                   ['venv','.git','__pycache__','node_modules','dist','build']]
        for f in files:
            if any(f.endswith(e) for e in SUPPORTED_EXTENSIONS):
                out.append(os.path.join(root,f))
    return out

# ── Archive safety limits ─────────────────────────────────────────
_ARCHIVE_MAX_UNCOMPRESSED = 500 * 1024 * 1024   # 500 MB
_ARCHIVE_MAX_FILES        = 2_000
_ARCHIVE_DANGEROUS_EXTS   = frozenset({
    '.exe', '.dll', '.so', '.bat', '.cmd', '.sh', '.ps1',
    '.vbs', '.msi', '.app', '.scr', '.com', '.pif',
})

def extract_zip(zip_path, uld):
    safe_name = re.sub(r'[^\w\-]', '_', os.path.splitext(os.path.basename(zip_path))[0])
    dest = os.path.join(uld, safe_name + '_extracted')
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        members = zf.infolist()
        if len(members) > _ARCHIVE_MAX_FILES:
            raise ValueError(f"Archive trop volumineuse : {len(members)} fichiers (max {_ARCHIVE_MAX_FILES})")
        total_size = sum(m.file_size for m in members)
        if total_size > _ARCHIVE_MAX_UNCOMPRESSED:
            raise ValueError(f"Contenu décompressé trop grand : {total_size // 1024 // 1024} MB")
        for m in members:
            mname = m.filename.replace('\\', '/')
            # Reject absolute paths and directory traversal
            parts = mname.split('/')
            if mname.startswith('/') or '..' in parts:
                continue
            # Reject dangerous executables
            if any(mname.lower().endswith(ext) for ext in _ARCHIVE_DANGEROUS_EXTS):
                continue
            # Verify resolved path stays inside dest
            target = os.path.realpath(os.path.join(dest_real, mname))
            if not (target == dest_real or target.startswith(dest_real + os.sep)):
                continue
            zf.extract(m, dest)
    return get_supported_files(dest), dest

def extract_rar(rar_path, uld):
    if not RAR_SUPPORTED:
        raise RuntimeError("rarfile non installé")
    safe_name = re.sub(r'[^\w\-]', '_', os.path.splitext(os.path.basename(rar_path))[0])
    dest = os.path.join(uld, safe_name + '_extracted')
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(dest, exist_ok=True)
    dest_real = os.path.realpath(dest)
    with rarfile.RarFile(rar_path, 'r') as rf:
        members = rf.infolist()
        if len(members) > _ARCHIVE_MAX_FILES:
            raise ValueError(f"Archive trop volumineuse : {len(members)} fichiers (max {_ARCHIVE_MAX_FILES})")
        for m in members:
            mname = m.filename.replace('\\', '/')
            parts = mname.split('/')
            if mname.startswith('/') or '..' in parts:
                continue
            if any(mname.lower().endswith(ext) for ext in _ARCHIVE_DANGEROUS_EXTS):
                continue
            target = os.path.realpath(os.path.join(dest_real, mname))
            if not (target == dest_real or target.startswith(dest_real + os.sep)):
                continue
            rf.extract(m, dest)
    return get_supported_files(dest), dest

# ── Git clone safety ──────────────────────────────────────────────
import ipaddress as _ipaddress
import urllib.parse as _urlparse

_CLONE_TIMEOUT  = int(os.environ.get('PATCHMIND_CLONE_TIMEOUT', '120'))
_CLONE_MAX_MB   = int(os.environ.get('PATCHMIND_CLONE_MAX_MB', '200'))
_GIT_ALLOWED_HOSTS = {'github.com', 'gitlab.com', 'bitbucket.org'}

_PRIVATE_NETS = [
    _ipaddress.ip_network('10.0.0.0/8'),
    _ipaddress.ip_network('172.16.0.0/12'),
    _ipaddress.ip_network('192.168.0.0/16'),
    _ipaddress.ip_network('169.254.0.0/16'),   # link-local + cloud metadata
    _ipaddress.ip_network('127.0.0.0/8'),
    _ipaddress.ip_network('::1/128'),
    _ipaddress.ip_network('fc00::/7'),
]

def _validate_git_url(url: str) -> None:
    """Raise ValueError if url is not a safe public HTTPS git URL."""
    if not url or len(url) > 512:
        raise ValueError("URL invalide ou trop longue")
    parsed = _urlparse.urlparse(url)
    if parsed.scheme not in ('https', 'http'):
        raise ValueError("Seuls les schémas http/https sont autorisés")
    host = (parsed.hostname or '').lower()
    if not host:
        raise ValueError("Hôte manquant dans l'URL")
    # Block raw IP literals pointing to private/metadata ranges
    try:
        addr = _ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise ValueError("Adresse IP interne ou réservée non autorisée")
        for net in _PRIVATE_NETS:
            if addr in net:
                raise ValueError("Adresse IP dans un réseau privé non autorisée")
    except ValueError as exc:
        if 'autoris' in str(exc) or 'interne' in str(exc) or 'priv' in str(exc):
            raise   # re-raise our own IP-range errors
        # ip_address() raised ValueError for a hostname — that is expected and fine
    # Restrict to known public git hosts
    if host not in _GIT_ALLOWED_HOSTS:
        raise ValueError(
            f"Hôte non autorisé : '{host}'. "
            "Utilisez github.com, gitlab.com ou bitbucket.org."
        )
    # No option injection via path (git treats paths starting with '-' as flags)
    path = parsed.path.lstrip('/')
    if path.startswith('-'):
        raise ValueError("Chemin de dépôt invalide")

def clone_repo(url: str, uld: str) -> str:
    _validate_git_url(url)
    import subprocess
    raw_name = url.rstrip('/').split('/')[-1].replace('.git', '')
    safe_name = re.sub(r'[^\w\-]', '_', raw_name)[:80] or 'repo'
    dest = os.path.join(uld, safe_name)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
    result = subprocess.run(
        ['git', 'clone', '--depth', '1', '--', url, dest],
        capture_output=True, text=True,
        timeout=_CLONE_TIMEOUT,
        env=env,
    )
    if result.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(f"Échec du clonage : {(result.stderr or result.stdout)[:300]}")
    # Post-clone size check
    total_bytes = sum(
        os.path.getsize(os.path.join(r, f))
        for r, _, files in os.walk(dest)
        for f in files
    )
    max_bytes = _CLONE_MAX_MB * 1024 * 1024
    if total_bytes > max_bytes:
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError(
            f"Dépôt trop volumineux ({total_bytes // 1024 // 1024} MB > {_CLONE_MAX_MB} MB)"
        )
    return dest

def norm_cwe(raw):
    part = raw.split(':')[0].strip()
    return re.sub(r'^CWE-0*(\d+)$', lambda m: f'CWE-{m.group(1)}',
                  part, flags=re.IGNORECASE) if part else "CWE-UNKNOWN"

def save_session_history(username: str, m: dict, project_id: str = None) -> None:
    """Persist one analysis session to the DB metrics table."""
    session_data = {
        "timestamp":         datetime.now().isoformat(),
        "total_vulns":       m.get("total", 0),
        "patches_validated": m.get("validated", 0),
        "patches_rejected":  m.get("rejected", 0),
        "success_rate":      m.get("success_rate", 0),
        "mttr_seconds":      m.get("mttr", 0),
        "total_duration":    m.get("duration", 0),
        "patched_files":     m.get("patched_files", []),
        "files_analyzed":    m.get("files_analyzed", []),
    }
    if project_id:
        session_data["project_id"] = project_id
    try:
        db = get_db_session()
        db.add(DBMetric(username=username, session_data=session_data))
        db.commit()
    except Exception as exc:
        print(f"⚠️  save_session_history DB error: {exc}")

def _compute_confidence(validation_results: dict, from_cache: bool, cwe: str = "",
                        fixed_code: str = "", consensus_info: dict = None):
    """
    Weighted confidence score (0-100) based on Section 10 requirements.

    Weights:
      Syntax valid       +30
      Semgrep clean      +30
      GitLeaks clean     +20
      Regression/lint    +20
    Bonuses:
      No new vulns       +5
      Cache hit          +5
    Cap: 100

    Returns (score: int, details: dict)
    """
    details: dict = {}

    if not validation_results.get("vuln_fixed"):
        errors = validation_results.get("errors", [])
        details = {
            "syntax":    "—",
            "semgrep":   "failed: vulnerability not fixed",
            "gitleaks":  "—",
            "lint":      "—",
            "consensus": "—",
        }
        if errors:
            details["semgrep"] = f"failed: {errors[0][:80]}"
        return 0, details

    score = 0

    # ── Syntax (+30) ─────────────────────────────────────────────
    syn = validation_results.get("syntax", {})
    if syn.get("warning"):
        score += 15  # tool not available — partial credit
        details["syntax"] = f"warning: {syn.get('message','')[:80]}"
    elif syn.get("passed", True):
        score += 30
        details["syntax"] = f"passed ({syn.get('tool','?')})"
    else:
        details["syntax"] = f"failed: {syn.get('message','')[:80]}"

    # ── Semgrep (+30) ────────────────────────────────────────────
    if validation_results.get("rescan_passed"):
        score += 30
        details["semgrep"] = "passed"
    else:
        score += 10  # fixed but vuln still detected at nearby line
        details["semgrep"] = "warning: vulnerability may still be present at original line"

    # ── GitLeaks (+20) ───────────────────────────────────────────
    gl = validation_results.get("gitleaks", {})
    if gl.get("passed", True):
        score += 20
        details["gitleaks"] = "passed"
    else:
        score += 5  # partial — no hard block, but reduced score
        details["gitleaks"] = f"warning: {gl.get('count', 0)} secret(s) detected in patched file"

    # ── Regression / lint (+20) ──────────────────────────────────
    reg = validation_results.get("regression", {})
    if not reg.get("passed", True):
        details["lint"] = f"failed: {(reg.get('errors') or ['unknown'])[0][:80]}"
    elif reg.get("warnings"):
        score += 10  # warnings present but not blocking
        details["lint"] = f"warning: {reg['warnings'][0][:80]}"
    else:
        score += 20
        details["lint"] = "passed"

    # ── Bonuses ──────────────────────────────────────────────────
    if validation_results.get("new_vulns", 0) == 0:
        score += 5
    if from_cache:
        score += 5

    # ── Consensus label ──────────────────────────────────────────
    if from_cache:
        details["consensus"] = "cache"
    elif consensus_info:
        badge   = consensus_info.get("badge", "")
        patches = consensus_info.get("patches", {})
        n_agree = len(patches)
        details["consensus"] = f"{n_agree}/3" if n_agree else (badge or "single model")
    else:
        details["consensus"] = "single model"

    return min(score, 100), details

def _compute_diff(original_code, fixed_code):
    """Génère un diff simplifié entre le code original et corrigé."""
    import difflib
    orig_lines  = original_code.splitlines(keepends=True)
    fixed_lines = fixed_code.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        orig_lines, fixed_lines,
        fromfile="original", tofile="patched", n=2
    ))
    return "".join(diff[:80])  # Max 80 lignes de diff

# ── Vulnerability explanations ────────────────────────────────────────────────

_VULN_EXPLANATIONS = {
    'CWE-89':  "Un attaquant peut lire, modifier ou supprimer l'ensemble des données de votre base de données, exposant les informations clients et les données métier confidentielles.",
    'CWE-79':  "Des personnes malveillantes peuvent prendre le contrôle de la session de vos utilisateurs, voler leurs identifiants ou les rediriger vers des sites frauduleux.",
    'CWE-22':  "Un tiers non autorisé peut consulter des fichiers confidentiels du serveur (mots de passe, configurations, données clients) en dehors de tout périmètre autorisé.",
    'CWE-78':  "Si exploitée, cette faille permet à un attaquant de prendre le contrôle total du serveur, d'effacer des données ou d'y installer des logiciels malveillants.",
    'CWE-95':  "Un attaquant peut exécuter n'importe quelle instruction sur votre serveur ou dans le navigateur de vos utilisateurs, pouvant mener à une compromission complète du système.",
    'CWE-327': "Les mots de passe et données protégées peuvent être déchiffrés en quelques heures avec des outils courants, exposant directement les comptes de vos utilisateurs.",
    'CWE-502': "Un attaquant peut manipuler les échanges de données pour prendre le contrôle de l'application, pouvant entraîner une compromission totale du serveur.",
    'CWE-798': "Des secrets d'accès (mots de passe, clés API) sont visibles dans le code source, donnant à quiconque y accède un accès direct à vos services et infrastructures.",
    'CWE-434': "Des fichiers malveillants peuvent être déposés sur votre serveur via cette fonctionnalité d'upload, pouvant mener à une prise de contrôle complète de l'infrastructure.",
    'CWE-918': "Un attaquant peut utiliser votre serveur comme relais pour atteindre vos systèmes internes ou exfiltrer des données sensibles hors du périmètre de sécurité.",
    'CWE-611': "Des données internes (fichiers de configuration, informations sensibles) peuvent être extraites de votre serveur à l'insu de vos équipes.",
    'CWE-352': "Un utilisateur connecté peut être manipulé pour effectuer des actions non souhaitées en son nom (modification de données, transactions, suppressions de compte).",
    'CWE-200': "Des informations confidentielles (données clients, configuration système, traces d'erreurs) peuvent être exposées à des personnes non autorisées.",
    'CWE-306': "Des fonctionnalités ou ressources sensibles sont accessibles sans vérification d'identité, ouvrant la porte à un accès non autorisé à l'ensemble de l'application.",
    'CWE-732': "Des fichiers sensibles sont accessibles par des utilisateurs ou processus qui ne devraient pas y avoir accès, augmentant le risque de fuite de données.",
    'CWE-601': "Vos utilisateurs peuvent être redirigés vers des sites malveillants imitant votre application, facilitant le vol d'identifiants ou des tentatives de fraude.",
    'CWE-312': "Des données sensibles (identifiants, informations personnelles) sont stockées sans protection et peuvent être lues directement en cas d'accès non autorisé au système.",
    'CWE-547': "Des paramètres de configuration codés en dur peuvent perturber le bon fonctionnement en production et révèlent des informations sur l'architecture interne de l'application.",
}

_FIX_RECOMMENDATIONS = {
    'CWE-89':  "Faire réviser par l'équipe de développement toutes les interactions avec la base de données pour garantir qu'aucune donnée externe n'y est insérée directement.",
    'CWE-79':  "Mettre en place un encodage systématique de toutes les données affichées à l'utilisateur afin d'empêcher l'exécution de contenu non autorisé.",
    'CWE-22':  "Restreindre strictement l'accès aux fichiers du serveur et valider que tout chemin demandé reste dans le périmètre autorisé de l'application.",
    'CWE-78':  "Supprimer ou isoler tous les points d'accès au système d'exploitation exposés à des données externes et faire auditer les commandes exécutées par l'application.",
    'CWE-95':  "Interdire l'exécution dynamique de code provenant de sources non maîtrisées et faire auditer tous les traitements de données utilisateur.",
    'CWE-327': "Mettre à jour les mécanismes de protection des mots de passe et des données sensibles vers des standards cryptographiques modernes reconnus.",
    'CWE-502': "Remplacer les mécanismes d'échange de données non sécurisés par des formats validés et auditer tous les points d'entrée de l'application.",
    'CWE-798': "Retirer immédiatement les identifiants du code source, révoquer les clés exposées et les centraliser dans un gestionnaire de secrets dédié.",
    'CWE-434': "Mettre en place une validation stricte des fichiers déposés (type, taille, contenu autorisé) et les stocker hors des zones d'exécution du serveur.",
    'CWE-918': "Limiter les communications réseau du serveur aux seules destinations explicitement approuvées et bloquer tout accès aux ressources internes non autorisées.",
    'CWE-611': "Désactiver la prise en charge des ressources externes dans tous les composants de l'application traitant des données structurées.",
    'CWE-352': "Ajouter des jetons de protection anti-rejeu sur l'ensemble des formulaires et actions sensibles de l'application.",
    'CWE-200': "Masquer tous les messages d'erreur techniques en production et s'assurer qu'aucune donnée interne n'est exposée dans les réponses de l'application.",
    'CWE-306': "Vérifier systématiquement l'identité et les droits de chaque utilisateur avant d'autoriser l'accès à toute fonctionnalité ou ressource sensible.",
    'CWE-732': "Appliquer le principe du moindre privilège sur l'ensemble des fichiers, répertoires et ressources de l'application.",
    'CWE-601': "Valider toutes les redirections en les limitant à une liste de destinations approuvées et rejeter toute URL externe non autorisée.",
    'CWE-312': "Chiffrer l'ensemble des données sensibles stockées et en transit selon les standards de sécurité actuels, et sécuriser les clés de chiffrement dans un espace dédié.",
}


def get_vuln_explanation(vuln):
    """Retourne une explication courte et compréhensible de la vulnérabilité."""
    cwe = vuln.get('cwe', '').split(':')[0].strip()
    if cwe in _VULN_EXPLANATIONS:
        return _VULN_EXPLANATIONS[cwe]
    vtype = vuln.get('type', '')
    if vtype == 'SECRET':
        rule = vuln.get('rule', vuln.get('RuleID', 'inconnu'))
        return f"Un secret potentiel de type « {rule} » a été détecté dans le code. Les secrets codés en dur exposent des accès privilégiés si le code est partagé."
    if vtype == 'DEPENDENCY':
        pkg = vuln.get('package', '?')
        ver = vuln.get('version', '?')
        cve = vuln.get('cve', 'CVE inconnu')
        return f"La dépendance '{pkg}' version {ver} contient une vulnérabilité connue ({cve}). Mettre à jour vers la version corrigée réduit immédiatement le risque."
    if vtype == 'DAST':
        return vuln.get('description', "Cette vulnérabilité web peut être exploitée par un attaquant distant pour compromettre l'application ou ses utilisateurs.")
    if vtype == 'CUSTOM':
        return vuln.get('explanation', vuln.get('description', "Vulnérabilité détectée par l'outil personnalisé. Consultez la documentation de l'outil pour plus de détails."))
    # Fall back to cwe_resolver's beginner-friendly explanations
    eng = explain_vuln(cwe, vuln.get('message', ''))
    if eng:
        return eng
    return vuln.get('message', "Vulnérabilité de sécurité détectée. Consultez le détail CWE pour comprendre l'impact et appliquer le correctif recommandé.")


def run_custom_tool(name, command, work_dir, file_paths):
    """Exécute un outil de sécurité personnalisé et parse sa sortie."""
    import subprocess as _sp
    file_arg = file_paths[0] if file_paths else work_dir
    cmd = command.replace('{file}', file_arg).replace('{dir}', work_dir).replace('{path}', file_arg)
    results = []
    try:
        proc = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=120, cwd=work_dir)
        output = (proc.stdout or '') + (proc.stderr or '')
    except _sp.TimeoutExpired:
        return [{"tool": name, "type": "CUSTOM", "cwe": "INFO", "severity": "INFO",
                 "message": f"{name} : timeout après 120s", "file": "", "line": 0,
                 "explanation": f"L'outil {name} a dépassé le délai d'exécution de 120 secondes."}]
    except Exception as e:
        return [{"tool": name, "type": "CUSTOM", "cwe": "INFO", "severity": "INFO",
                 "message": f"{name} : erreur d'exécution — {e}", "file": "", "line": 0,
                 "explanation": f"L'outil {name} n'a pas pu s'exécuter : {e}"}]

    # Try JSON output first
    try:
        parsed = json.loads(output)
        items = parsed if isinstance(parsed, list) else parsed.get('results', parsed.get('findings', []))
        for item in items:
            sev = str(item.get('severity', item.get('level', 'MEDIUM'))).upper()
            results.append({
                "tool": name, "type": "CUSTOM",
                "file": str(item.get('file', item.get('path', item.get('filename', '')))),
                "line": int(item.get('line', item.get('lineno', item.get('start_line', 0)))),
                "cwe": str(item.get('cwe', item.get('rule_id', 'CUSTOM'))),
                "severity": sev if sev in ('CRITICAL','HIGH','MEDIUM','LOW','INFO') else 'MEDIUM',
                "message": str(item.get('message', item.get('msg', item.get('description', str(item)))))[:200],
                "rule": str(item.get('rule', item.get('id', name))),
                "explanation": str(item.get('explanation', item.get('description', f"Résultat de l'outil {name}.")))[:300],
            })
        return results[:50]
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    # Plain-text fallback: one finding per line
    _sev_re  = re.compile(r'\b(CRITICAL|HIGH|MEDIUM|LOW|INFO|ERROR|WARNING|WARN)\b', re.IGNORECASE)
    _file_re = re.compile(r'([\w./-]+\.\w+):(\d+)')
    for line in output.splitlines():
        line = line.strip()
        if not line or len(line) < 8:
            continue
        sev_m  = _sev_re.search(line)
        file_m = _file_re.search(line)
        raw_sev = sev_m.group(1).upper() if sev_m else 'MEDIUM'
        if raw_sev == 'WARNING': raw_sev = 'MEDIUM'
        if raw_sev == 'ERROR':   raw_sev = 'HIGH'
        results.append({
            "tool": name, "type": "CUSTOM",
            "file": file_m.group(1) if file_m else "",
            "line": int(file_m.group(2)) if file_m else 0,
            "cwe": "CUSTOM",
            "severity": raw_sev,
            "message": line[:200],
            "rule": name.lower().replace(' ', '_'),
            "explanation": f"Résultat de l'outil {name} : {line[:150]}",
        })

    return results[:50]


# ─────────────────────────────────────────────────────────────────────────────

def run_pipeline(username, file_paths, scanners=None):
    if scanners is None:
        scanners = {"semgrep": True, "gitleaks": True, "snyk": True, "zap": False, "zap_url": ""}
    ps = get_pipeline(username)
    ps.update({
        "running": True, "progress": 0, "status": "running",
        "results": [], "logs": [], "metrics": {},
        "gitleaks": [], "snyk": [], "zap": [],
        "custom_tools": [], "optional_tools_results": []
    })
    metrics = PatchMindMetrics(); all_vulns = []
    _optional_scanner_failed = [False]

    # Dossier racine
    root_dir = os.path.dirname(file_paths[0]) if file_paths else ""

    try:
        # ── GitLeaks ──────────────────────────────────────────────
        if scanners.get("gitleaks", True):
            logp(username,"🔑 Scan secrets (GitLeaks)...")
            try:
                gitleaks_target = file_paths[0] if len(file_paths) == 1 else root_dir
                gl = run_gitleaks(gitleaks_target)
                ps["gitleaks"] = gl
                logp(username, f"🔑 {len(gl)} secret(s) détecté(s)" if gl else "✅ Aucun secret détecté")
            except Exception as e:
                logp(username, f"⚠️ GitLeaks : {e}")
                _optional_scanner_failed[0] = True

        # ── Snyk/OSV ──────────────────────────────────────────────
        if scanners.get("snyk", True):
            logp(username,"📦 Scan dépendances (Snyk/OSV)...")
            try:
                snyk = run_snyk(root_dir)
                ps["snyk"] = snyk
                logp(username, f"📦 {len(snyk)} dépendance(s) vulnérable(s)" if snyk else "✅ Aucune dépendance vulnérable")
            except Exception as e:
                logp(username, f"⚠️ Snyk : {e}")
                _optional_scanner_failed[0] = True

        # ── ZAP DAST ──────────────────────────────────────────────
        if scanners.get("zap", False):
            zap_url = scanners.get("zap_url", "").strip()
            if zap_url:
                # Explicit URL: full ZAP network scan
                logp(username, f"🌐 Scan DAST ZAP sur {zap_url}...")
                try:
                    if ZAP_OK:
                        zap_results = run_zap(zap_url, scan_type="active")
                    else:
                        zap_results = []
                        logp(username, "⚠️ ZAP non installé")
                    ps["zap"] = zap_results
                    logp(username, f"🌐 {len(zap_results)} vulnérabilité(s) web détectée(s)" if zap_results else "✅ Aucune vulnérabilité web détectée")
                except Exception as e:
                    logp(username, f"⚠️ ZAP : {e}")
            else:
                # No URL: analyse fichiers uploadés directement
                logp(username, "🌐 Scan DAST ZAP sur les fichiers uploadés (analyse statique DAST)...")
                try:
                    if ZAP_OK and run_zap_on_file:
                        zap_results = run_zap_on_file(root_dir)
                    else:
                        from scanner.zap_scanner import _regex_dast_scan
                        zap_results = _regex_dast_scan(root_dir)
                    ps["zap"] = zap_results
                    logp(username, f"🌐 {len(zap_results)} vulnérabilité(s) DAST détectée(s)" if zap_results else "✅ Aucune vulnérabilité DAST détectée")
                except Exception as e:
                    logp(username, f"⚠️ ZAP fichier : {e}")

        # ── Semgrep SAST ──────────────────────────────────────────
        if scanners.get("semgrep", True):
            for fp in file_paths:
                logp(username,f"🔍 Scan de {os.path.basename(fp)}...")
                vulns = run_scan(fp); seen = set()
                for v in vulns:
                    key = (v["line"],v["cwe"].split(":")[0],v["file"])
                    if key not in seen: seen.add(key); all_vulns.append(v)

        # ── Outils optionnels (sélectionnés par l'utilisateur) ───────
        # Category routing: SAST-like → all_vulns; deps → ps["snyk"]; rest → ps["custom_tools"]
        _SAST_TOOLS = {"bandit", "pylint", "eslint"}
        _DEP_TOOLS  = {"pip_audit", "npm_audit"}
        optional_tools = scanners.get("optional_tools", [])
        ps.setdefault("optional_tools_results", {})
        for ot_name in optional_tools:
            if not ot_name:
                continue
            logp(username, f"🔧 Outil optionnel : {ot_name}...")
            try:
                ot_result = _tool_registry.run_tool(
                    name        = ot_name,
                    target_path = root_dir or (file_paths[0] if file_paths else "."),
                    username    = username,
                )
                if not ot_result.get("ok"):
                    logp(username, f"⚠️ {ot_name} : {ot_result.get('error','erreur')}")
                    continue
                ot_findings = ot_result.get("findings", [])
                logp(username, f"🔧 {ot_name} : {len(ot_findings)} résultat(s)")
                if ot_name in _SAST_TOOLS:
                    seen_ot = set()
                    for f in ot_findings:
                        key = (f.get("file",""), f.get("line",0), f.get("cwe",""))
                        if key in seen_ot:
                            continue
                        seen_ot.add(key)
                        all_vulns.append({
                            "file":     f.get("file", ""),
                            "line":     f.get("line", 0),
                            "rule":     f"{ot_name}:{(f.get('raw') or {}).get('test_id', f.get('message','')[:20])}",
                            "severity": f.get("severity", "MEDIUM"),
                            "message":  f.get("message", ""),
                            "cwe":      resolve_cwe(f),
                            "language": f.get("tool", ot_name),
                            "source":   ot_name,
                        })
                elif ot_name in _DEP_TOOLS:
                    ps["snyk"].extend(ot_findings)
                else:
                    ps["custom_tools"].extend(ot_findings)
                ps["optional_tools_results"][ot_name] = len(ot_findings)
            except Exception as _ot_exc:
                logp(username, f"⚠️ {ot_name} : {_ot_exc}")

        # ── Outils personnalisés (commandes shell définies par l'utilisateur) ──
        custom_tools = scanners.get("custom_tools", [])
        ps.setdefault("custom_tools", [])
        for ct in custom_tools:
            ct_name = (ct.get("name") or "").strip()
            ct_cmd  = (ct.get("command") or "").strip()
            if not ct_name or not ct_cmd:
                continue
            logp(username, f"🔧 Outil personnalisé : {ct_name}...")
            try:
                ct_results = run_custom_tool(ct_name, ct_cmd, root_dir, file_paths)
                for r in ct_results:
                    r["explanation"] = get_vuln_explanation(r)
                ps["custom_tools"].extend(ct_results)
                logp(username, f"🔧 {ct_name} : {len(ct_results)} résultat(s)")
            except Exception as e:
                logp(username, f"⚠️ {ct_name} : {e}")

        # ── False positive filtering ───────────────────────────────
        if all_vulns:
            before = len(all_vulns)
            all_vulns = [v for v in all_vulns
                         if not is_false_positive(v.get("cwe",""), v.get("message",""))]
            filtered = before - len(all_vulns)
            if filtered > 0:
                logp(username, f"🚫 {filtered} faux positif(s) confirmé(s) filtrés")

        # ── Enrichissement des explications ───────────────────────
        for v in all_vulns:
            if not v.get("explanation"):
                v["explanation"] = get_vuln_explanation(v)
        for v in ps.get("gitleaks", []):
            if not v.get("explanation"):
                v["type"] = "SECRET"
                v["explanation"] = get_vuln_explanation(v)
        for v in ps.get("snyk", []):
            if not v.get("explanation"):
                v["type"] = "DEPENDENCY"
                v["explanation"] = get_vuln_explanation(v)

        # ── Snapshot of all detected findings (before patch gen) ─────
        _detected_code    = len(all_vulns)
        _detected_secrets = len(ps.get("gitleaks",  []))
        _detected_deps    = len(ps.get("snyk",       []))
        _detected_dast    = len(ps.get("zap",        []))
        _detected_custom  = len(ps.get("custom_tools",[]))
        _detected_total   = (_detected_code + _detected_secrets +
                             _detected_deps + _detected_dast + _detected_custom)

        if not _detected_total:
            logp(username,"✅ Aucune vulnérabilité trouvée !")
            ps["running"] = False
            ps["status"]  = "completed_with_warnings" if _optional_scanner_failed[0] else "completed"
            return

        if _detected_code:
            logp(username, f"⚠️  {_detected_code} vulnérabilité(s) code détectée(s)")
        if _detected_secrets:
            logp(username, f"🔑 {_detected_secrets} secret(s) détecté(s) — correction manuelle requise")
        if _detected_deps:
            logp(username, f"📦 {_detected_deps} dépendance(s) vulnérable(s) — vérifiez manuellement")
        if _detected_dast:
            logp(username, f"🌐 {_detected_dast} finding(s) DAST détecté(s)")

        # ── Cache stats avant traitement ──────────────────────────
        try:
            from generator.generator import get_cache_stats
            stats = get_cache_stats()
            if stats["total_entries"] > 0:
                logp(username, f"⚡ Cache : {stats['total_entries']} patches en cache disponibles")
        except Exception:
            pass

        # ── Traitement des vulnérabilités ─────────────────────────
        import concurrent.futures, threading
        lock = threading.Lock()
        completed = [0]


        def make_manual_result(vuln, source="manual"):
            """Create visible result for non-patchable findings like GitLeaks secrets."""
            msg = (
                vuln.get("message")
                or vuln.get("Message")
                or vuln.get("Description")
                or vuln.get("description")
                or vuln.get("RuleID")
                or "Finding detected"
            )
            raw_cwe = vuln.get("cwe") or vuln.get("CWE") or resolve_cwe(vuln)
            cwe = norm_cwe(str(raw_cwe or "CWE-UNKNOWN"))

            file_value = (
                vuln.get("file")
                or vuln.get("File")
                or vuln.get("path")
                or vuln.get("Path")
                or vuln.get("filename")
                or ""
            )
            line_value = (
                vuln.get("line")
                or vuln.get("Line")
                or vuln.get("StartLine")
                or vuln.get("start_line")
                or 0
            )
            try:
                line_value = int(line_value)
            except Exception:
                line_value = 0

            source_key = (source or vuln.get("source") or vuln.get("tool") or "manual").lower()

            if source_key == "gitleaks":
                vuln_type = "SECRET"
                recommendation = (
                    "Supprimez le secret exposé, révoquez ou renouvelez la clé concernée, "
                    "puis stockez-la dans une variable d'environnement ou un gestionnaire de secrets."
                )
            elif source_key in ("snyk", "osv", "pip_audit", "npm_audit"):
                vuln_type = "DEPENDENCY"
                recommendation = "Mettez à jour la dépendance vulnérable vers une version corrigée."
            elif source_key == "zap":
                vuln_type = "DAST"
                recommendation = "Analysez le point d'entrée web concerné et appliquez une correction côté application."
            else:
                vuln_type = vuln.get("type", "CUSTOM")
                recommendation = vuln.get("recommendation") or vuln.get("solution") or "Correction manuelle requise."

            enriched = dict(vuln)
            enriched.setdefault("type", vuln_type)
            enriched.setdefault("cwe", cwe)
            enriched.setdefault("message", str(msg))

            return {
                "cwe": cwe,
                "cwe_display": display_cwe(cwe, str(msg)),
                "file": os.path.basename(str(file_value)) if file_value else "",
                "line": line_value,
                "severity": str(vuln.get("severity", vuln.get("Severity", "MEDIUM"))).upper(),
                "success": False,
                "manual_review": True,
                "patchable": False,
                "message": str(msg)[:200],
                "explanation": vuln.get("explanation") or get_vuln_explanation(enriched),
                "recommendation": recommendation,
                "patched": "",
                "patched_name": "",
                "analyzed_at": datetime.now().strftime("%H:%M:%S"),
                "from_cache": False,
                "confidence": 0,
                "confidence_details": {
                    "status": "manual_review_required",
                    "scanner": source_key,
                },
                "validation_warnings": [],
                "diff": "",
                "tools": [],
                "test_code": "",
                "consensus": {},
                "source": source_key,
            }

        def process_vuln(args):
            i, vuln = args
            try:
                cwe  = norm_cwe(vuln['cwe'])
                cves = get_cves_by_cwe(cwe)
                known = [c for c in cves if c.get("severity")!="UNKNOWN"]
                sev   = f"{max(known,key=lambda x:x.get('cvss_score',0)).get('severity')} (CVSS {max(known,key=lambda x:x.get('cvss_score',0)).get('cvss_score')})" if known else vuln['severity']

                # Lire code original pour diff
                orig_path = vuln["file"]
                try:
                    with open(orig_path, "r", encoding="utf-8", errors="ignore") as f:
                        original_code = f.read()
                except Exception:
                    original_code = ""

                base, ext = os.path.splitext(orig_path)
                patched   = base + "_patched" + ext
                src       = patched if os.path.exists(patched) else orig_path
                vt        = vuln.copy(); vt["file"] = orig_path

                # Cache check
                from generator.generator import get_from_cache
                cwe_clean = cwe.split(":")[0].strip()
                lang      = vuln.get("language","python")
                cached    = get_from_cache(cwe_clean, lang, original_code, vuln.get("line",0))
                from_cache = cached is not None

                with lock:
                    logp(username, f"{'⚡ Cache' if from_cache else '🤖'} [{i}/{len(all_vulns)}] {'Patch depuis cache' if from_cache else 'Génération patch'}...")
                    metrics.start_vuln(vuln)

                consensus_info = {}
                if cached:
                    fixed_code = cached
                elif CONSENSUS_OK:
                    with lock:
                        logp(username, f"🤝 [{i}/{len(all_vulns)}] Consensus multi-LLM...")
                    c_result   = consensus_patch(vt, code_context=original_code)
                    fixed_code = c_result.get("fixed_code", "") or generate_patch(vt)
                    consensus_info = c_result.get("consensus", {})
                    with lock:
                        badge = consensus_info.get("badge", "")
                        if badge:
                            logp(username, f"🤝 [{i}/{len(all_vulns)}] {badge}")
                else:
                    fixed_code = generate_patch(vt)

                with lock:
                    logp(username, f"✅ [{i}/{len(all_vulns)}] Validation...")

                target_url = (scanners or {}).get("zap_url", "") or None
                ok, validation_results = validate_patch(src, fixed_code, vuln, target_url=target_url)

                # Score de confiance (Section 10 — weighted)
                confidence, confidence_details = _compute_confidence(
                    validation_results, from_cache, cwe_clean, fixed_code, consensus_info
                )

                # Diff visuel
                diff = _compute_diff(original_code, fixed_code) if ok else ""

                # Suggestions outils + test généré (second LLM call)
                suggestions = {}
                if ok and fixed_code:
                    try:
                        from generator.generator import generate_suggestions
                        suggestions = generate_suggestions(vuln, fixed_code)
                    except Exception:
                        suggestions = {}

                with lock:
                    metrics.end_vuln(ok)
                    patched_exists = ok and os.path.exists(patched)
                    completed[0] += 1
                    ps["progress"] = int(completed[0] / len(all_vulns) * 100)
                    logp(username, f"{'✅' if ok else '❌'} [{i}/{len(all_vulns)}] {'VALIDÉ' if ok else 'REJETÉ'} {'(cache ⚡)' if from_cache else ''} — confiance: {confidence}%")

                return {
                    "cwe":                 vuln['cwe'].split(':')[0].strip(),
                    "file":                os.path.basename(orig_path),
                    "line":                vuln["line"],
                    "severity":            sev,
                    "success":             ok,
                    "message":             vuln["message"][:100],
                    "patched":             patched if patched_exists else "",
                    "patched_name":        os.path.basename(patched) if patched_exists else "",
                    "analyzed_at":         datetime.now().strftime("%H:%M:%S"),
                    "from_cache":          from_cache,
                    "confidence":          confidence,
                    "confidence_details":  confidence_details,
                    "validation_warnings": validation_results.get("warnings", []),
                    "diff":                diff,
                    "tools":               suggestions.get("tools", []),
                    "test_code":           suggestions.get("test_code", ""),
                    "consensus":           consensus_info,
                    "source":              vuln.get("source", "semgrep"),
                }
            except Exception as e:
                with lock:
                    logp(username, f"❌ [{i}] Erreur : {e}")
                return None

        # Parallélisation — adapter selon taille du projet
        # Petit projet (<20 vulns) → 3 workers
        # Moyen projet (20-50 vulns) → 2 workers
        # Gros projet (>50 vulns) → 1 worker séquentiel pour éviter rate limit
        if len(all_vulns) > 50:
            MAX_WORKERS = 1
            logp(username, f"📋 Gros projet ({len(all_vulns)} vulns) — mode séquentiel pour éviter rate limit")
        elif len(all_vulns) > 20:
            MAX_WORKERS = 2
            logp(username, f"📋 Projet moyen ({len(all_vulns)} vulns) — 2 workers")
        else:
            MAX_WORKERS = 3

        args_list   = list(enumerate(all_vulns, 1))
        results_raw = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_vuln, arg): arg for arg in args_list}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results_raw.append((futures[future][0], result))
                # Pause anti rate limit pour gros projets
                if len(all_vulns) > 30:
                    time.sleep(1)

        # Trier par ordre original
        results_raw.sort(key=lambda x: x[0])

        patch_results = [r for _, r in results_raw]
        manual_results = []

        for secret in ps.get("gitleaks", []):
            secret = dict(secret)
            secret["type"] = "SECRET"
            secret.setdefault("cwe", resolve_cwe(secret))
            manual_results.append(make_manual_result(secret, source="gitleaks"))

        for dep in ps.get("snyk", []):
            dep = dict(dep)
            dep["type"] = "DEPENDENCY"
            dep.setdefault("cwe", resolve_cwe(dep))
            manual_results.append(make_manual_result(dep, source="snyk"))

        for z in ps.get("zap", []):
            z = dict(z)
            z["type"] = "DAST"
            z.setdefault("cwe", resolve_cwe(z))
            manual_results.append(make_manual_result(z, source="zap"))

        for custom in ps.get("custom_tools", []):
            custom = dict(custom)
            custom.setdefault("cwe", resolve_cwe(custom))
            manual_results.append(make_manual_result(custom, source=custom.get("tool", "custom")))

        ps["results"] = patch_results + manual_results
        manual_review_required = len(manual_results)

        metrics.finalize(
            total_detected=_detected_total,
            manual_review_required=manual_review_required
        )

        total = len(patch_results)
        succ = sum(1 for r in patch_results if r.get("success"))
        cache_hits = sum(1 for r in patch_results if r.get("from_cache"))
        if cache_hits > 0:
            logp(username, f"⚡ {cache_hits} patch(es) depuis cache — {cache_hits * 20}s économisés !")

        seen_p, patches = [], []
        for r in ps["results"]:
            p = r.get("patched","")
            if r["success"] and p and p not in seen_p:
                seen_p.append(p)
                try:
                    st = os.stat(p)
                    patches.append({
                        "name":       os.path.basename(p),
                        "path":       p,
                        "size":       round(st.st_size / 1024, 1),
                        "patched_at": datetime.fromtimestamp(st.st_mtime).strftime("%d/%m/%Y %H:%M"),
                    })
                except OSError:
                    patches.append({"name": os.path.basename(p), "path": p, "size": 0, "patched_at": ""})

        # Unique file basenames with per-file vuln counts + downloadable paths
        original_path_map = {
            os.path.basename(fp): fp
            for fp in file_paths
        }

        file_vuln_map = {}
        for r in ps["results"]:
            fn = r.get("file", "")
            if fn:
                file_vuln_map[fn] = file_vuln_map.get(fn, 0) + 1

        files_analyzed = []
        for name, vulns_count in file_vuln_map.items():
            original_path = original_path_map.get(name, "")
            patched_path = ""
            patched_name = ""

            base_name, ext = os.path.splitext(name)
            for pf in patches:
                pf_name = pf.get("name", "")
                if pf_name.startswith(base_name):
                    patched_path = pf.get("path", "")
                    patched_name = pf_name
                    break

            files_analyzed.append({
                "name": name,
                "vulns": vulns_count,
                "path": original_path,
                "original_path": original_path,
                "patched_path": patched_path,
                "patched_name": patched_name,
            })

        ps["metrics"]={
            # real totals — all scanners combined
            "total":            _detected_total,
            "detected_code":    _detected_code,
            "detected_secrets": _detected_secrets,
            "detected_deps":    _detected_deps,
            "detected_dast":    _detected_dast,
            "detected_custom":  _detected_custom,
            # patch-generation results (code vulns only)
            "patchable":        _detected_code,
            "validated":        succ,
            "rejected":         total - succ,
            "manual_review_required": manual_review_required,
            "non_patchable":    manual_review_required,
            "success_rate":     round(succ / _detected_code * 100, 1) if _detected_code else 0,
            "mttr":             round(metrics.session.get("mttr_seconds",  0), 2),
            "duration":         round(metrics.session.get("total_duration", 0), 2),
            "patched_files":    patches,
            "files_analyzed":   files_analyzed,
        }
        save_session_history(username, ps["metrics"], project_id=ps.get("project_id"))
        audit_log("scan_complete", user=username, details={
            "total": ps["metrics"].get("total",0),
            "validated": ps["metrics"].get("validated",0),
            "success_rate": ps["metrics"].get("success_rate",0),
        })
        ps["status"] = "completed_with_warnings" if _optional_scanner_failed[0] else "completed"
        logp(username,"🎉 Pipeline terminé !")

        # ── Notifications automatiques ────────────────────────────
        if INTELLIGENCE_OK:
            try:
                notifs = send_all_notifications(ps["metrics"], ps["results"], username)
                if notifs.get("slack"):    logp(username,"📢 Notification Slack envoyée")
                if notifs.get("teams"):    logp(username,"📢 Notification Teams envoyée")
                if notifs.get("jira",{}).get("created",0)>0:
                    logp(username,f"🎫 {notifs['jira']['created']} ticket(s) Jira créé(s)")
            except Exception as e:
                pass  # Notifications optionnelles, ne pas bloquer

    except Exception as e:
        logp(username, f"❌ Erreur pipeline : {e}")
        ps["status"] = "failed"
    ps["running"] = False

# ══════════════════════════════════════════════════════════════════
# INTELLIGENCE ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/intelligence/trends')
@login_required
def get_trends():
    """Retourne les tendances et insights pour l'utilisateur connecté."""
    if not INTELLIGENCE_OK:
        return jsonify({"status":"unavailable","message":"Module intelligence non chargé"})
    u = current_user()
    return jsonify(analyze_trends(u))

@app.route('/intelligence/benchmark')
@login_required
def get_benchmark():
    """Compare les métriques avec la plateforme et l'industrie."""
    if not INTELLIGENCE_OK:
        return jsonify({"status":"unavailable"})
    u = current_user()
    return jsonify(benchmark_user(u))

@app.route('/intelligence/risk', methods=['POST'])
@login_required
def get_risk():
    """Estimation de risque avant analyse complète."""
    if not INTELLIGENCE_OK:
        return jsonify({"score":0,"level":"unknown","status":"unavailable"})
    u  = current_user()
    uld = get_user_upload_dir(u)
    # Utiliser les fichiers déjà uploadés
    fps = []
    for fn in os.listdir(uld):
        ext = os.path.splitext(fn)[1].lower()
        if ext in {'.py','.js','.java','.php','.go','.rb','.cpp','.c','.kt','.swift','.rs','.ts'}:
            fps.append(os.path.join(uld, fn))
    risk = predict_risk(fps[:20])
    return jsonify(risk)

@app.route('/intelligence/cache-stats')
@login_required
def get_cache_stats_route():
    """Statistiques du cache de patches."""
    try:
        from generator.generator import get_cache_stats
        return jsonify(get_cache_stats())
    except Exception:
        return jsonify({"total_entries":0,"total_hits":0})

# ══════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET','POST'])
def login_page():
    if 'username' in session and session.get('2fa_ok'): return redirect('/dashboard')
    if request.method == 'POST':
        d  = request.get_json() or {}
        u  = d.get('username','').strip()
        p  = d.get('password','')
        ip = request.remote_addr

        # Brute-force check
        locked, remaining = is_locked(ip)
        if locked:
            return jsonify({"error":f"Compte verrouillé. Réessayez dans {remaining} min."}), 429

        users = load_users()
        if u not in users or not users[u].get('active', True):
            record_fail(ip)
            audit_log("login_fail", user=u, details={"reason": "unknown_user", "ip": ip})
            return jsonify({"error":"Identifiants incorrects"}), 401
        if users[u].get('blocked', False):
            audit_log("login_blocked", user=u, details={"ip": ip})
            return jsonify({"error":"Compte bloqué. Contactez votre administrateur."}), 403
        if not check_password_hash(users[u]['password'], p):
            record_fail(ip)
            fails = _login_attempts.get(ip,{}).get('count',0)
            remaining_att = MAX_ATTEMPTS - fails
            audit_log("login_fail", user=u, details={"reason": "bad_password", "attempts_left": remaining_att, "ip": ip})
            return jsonify({"error":f"Identifiants incorrects. {remaining_att} tentative(s) restante(s)"}), 401

        reset_attempts(ip)
        audit_log("login_success", user=u, details={"ip": ip, "role": users[u].get('role','user')})
        session.permanent = True   # Enforce the 8-hour PERMANENT_SESSION_LIFETIME timeout
        session['username'] = u
        session['role']     = users[u].get('role','user')
        session['fullname'] = users[u].get('full_name',u)

        # 2FA check
        if users[u].get('totp_enabled') and users[u].get('totp_secret'):
            session['need_2fa'] = True
            session['2fa_ok']   = False
            return jsonify({"ok":True,"need_2fa":True})

        session['need_2fa'] = False
        session['2fa_ok']   = True
        # must_change_password → force change on first login
        if users[u].get('must_change_password', False):
            session['must_change_pw'] = True
            return jsonify({"ok": True, "need_2fa": False, "redirect": "/change-password"})
        # Admin → /admin, user → /dashboard
        redirect_url = "/admin" if session['role'] == 'admin' else "/dashboard"
        return jsonify({"ok":True,"need_2fa":False,"role":session['role'],"redirect": redirect_url})
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET','POST'])
def verify_2fa():
    if '2fa_ok' not in session: return redirect('/login')
    if session.get('2fa_ok'):   return redirect('/dashboard')
    if request.method == 'POST':
        if not _rate_check(request.remote_addr, 'verify-2fa', 5, 300):
            return jsonify({"error": "Trop de tentatives 2FA. Réessayez dans 5 minutes."}), 429
        d    = request.get_json() or {}
        code = d.get('code','').replace(' ','')
        users = load_users()
        u     = session.get('username')
        if not u or u not in users:
            return jsonify({"error":"Session invalide"}), 401
        secret = users[u].get('totp_secret')
        if verify_totp(secret, code):
            session['2fa_ok']   = True
            session['need_2fa'] = False
            if users[u].get('must_change_password', False):
                session['must_change_pw'] = True
                return jsonify({"ok": True, "redirect": "/change-password"})
            redirect_url = "/admin" if session.get('role') == 'admin' else "/dashboard"
            return jsonify({"ok": True, "redirect": redirect_url})
        return jsonify({"error":"Code incorrect. Vérifiez votre application."}), 401
    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    timed_out = request.args.get('timeout') == '1'
    audit_log("logout", details={"timeout": timed_out})
    session.clear()
    if timed_out:
        return redirect('/login?msg=session_expired')
    return redirect('/login')

@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    u = current_user()
    if request.method == 'POST':
        d       = request.get_json() or {}
        new_pw  = d.get('password','').strip()
        if len(new_pw) < 8:
            return jsonify({"error":"Mot de passe trop court (8 car. min)"}), 400
        users = load_users()
        if u not in users:
            return jsonify({"error":"Utilisateur introuvable"}), 404
        users[u]['password']             = generate_password_hash(new_pw)
        users[u]['must_change_password'] = False
        save_users(users)
        session.pop('must_change_pw', None)
        role = users[u].get('role','user')
        redirect_url = "/admin" if role == 'admin' else "/dashboard"
        return jsonify({"ok": True, "redirect": redirect_url})
    return render_template('change_password.html')

@app.route('/me')
@login_required
def me():
    users = load_users()
    u     = current_user()
    ud    = users.get(u, {})
    avatar_path = os.path.join(BASE_DIR, 'dashboard', 'static', 'avatars', f'{u}.jpg')
    return jsonify({
        "username":     u,
        "role":         session.get('role','user'),
        "fullname":     session.get('fullname', u),
        "full_name":    ud.get('full_name', u),
        "email":        ud.get('email',''),
        "company":      ud.get('company',''),
        "lang":         ud.get('lang','fr'),
        "notif_email":  ud.get('notif_email', False),
        "notif_browser":ud.get('notif_browser', False),
        "has_2fa":      ud.get('totp_enabled', False),
        "has_avatar":      os.path.exists(avatar_path),
        "onboarding_done": ud.get('onboarding_done', False),
        "permissions":  [p for p, roles in RBAC_PERMISSIONS.items()
                         if session.get('role','user') in roles],
    })

@app.route('/onboarding/done', methods=['POST'])
@login_required
def onboarding_done():
    users = load_users()
    u = current_user()
    if u in users:
        users[u]['onboarding_done'] = True
        save_users(users)
    return jsonify({"ok": True})

@app.route('/generate-test', methods=['POST'])
@login_required
def generate_test_on_demand():
    """Generate a unit test for a specific vulnerability on demand."""
    d        = request.get_json() or {}
    idx      = int(d.get('vuln_index', 0))
    ps       = get_pipeline(current_user())
    results  = ps.get('results', [])
    if idx < 0 or idx >= len(results):
        return jsonify({"test_code": "// Vulnérabilité introuvable"}), 200
    r = results[idx]
    vuln = {
        'cwe':      r.get('cwe', 'Unknown'),
        'message':  r.get('message', ''),
        'language': r.get('language', 'python'),
        'line':     r.get('line', 0),
    }
    fixed_code = r.get('fixed_code', r.get('original_code', ''))
    try:
        from generator.generator import generate_suggestions
        sugg = generate_suggestions(vuln, fixed_code)
        test_code = sugg.get('test_code', '') or '// Aucun test disponible'
    except Exception:
        test_code = '// Erreur de génération — vérifiez votre clé API Groq'
    return jsonify({"test_code": test_code})

# pip-installable tool names
_PIP_TOOLS = {'bandit', 'pylint', 'safety', 'pyflakes', 'checkov', 'sqlmap'}
# npm-installable tool names
_NPM_TOOLS  = {'eslint'}
# tools not installable via pip/npm — require manual setup
_BINARY_TOOLS = {'trivy'}

@app.route('/run-tool', methods=['POST'])
@login_required
def run_recommended_tool():
    if not _rate_check(request.remote_addr, 'run-tool', 15, 60):
        return jsonify({"ok": False, "error": "Trop de requêtes. Réessayez dans une minute."}), 429
    import subprocess, shlex
    d    = request.get_json() or {}
    cmd  = (d.get('cmd') or '').strip()
    name = (d.get('tool_name') or '').strip()[:80]
    if not cmd:
        return jsonify({"ok": False, "error": "Commande vide"}), 400
    allowed_prefixes = ('pip install', 'pip3 install', 'npm install', '-m pip',
                        'bandit', 'eslint', 'pylint', 'safety', 'pyflakes',
                        'npm audit', 'yarn audit', 'semgrep', 'trivy',
                        'snyk test', 'gitleaks detect', 'checkov', 'sqlmap')
    if not any(cmd.startswith(p) for p in allowed_prefixes):
        return jsonify({"ok": False, "error": "Commande non autorisée"}), 403

    def _run(c):
        return subprocess.run(shlex.split(c), capture_output=True, text=True,
                              timeout=120, cwd=BASE_DIR)

    try:
        result = _run(cmd)
        out = (result.stdout or '') + (result.stderr or '')
        return jsonify({"ok": True, "output": out[:3000], "returncode": result.returncode})

    except FileNotFoundError:
        tool_bin = shlex.split(cmd)[0].lower()
        # ── Auto-install ──────────────────────────────────────────
        install_log = ''
        installed   = False
        if tool_bin in _PIP_TOOLS:
            try:
                # Use sys.executable to guarantee the correct pip in any venv/conda env
                ir = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--quiet', tool_bin],
                    capture_output=True, text=True, timeout=180
                )
                install_log = (ir.stdout or '') + (ir.stderr or '')
                installed   = ir.returncode == 0
            except Exception as ie:
                install_log = str(ie)
        elif tool_bin in _NPM_TOOLS:
            try:
                ir = subprocess.run(
                    ['npm', 'install', '-g', tool_bin],
                    capture_output=True, text=True, timeout=120
                )
                install_log = (ir.stdout or '') + (ir.stderr or '')
                installed   = ir.returncode == 0
            except Exception as ie:
                install_log = str(ie)

        if installed:
            # Re-run using python -m <tool> first (works before PATH refreshes on Windows)
            try:
                py_cmd = f'{sys.executable} -m {tool_bin} ' + ' '.join(shlex.split(cmd)[1:])
                result2 = subprocess.run(shlex.split(py_cmd), capture_output=True, text=True,
                                         timeout=120, cwd=BASE_DIR)
                out2 = (result2.stdout or '') + (result2.stderr or '')
                return jsonify({
                    "ok": True,
                    "output": out2[:3000],
                    "returncode": result2.returncode,
                    "installed": True,
                    "install_log": install_log[:500],
                })
            except Exception:
                pass
            # Fall back to direct PATH re-run
            try:
                result2 = _run(cmd)
                out2 = (result2.stdout or '') + (result2.stderr or '')
                return jsonify({
                    "ok": True,
                    "output": out2[:3000],
                    "returncode": result2.returncode,
                    "installed": True,
                    "install_log": install_log[:500],
                })
            except FileNotFoundError:
                pass  # fall through to manual instructions

        # ── Fallback: manual instructions ─────────────────────────
        if tool_bin in _PIP_TOOLS:
            hint = f"pip install {tool_bin}  (ou: python -m pip install {tool_bin})"
        elif tool_bin in _NPM_TOOLS:
            hint = f"npm install -g {tool_bin}"
        elif tool_bin in _BINARY_TOOLS:
            hint = f"Téléchargez {tool_bin} depuis https://github.com/aquasecurity/trivy/releases"
        else:
            hint = f"Installez '{tool_bin}' selon sa documentation officielle"

        msg = f"'{tool_bin}' introuvable dans le PATH."
        if install_log:
            msg += f" Installation échouée : {install_log[:200]}"
        msg += f" Commande manuelle : {hint}"
        return jsonify({"ok": False, "error": msg, "install_hint": hint}), 200

    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Timeout (120s)"}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200

@app.route('/profile', methods=['GET'])
@login_required
def profile_page():
    return render_template('profile.html')

@app.route('/profile', methods=['POST'])
@login_required
def profile_update():
    u    = current_user()
    d    = request.get_json() or {}
    users = load_users()
    if u not in users:
        return jsonify({"error":"Utilisateur introuvable"}), 404
    allowed = ['full_name','email','company','lang','notif_email','notif_browser']
    for k in allowed:
        if k in d:
            users[u][k] = d[k]
    save_users(users)
    session['fullname'] = users[u].get('full_name', u)
    return jsonify({"ok": True})

@app.route('/profile/avatar', methods=['POST'])
@login_required
def profile_avatar():
    u = current_user()
    if 'avatar' not in request.files:
        return jsonify({"error": "Aucun fichier"}), 400
    f = request.files['avatar']
    if not f.filename:
        return jsonify({"error": "Fichier vide"}), 400
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ('.jpg','.jpeg','.png','.webp'):
        return jsonify({"error": "Format non supporté (jpg/png/webp)"}), 400
    if f.content_length and f.content_length > 2 * 1024 * 1024:
        return jsonify({"error": "Fichier trop volumineux (max 2 MB)"}), 400
    try:
        from PIL import Image
        from io import BytesIO
        img_data = BytesIO(f.read())
        img = Image.open(img_data).convert('RGB')
        img = img.resize((128, 128), Image.LANCZOS)
        avatars_dir = os.path.join(BASE_DIR, 'dashboard', 'static', 'avatars')
        os.makedirs(avatars_dir, exist_ok=True)
        out_path = os.path.join(avatars_dir, f'{u}.jpg')
        img.save(out_path, 'JPEG', quality=85)
        return jsonify({"ok": True})
    except ImportError:
        return jsonify({"error": "pip install pillow"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/profile/password', methods=['POST'])
@login_required
def profile_change_password():
    u  = current_user()
    d  = request.get_json() or {}
    old_pw = d.get('old_password','')
    new_pw = d.get('new_password','')
    if not old_pw or not new_pw:
        return jsonify({"error":"Tous les champs sont requis"}), 400
    if len(new_pw) < 8:
        return jsonify({"error":"Mot de passe trop court (8 car. min)"}), 400
    users = load_users()
    if u not in users:
        return jsonify({"error":"Utilisateur introuvable"}), 404
    if not check_password_hash(users[u]['password'], old_pw):
        return jsonify({"error":"Mot de passe actuel incorrect"}), 401
    users[u]['password'] = generate_password_hash(new_pw)
    save_users(users)
    return jsonify({"ok": True})

@app.route('/profile/lang', methods=['POST'])
@login_required
def profile_set_lang():
    d    = request.get_json() or {}
    lang = d.get('lang', 'fr')
    if lang not in ('fr', 'en'):
        return jsonify({"error": "Langue non supportée"}), 400
    users = load_users()
    u     = current_user()
    if u in users:
        users[u]['lang'] = lang
        save_users(users)
    return jsonify({"ok": True, "lang": lang})

@app.route('/avatar/<username>')
@login_required
def serve_avatar(username):
    avatars_dir = os.path.join(BASE_DIR, 'dashboard', 'static', 'avatars')
    path = os.path.join(avatars_dir, f'{username}.jpg')
    if not os.path.exists(path):
        return jsonify({"error": "Pas d'avatar"}), 404
    return send_file(path, mimetype='image/jpeg')

# ══════════════════════════════════════════════════════════════════
# 2FA SETUP ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/setup-2fa', methods=['GET'])
@login_required
def setup_2fa_page():
    u = load_users().get(current_user(), {})
    dashboard_url = '/admin' if u.get('role') == 'admin' else '/dashboard'
    return render_template('setup_2fa.html', dashboard_url=dashboard_url)

@app.route('/api/2fa/generate', methods=['POST'])
@login_required
def api_2fa_generate():
    if not TOTP_SUPPORTED:
        return jsonify({"error":"pyotp non installé. pip install pyotp qrcode[pil]"}), 500
    users  = load_users()
    u      = current_user()
    # Générer ou réutiliser le secret
    secret = users[u].get('totp_secret') or generate_totp_secret()
    users[u]['totp_secret'] = secret
    save_users(users)
    uri    = get_totp_uri(secret, u)
    qr_b64 = generate_qr_b64(uri)
    return jsonify({"qr": qr_b64, "secret": secret})

@app.route('/api/2fa/enable', methods=['POST'])
@login_required
def api_2fa_enable():
    d      = request.get_json() or {}
    code   = d.get('code','').replace(' ','')
    users  = load_users()
    u      = current_user()
    secret = users[u].get('totp_secret')
    if not secret:
        return jsonify({"error":"Générez d'abord le QR code"}), 400
    if not verify_totp(secret, code):
        return jsonify({"error":"Code incorrect"}), 401
    users[u]['totp_enabled'] = True
    save_users(users)
    session['2fa_ok'] = True
    return jsonify({"ok":True,"message":"2FA activé avec succès !"})

@app.route('/api/2fa/disable', methods=['POST'])
@login_required
def api_2fa_disable():
    d      = request.get_json() or {}
    code   = d.get('code','').replace(' ','')
    users  = load_users()
    u      = current_user()
    secret = users[u].get('totp_secret')
    if not verify_totp(secret, code):
        return jsonify({"error":"Code incorrect"}), 401
    users[u]['totp_enabled'] = False
    save_users(users)
    return jsonify({"ok":True,"message":"2FA désactivé"})

# ══════════════════════════════════════════════════════════════════
# PROJECTS
# ══════════════════════════════════════════════════════════════════

PROJECTS_FILE = os.path.join(BASE_DIR, 'data', 'projects.json')
ANALYSES_DIR  = os.path.join(BASE_DIR, 'data', 'analyses')

def _load_projects() -> dict:
    db = get_db_session()
    rows = db.query(DBProject).all()
    return {r.id: r.to_dict() for r in rows}

_PROJECT_SKIP_ON_UPDATE = {"id", "created_at", "owner"}

def _save_projects(data: dict) -> None:
    db = get_db_session()
    for pid, pdata in data.items():
        row = db.query(DBProject).filter_by(id=pid).first()
        if row:
            for k, v in pdata.items():
                if k in _PROJECT_SKIP_ON_UPDATE:
                    continue
                if hasattr(row, k):
                    setattr(row, k, v)
        else:
            db.add(DBProject.from_dict(pid, pdata))
    db.commit()


def _project_member_usernames(project_id: str) -> list:
    """Return active DB members for a project."""
    db = get_db_session()
    rows = db.query(DBProjectMember).filter_by(project_id=project_id).all()
    return [r.username for r in rows]


def _is_project_member(project_id: str, username: str) -> bool:
    """Strict membership check from SQL table."""
    db = get_db_session()
    return db.query(DBProjectMember).filter_by(
        project_id=project_id,
        username=username
    ).first() is not None


def _user_email(username: str) -> str:
    users = load_users()
    return (users.get(username) or {}).get("email", "").strip().lower()




@app.route('/projects/api/<project_id>/analysis-report')
@login_required
def project_analysis_report(project_id):
    projects = _load_projects()
    u = current_user()
    p = projects.get(project_id)

    if not p or (p.get('owner') != u and u not in p.get('members', []) and session.get('role') != 'admin'):
        return jsonify({"error": "Projet introuvable"}), 404

    ts = request.args.get("timestamp", "").strip()
    analyses = _get_project_analyses(project_id)

    analysis = None
    for a in analyses:
        if a.get("timestamp") == ts:
            analysis = a
            break

    if not analysis:
        return jsonify({"error": "Rapport introuvable"}), 404

    results = analysis.get("results") or analysis.get("vulns") or analysis.get("findings") or []

    prepared = []
    for r in results:
        sev = (r.get("severity") or "LOW").upper()
        if "CRITICAL" in sev:
            sev_class = "critical"
        elif "HIGH" in sev:
            sev_class = "high"
        elif "MEDIUM" in sev:
            sev_class = "medium"
        elif "LOW" in sev:
            sev_class = "low"
        else:
            sev_class = "info"

        conf = int(float(r.get("confidence", 0) or 0))
        if conf >= 90:
            conf_label = "✓ Prêt à appliquer"
        elif conf >= 70:
            conf_label = "~ Vérifier le diff"
        else:
            conf_label = "⚠ Correction manuelle"

        diff = r.get("diff") or ""

        prepared.append({
            **r,
            "severity_class": sev_class,
            "severity_label": sev,
            "confidence": conf,
            "conf_label": conf_label,
            "diff_lines": diff.splitlines() if diff else [],
            "from_cache": r.get("from_cache", False),
            "explanation": r.get("explanation") or r.get("message") or "",
            "fix_recommendation": r.get("fix_recommendation") or r.get("recommendation") or "",
        })

    html = render_template(
        "report_template.html",
        results=prepared,
        total_vulns=analysis.get("total_vulns", analysis.get("total", len(prepared))),
        validated=analysis.get("patches_validated", analysis.get("validated", 0)),
        rejected=analysis.get("patches_rejected", analysis.get("rejected", 0)),
        success_rate=analysis.get("success_rate", 0),
        mttr=analysis.get("mttr_seconds", analysis.get("mttr", 0)),
        duration=analysis.get("total_duration", analysis.get("duration", 0)),
        cache_hits=analysis.get("cache_hits", 0),
        cache_savings=analysis.get("cache_savings", 0),
        avg_confidence=analysis.get("avg_confidence", 0),
        gen_date=analysis.get("timestamp", ""),
        username=analysis.get("username", u),
    )

    filename = f"rapport_patchmind_{project_id}_{ts.replace(':','-')}.html"

    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


def _get_project_analyses(project_id):
    """Load all saved analyses for a project from disk."""
    d = os.path.join(ANALYSES_DIR, project_id)
    if not os.path.isdir(d):
        return []
    results = []
    for fname in os.listdir(d):
        if fname.endswith('.json'):
            data = _read_json(os.path.join(d, fname), {})
            if data:
                results.append(data)
    results.sort(key=lambda x: x.get('timestamp',''), reverse=True)
    return results

def _save_analysis(project_id, metrics_snapshot):
    """Persist an analysis snapshot under data/analyses/<project_id>/."""
    os.makedirs(os.path.join(ANALYSES_DIR, project_id), exist_ok=True)
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    aid  = f"analysis_{ts}"
    path = os.path.join(ANALYSES_DIR, project_id, aid + '.json')
    _write_json(path, {**metrics_snapshot, 'id': aid, 'timestamp': datetime.now().isoformat()})
    return aid

def _project_stats(project_id):
    analyses = _get_project_analyses(project_id)
    total_vulns   = sum(a.get('total_vulns', 0) for a in analyses)
    total_patches = sum(a.get('patches_validated', 0) for a in analyses)
    avg_rate      = round(sum(a.get('success_rate', 0) for a in analyses) / len(analyses), 1) if analyses else 0
    last          = analyses[0].get('timestamp', '') if analyses else ''
    return {
        'analysis_count': len(analyses),
        'total_vulns':    total_vulns,
        'total_patches':  total_patches,
        'avg_rate':       avg_rate,
        'last_analysis':  last,
    }



def _project_members_sql(project_id: str) -> list:
    db = get_db_session()
    rows = db.query(DBProjectMember).filter_by(project_id=project_id).all()
    return [r.username for r in rows]

def _is_project_member(project_id: str, username: str) -> bool:
    db = get_db_session()
    return db.query(DBProjectMember).filter_by(
        project_id=project_id,
        username=username
    ).first() is not None

def _project_can_access(project_id: str, username: str = None) -> bool:
    username = username or current_user()
    role = session.get("role", "user")
    projects = _load_projects()
    p = projects.get(project_id)
    if not p:
        return False
    return role == "admin" or p.get("owner") == username or _is_project_member(project_id, username)


def _project_has_access(project_id: str, username: str = None) -> bool:
    return _project_can_access(project_id, username)



def _safe_project_download_path(project_id: str, requested_path: str):
    if not requested_path:
        return None

    requested_real = os.path.realpath(requested_path)
    allowed_paths = set()

    for analysis in _get_project_analyses(project_id):
        for f in analysis.get("files_analyzed", []) or []:
            for key in ("path", "original_path", "patched_path"):
                val = f.get(key) if isinstance(f, dict) else None
                if val:
                    allowed_paths.add(os.path.realpath(val))

        for pf in analysis.get("patched_files", []) or []:
            val = pf.get("path") if isinstance(pf, dict) else None
            if val:
                allowed_paths.add(os.path.realpath(val))

    if requested_real not in allowed_paths:
        return None

    if not os.path.isfile(requested_real):
        return None

    return requested_real


@app.route('/projects')
@login_required
def projects_page():
    return render_template('projects.html')

@app.route('/projects/<project_id>')
@login_required
def project_detail_page(project_id):
    projects = _load_projects()
    u = current_user()
    p = projects.get(project_id)
    if not p or (p.get('owner') != u and not _is_project_member(project_id, u) and session.get('role') != 'admin'):
        return redirect('/projects')
    return render_template('project_detail.html')

@app.route('/projects/api', methods=['GET'])
@login_required
def projects_list():
    projects = _load_projects()
    u = current_user()
    result = []
    for pid, p in projects.items():
        if p.get('owner') != u and not _is_project_member(pid, u) and session.get('role') != 'admin':
            continue
        stats = _project_stats(pid)
        result.append({**p, **stats})
    result.sort(key=lambda x: x.get('created_at',''), reverse=True)
    return jsonify(result)

@app.route('/projects/api', methods=['POST'])
@login_required
def projects_create():
    d    = request.get_json() or {}
    name = d.get('name','').strip()
    if not name:
        return jsonify({"error": "Le nom est requis"}), 400
    import uuid
    pid = 'proj_' + uuid.uuid4().hex[:12]
    projects = _load_projects()
    projects[pid] = {
        'id':          pid,
        'name':        name,
        'description': d.get('description',''),
        'owner':       current_user(),
        'members':     [m for m in d.get('members',[]) if m],
        'department':  d.get('department',''),
        'created_at':  datetime.now().isoformat(),
        'tags':        [t for t in d.get('tags',[]) if t],
        'status':      'active',
    }
    _save_projects(projects)
    return jsonify({"ok": True, "id": pid})

@app.route('/projects/api/<project_id>', methods=['GET'])
@login_required
def project_get(project_id):
    projects = _load_projects()
    u = current_user()
    p = projects.get(project_id)
    if not p or (p.get('owner') != u and not _is_project_member(project_id, u) and session.get('role') != 'admin'):
        return jsonify({"error": "Projet introuvable"}), 404
    # Sync members from SQL before returning project
    p['members'] = _project_member_usernames(project_id)
    p['members'] = _project_members_sql(project_id)
    analyses = _get_project_analyses(project_id)
    return jsonify({"project": p, "analyses": analyses})

@app.route('/projects/api/<project_id>', methods=['DELETE'])
@login_required
def project_delete(project_id):
    """Delete a project completely from SQLite and remove related data."""
    projects = _load_projects()
    u = current_user()
    role = session.get("role", "user")
    proj = projects.get(project_id)

    if not proj:
        return jsonify({"error": "Projet introuvable"}), 404

    if proj.get("owner") != u and role != "admin":
        return jsonify({"error": "Seul le propriétaire ou un administrateur peut supprimer ce projet"}), 403

    db = get_db_session()

    # Delete related rows first
    db.query(DBProjectMember).filter_by(project_id=project_id).delete(synchronize_session=False)
    db.query(DBProjectInvitation).filter_by(project_id=project_id).delete(synchronize_session=False)

    # Delete project itself
    row = db.query(DBProject).filter_by(id=project_id).first()
    if row:
        db.delete(row)

    db.commit()

    # Clean analyses dir
    d = os.path.join(ANALYSES_DIR, project_id)
    if os.path.isdir(d):
        shutil.rmtree(d, ignore_errors=True)

    audit_log("project_deleted", details={
        "project_id": project_id,
        "deleted_by": u
    })

    return jsonify({"ok": True})


@app.route('/projects/api/<project_id>/save-analysis', methods=['POST'])
@login_required
def project_save_analysis(project_id):
    """Called after a pipeline run to save the metrics to the project."""
    projects = _load_projects()
    u = current_user()
    p = projects.get(project_id)
    if not _project_can_access(project_id, u):
        return jsonify({"error": "Projet introuvable"}), 404
    ps = get_pipeline(u)
    m  = ps.get('metrics', {})
    if not m:
        return jsonify({"error": "Aucune métrique disponible"}), 400
    aid = _save_analysis(project_id, {**m, 'username': u, 'project_id': project_id, 'project_name': p.get('name', project_id)})
    return jsonify({"ok": True, "analysis_id": aid})

@app.route('/projects/api/<project_id>/link', methods=['POST'])
@login_required
def project_link_analysis(project_id):
    """Associate a session history entry with a project by analysis_id."""
    projects = _load_projects()
    u = current_user()
    p = projects.get(project_id)
    if not _project_can_access(project_id, u):
        return jsonify({"error": "Projet introuvable"}), 404
    d   = request.get_json() or {}
    aid = d.get('analysis_id','').strip()
    if not aid:
        return jsonify({"error": "analysis_id requis"}), 400
    # Look in user session history for a matching timestamp
    hist = _read_json(get_user_metrics_path(u), {"sessions": []})
    match = next((s for s in hist.get('sessions',[]) if aid in s.get('timestamp','').replace(':','').replace('-','').replace(' ','_')[:19]), None)
    if not match:
        return jsonify({"error": "Analyse non trouvée"}), 404
    _save_analysis(project_id, {**match, 'username': u})
    return jsonify({"ok": True})


@app.route('/projects/api/<project_id>', methods=['PUT'])
@login_required
def project_edit(project_id):
    """Edit project metadata (owner only)."""
    projects = _load_projects()
    u = current_user()
    p = projects.get(project_id)
    if not p:
        return jsonify({"error": "Projet introuvable"}), 404
    if p['owner'] != u:
        return jsonify({"error": "Seul le propriétaire peut modifier ce projet"}), 403
    d = request.get_json() or {}
    allowed = {'name', 'description', 'department', 'tags', 'status'}
    for k in allowed:
        if k in d:
            p[k] = d[k]
    if not p.get('name', '').strip():
        return jsonify({"error": "Le nom est requis"}), 400
    projects[project_id] = p
    _save_projects(projects)
    return jsonify({"ok": True, "project": p})


@app.route('/projects/api/<project_id>/members', methods=['GET'])
@login_required
def project_members_list(project_id):
    """List members and invitations (all statuses) for a project."""
    projects = _load_projects()
    u    = current_user()
    role = session.get('role', 'user')
    p    = projects.get(project_id)
    if not _project_can_access(project_id, u):
        return jsonify({"error": "Projet introuvable"}), 404
    db  = get_db_session()
    now = datetime.now()
    members = db.query(DBProjectMember).filter_by(project_id=project_id).all()
    invitations = (db.query(DBProjectInvitation)
                   .filter_by(project_id=project_id)
                   .order_by(DBProjectInvitation.created_at.desc())
                   .all())
    # Auto-expire pending/approved invitations past their expiry
    for inv in invitations:
        if inv.status in ('pending', 'approved') and inv.expires_at and inv.expires_at < now:
            inv.status = 'expired'
    db.commit()
    return jsonify({
        "members":     [m.to_dict() for m in members],
        "invitations": [i.to_dict() for i in invitations],
    })


@app.route('/projects/api/<project_id>/invite', methods=['POST'])
@login_required
def project_invite(project_id):
    """Create a pending invitation request — requires admin approval before activation."""
    projects = _load_projects()
    u    = current_user()
    role = session.get('role', 'user')
    p    = projects.get(project_id)
    if not _project_can_access(project_id, u):
        return jsonify({"error": "Projet introuvable"}), 404
    d     = request.get_json() or {}
    email = (d.get('email') or '').strip().lower()
    inv_role = d.get('role', 'member')
    if not email or '@' not in email:
        return jsonify({"error": "Email invalide"}), 400
    # Only allow member/viewer roles for regular users
    allowed_roles = ('member', 'viewer', 'owner') if role == 'admin' else ('member', 'viewer')
    if inv_role not in allowed_roles:
        inv_role = 'member'

    db = get_db_session()
    # Prevent duplicate active pending/approved invitation for same email+project
    dup = (db.query(DBProjectInvitation)
             .filter(DBProjectInvitation.project_id == project_id,
                     DBProjectInvitation.email == email,
                     DBProjectInvitation.status.in_(['pending']))
             .first())
    if dup:
        return jsonify({"error": "Une invitation est déjà en attente pour cet email"}), 409

    # Check email is not already a member
    users = load_users()
    existing_uname = next((un for un, ud in users.items()
                           if ud.get('email', '').lower() == email), None)
    if existing_uname:
        already = (db.query(DBProjectMember)
                     .filter_by(project_id=project_id, username=existing_uname)
                     .first())
        if already:
            return jsonify({"error": "Cet utilisateur est déjà membre du projet"}), 409

    token = secrets.token_urlsafe(32)
    inv = DBProjectInvitation(
        project_id = project_id,
        invited_by = u,
        email      = email,
        token      = token,
        role       = inv_role,
        status     = 'pending',
        expires_at = datetime.now() + timedelta(days=30),
    )
    db.add(inv)
    db.commit()
    audit_log("invitation_created", details={
        "project_id": project_id, "email": email, "role": inv_role, "invited_by": u
    })
    return jsonify({
        "ok":      True,
        "id":      inv.id,
        "message": "Invitation soumise. Un administrateur doit l'approuver avant activation.",
        "pending_approval": True,
    })


@app.route('/project-invitations/<token>', methods=['GET'])
def project_invitation_view(token):
    """View an invitation — renders HTML page."""
    if 'username' not in session:
        return redirect(url_for('login_page') + f'?next=/project-invitations/{token}')
    db  = get_db_session()
    inv = db.query(DBProjectInvitation).filter_by(token=token).first()
    if not inv:
        return render_template('project_invitation.html',
                               inv=None, project=None, token=token,
                               error="Invitation introuvable"), 404
    if inv.status in ('pending', 'approved') and inv.expires_at < datetime.now():
        inv.status = 'expired'
        db.commit()
    projects = _load_projects()
    p = projects.get(inv.project_id, {})
    u = current_user()
    users      = load_users()
    user_email = (users.get(u) or {}).get('email', '').lower()
    email_match = (user_email == inv.email)
    return render_template('project_invitation.html',
                           inv=inv, project=p, token=token,
                           current_user=u, email_match=email_match, error=None)


@app.route('/project-invitations/<token>/accept', methods=['POST'])
@login_required
def project_invitation_accept(token):
    """Accept an approved invitation.
    For existing-user flow: user clicks the link to formally accept.
    For new-user flow: user is already added at approval time; this just marks accepted.
    """
    db  = get_db_session()
    inv = db.query(DBProjectInvitation).filter_by(token=token).first()
    if not inv:
        return jsonify({"error": "Invitation introuvable"}), 404
    if inv.status == 'pending':
        return jsonify({"error": "Cette invitation est en attente d'approbation par un administrateur"}), 409
    if inv.status not in ('approved',):
        return jsonify({"error": f"Cette invitation est '{inv.status}'"}), 409
    if inv.expires_at < datetime.now():
        inv.status = 'expired'
        db.commit()
        return jsonify({"error": "Cette invitation a expiré"}), 410

    u = current_user()
    # Verify the user's email matches the invitation
    users = load_users()
    user_email = (users.get(u) or {}).get('email', '').lower()
    if user_email != inv.email:
        return jsonify({"error": "Cette invitation ne vous est pas destinée"}), 403

    # Ensure member row exists (may already exist from approval step)
    already = (db.query(DBProjectMember)
                 .filter_by(project_id=inv.project_id, username=u)
                 .first())
    if not already:
        db.add(DBProjectMember(
            project_id=inv.project_id,
            username=u,
            role=inv.role or 'member',
        ))
        projects = _load_projects()
        p = projects.get(inv.project_id)
        if p:
            members = list(p.get('members', []))
            if u not in members:
                members.append(u)
            p['members'] = members
            projects[inv.project_id] = p
            _save_projects(projects)

    inv.status       = 'accepted'
    inv.responded_at = datetime.now()
    db.commit()
    audit_log("invitation_accepted", details={"project_id": inv.project_id, "email": inv.email})
    if request.accept_mimetypes.accept_html and not request.is_json:
        return redirect(f'/project/{inv.project_id}')
    return jsonify({"ok": True, "project_id": inv.project_id})


@app.route('/project-invitations/<token>/reject', methods=['POST'])
@login_required
def project_invitation_reject(token):
    """Reject a project invitation (invitee declining after approval)."""
    db  = get_db_session()
    inv = db.query(DBProjectInvitation).filter_by(token=token).first()
    if not inv:
        return jsonify({"error": "Invitation introuvable"}), 404
    if inv.status not in ('pending', 'approved'):
        return jsonify({"error": f"Cette invitation est déjà {inv.status}"}), 409
    inv.status       = 'rejected'
    inv.rejected_at  = datetime.now()
    inv.responded_at = datetime.now()
    db.commit()
    audit_log("invitation_declined", details={"project_id": inv.project_id, "token": token[:8]})
    if request.accept_mimetypes.accept_html and not request.is_json:
        return redirect(f'/project-invitations/{token}')
    return jsonify({"ok": True})


@app.route('/projects/api/<project_id>/invitations/<int:inv_id>/cancel', methods=['POST'])
@login_required
def project_invitation_cancel(project_id, inv_id):
    """Cancel a pending invitation (requester, project owner, or admin)."""
    projects = _load_projects()
    u    = current_user()
    role = session.get('role', 'user')
    p    = projects.get(project_id)
    if not p:
        return jsonify({"error": "Projet introuvable"}), 404
    db  = get_db_session()
    inv = db.query(DBProjectInvitation).filter_by(id=inv_id, project_id=project_id).first()
    if not inv:
        return jsonify({"error": "Invitation introuvable"}), 404
    if inv.status not in ('pending', 'approved'):
        return jsonify({"error": f"Impossible d'annuler une invitation '{inv.status}'"}), 409
    # RBAC: requester, project owner, or admin can cancel
    is_owner = p.get('owner') == u
    is_admin = role == 'admin'
    is_requester = inv.invited_by == u
    if not (is_owner or is_admin or is_requester):
        return jsonify({"error": "Non autorisé"}), 403
    inv.status       = 'cancelled'
    inv.cancelled_at = datetime.now()
    inv.cancelled_by = u
    db.commit()
    audit_log("invitation_cancelled", details={
        "project_id": project_id, "email": inv.email, "cancelled_by": u
    })
    return jsonify({"ok": True})


@app.route('/projects/api/<project_id>/members/<member_username>', methods=['DELETE'])
@login_required
def project_member_remove(project_id, member_username):
    """Remove a member from a project and revoke his access completely."""
    projects = _load_projects()
    u = current_user()
    role = session.get('role', 'user')
    p = projects.get(project_id)

    if not p:
        return jsonify({"error": "Projet introuvable"}), 404

    if role != "admin" and p.get("owner") != u:
        return jsonify({"error": "Seul le propriétaire ou un administrateur peut retirer un membre"}), 403

    if member_username == p.get("owner"):
        return jsonify({"error": "Impossible de retirer le propriétaire du projet"}), 400

    db = get_db_session()

    # 1) Delete SQL membership
    rows = db.query(DBProjectMember).filter_by(
        project_id=project_id,
        username=member_username
    ).all()

    for row in rows:
        db.delete(row)

    # 2) Remove from Project.members JSON column
    p["members"] = [m for m in p.get("members", []) if m != member_username]
    projects[project_id] = p
    _save_projects(projects)

    # 3) Find user email
    users = load_users()
    email = (users.get(member_username) or {}).get("email", "").strip().lower()

    # 4) Cancel old invitations for this user/email
    if email:
        invs = db.query(DBProjectInvitation).filter(
            DBProjectInvitation.project_id == project_id,
            DBProjectInvitation.email == email,
            DBProjectInvitation.status.in_(["pending", "approved", "accepted"])
        ).all()

        for inv in invs:
            inv.status = "cancelled"
            inv.cancelled_at = datetime.now()
            inv.cancelled_by = u

    db.commit()

    audit_log("member_removed", details={
        "project_id": project_id,
        "removed_user": member_username,
        "email": email,
        "by": u
    })

    return jsonify({"ok": True, "removed_user": member_username})




# ══════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/admin')
@login_required
@admin_required
def admin_page(): return render_template('admin.html')


# ── Admin: Invitation management ──────────────────────────────────────────────

@app.route('/admin/api/invitations', methods=['GET'])
@login_required
@admin_required
def admin_list_invitations():
    """Return all project invitations with optional status filter."""
    status_filter = request.args.get('status', '').strip()
    db = get_db_session()
    q  = db.query(DBProjectInvitation).order_by(DBProjectInvitation.created_at.desc())
    if status_filter:
        statuses = [s.strip() for s in status_filter.split(',') if s.strip()]
        q = q.filter(DBProjectInvitation.status.in_(statuses))
    invitations = q.limit(500).all()
    # Enrich with project name
    projects = _load_projects()
    result = []
    for inv in invitations:
        d = inv.to_dict()
        p = projects.get(inv.project_id, {})
        d['project_name'] = p.get('name', inv.project_id)
        result.append(d)
    pending_count = db.query(DBProjectInvitation).filter_by(status='pending').count()
    return jsonify({"ok": True, "invitations": result, "pending_count": pending_count})


@app.route('/admin/api/invitations/<int:inv_id>/approve', methods=['POST'])
@login_required
@admin_required
def admin_approve_invitation(inv_id):
    """
    Admin approves a pending invitation.
    CASE 1 — email belongs to existing user: add to project + send notification.
    CASE 2 — email unknown: create account, generate temp password, send credentials, add to project.
    """
    db  = get_db_session()
    inv = db.query(DBProjectInvitation).filter_by(id=inv_id).first()
    if not inv:
        return jsonify({"error": "Invitation introuvable"}), 404
    if inv.status != 'pending':
        return jsonify({"error": f"Invitation déjà '{inv.status}'"}), 409

    admin = current_user()
    now   = datetime.now()
    users = load_users()
    email = inv.email.lower()

    # Locate existing user by email
    existing_uname = next((un for un, ud in users.items()
                           if ud.get('email', '').lower() == email and ud.get('active', True)), None)

    projects = _load_projects()
    p = projects.get(inv.project_id, {})
    project_name = p.get('name', inv.project_id)
    email_sent = False

    if existing_uname:
        # ── Case 1: existing user ──────────────────────────────────
        already = (db.query(DBProjectMember)
                     .filter_by(project_id=inv.project_id, username=existing_uname)
                     .first())
        if not already:
            db.add(DBProjectMember(
                project_id=inv.project_id,
                username=existing_uname,
                role=inv.role or 'member',
            ))
            # Sync to Project.members JSON column
            members = list(p.get('members', []))
            if existing_uname not in members:
                members.append(existing_uname)
            p['members'] = members
            projects[inv.project_id] = p
            _save_projects(projects)

        inv.invited_existing_user = True
        inv.provisioned_username  = existing_uname

        # Send notification email (non-blocking)
        invite_url = request.host_url.rstrip('/') + f'/project-invitations/{inv.token}'
        try:
            email_sent = send_project_invitation_email(
                to_email     = email,
                invited_by   = inv.invited_by or admin,
                project_name = project_name,
                invite_url   = invite_url,
                role         = inv.role or 'member',
                expires_at   = inv.expires_at,
            )
        except Exception:
            pass

        audit_log("invitation_approved", details={
            "project_id": inv.project_id, "email": email,
            "existing_user": existing_uname, "approved_by": admin,
        })

    else:
        # ── Case 2: new user — create account ─────────────────────
        # Derive username from email, ensure uniqueness
        base = re.sub(r'[^a-zA-Z0-9_]', '_', email.split('@')[0])[:20] or 'user'
        username = base
        counter  = 1
        while username in users:
            username = f"{base}_{counter}"
            counter += 1

        temp_password = generate_password(14)
        hashed        = generate_password_hash(temp_password)
        new_user_data = {
            "password":             hashed,
            "role":                 "analyst",
            "full_name":            "",
            "email":                email,
            "must_change_password": True,
            "active":               True,
            "created_at":           now.isoformat(),
        }
        users[username] = new_user_data
        save_users(users)

        # Add to project
        db.add(DBProjectMember(
            project_id=inv.project_id,
            username=username,
            role=inv.role or 'member',
        ))
        members = list(p.get('members', []))
        if username not in members:
            members.append(username)
        p['members'] = members
        projects[inv.project_id] = p
        _save_projects(projects)

        inv.invited_existing_user = False
        inv.provisioned_username  = username

        # Send credentials email
        try:
            email_sent = send_credentials_email(
                to_email  = email,
                full_name = username,
                username  = username,
                password  = temp_password,
            )
            inv.credentials_sent = email_sent
        except Exception:
            pass

        audit_log("invitation_approved_new_user", details={
            "project_id": inv.project_id, "email": email,
            "new_username": username, "approved_by": admin,
            "credentials_sent": email_sent,
        })

    inv.status      = 'approved'
    inv.approved_by = admin
    inv.approved_at = now
    db.commit()

    audit_log("member_added", details={
        "project_id": inv.project_id,
        "username": inv.provisioned_username,
        "role": inv.role,
        "via": "invitation_approval",
    })

    return jsonify({
        "ok":               True,
        "existing_user":    inv.invited_existing_user,
        "provisioned_user": inv.provisioned_username,
        "email_sent":       email_sent,
    })


@app.route('/admin/api/invitations/<int:inv_id>/reject', methods=['POST'])
@login_required
@admin_required
def admin_reject_invitation(inv_id):
    """Admin rejects a pending invitation with optional reason."""
    db  = get_db_session()
    inv = db.query(DBProjectInvitation).filter_by(id=inv_id).first()
    if not inv:
        return jsonify({"error": "Invitation introuvable"}), 404
    if inv.status != 'pending':
        return jsonify({"error": f"Invitation déjà '{inv.status}'"}), 409
    d      = request.get_json() or {}
    reason = (d.get('reason') or '').strip()[:500]
    admin  = current_user()
    now    = datetime.now()
    inv.status           = 'rejected'
    inv.rejected_at      = now
    inv.rejection_reason = reason
    inv.approved_by      = admin   # repurpose field to track who acted
    db.commit()
    audit_log("invitation_rejected", details={
        "project_id": inv.project_id, "email": inv.email,
        "reason": reason, "rejected_by": admin,
    })
    return jsonify({"ok": True})


@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_list_users():
    users = load_users(); result = []
    for uname, ud in users.items():
        if not ud.get('active', True):   # skip soft-deleted accounts
            continue
        mp   = get_user_metrics_path(uname)
        data = _read_json(mp,{"sessions":[]})
        sess = data.get("sessions",[])
        result.append({
            "username":      uname,
            "role":          ud.get("role","user"),
            "full_name":     ud.get("full_name",uname),
            "created_at":    ud.get("created_at",""),
            "active":        ud.get("active",True),
            "totp_enabled":  ud.get("totp_enabled",False),
            "sessions":      len(sess),
            "total_vulns":   sum(s.get("total_vulns",0) for s in sess),
            "total_patches": sum(s.get("patches_validated",0) for s in sess),
            "company":       ud.get("company",""),
            "blocked":       ud.get("blocked", False),
            "email":         ud.get("email",""),
        })
    return jsonify(result)

@app.route('/admin/users', methods=['POST'])
@login_required
@admin_required
def admin_create_user():
    d = request.get_json() or {}
    u     = d.get('username','').strip()
    email = d.get('email','').strip()
    if not u or not email: return jsonify({"error":"Identifiant et email requis"}), 400
    users = load_users()
    if u in users: return jsonify({"error":"Utilisateur déjà existant"}), 400
    role = d.get('role', 'analyst')
    if role not in RBAC_ROLES:
        role = 'analyst'
    p = generate_password()
    users[u] = {
        "password":             generate_password_hash(p),
        "email":                email,
        "role":                 role,
        "full_name":            d.get('full_name', u),
        "company":              d.get('company',''),
        "created_at":           datetime.now().isoformat(),
        "totp_secret":          generate_totp_secret(),
        "totp_enabled":         False,
        "active":               True,
        "blocked":              False,
        "must_change_password": True,
    }
    save_users(users)
    os.makedirs(os.path.join(DATA_DIR, u, 'uploads'), exist_ok=True)
    full_name = d.get('full_name', u)
    email_sent = send_credentials_email(to_email=email, full_name=full_name, username=u, password=p)
    if not email_sent:
        return jsonify({"ok": True, "warn": "Compte créé mais email non envoyé — vérifiez la config SMTP"}), 207
    return jsonify({"ok": True})

@app.route('/admin/users/<username>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_user(username):
    current_user = session.get('username')
    if username == current_user:
        return jsonify({"ok": False, "error": "Impossible de supprimer votre propre compte"}), 400

    users = load_users()
    if username not in users:
        return jsonify({"ok": False, "error": "Utilisateur introuvable"}), 404

    target = users[username]

    # Protect last active admin
    if target.get('role') == 'admin':
        admin_count = sum(
            1 for u in users.values()
            if u.get('role') == 'admin' and u.get('active', True)
        )
        if admin_count <= 1:
            return jsonify({"ok": False, "error": "Impossible de supprimer le dernier compte administrateur"}), 400

    # Soft delete — deactivate and block the account
    save_users({username: {**target, "active": False, "blocked": True}})
    return jsonify({"ok": True, "message": "Utilisateur supprimé."})

@app.route('/admin/users/<username>/toggle', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user(username):
    if username == 'admin': return jsonify({"error":"Non autorisé"}), 400
    users = load_users()
    if username not in users: return jsonify({"error":"Introuvable"}), 404
    users[username]['active'] = not users[username].get('active',True)
    save_users(users)
    return jsonify({"ok":True,"active":users[username]['active']})

@app.route('/admin/users/<username>/role', methods=['POST'])
@login_required
@admin_required
def admin_change_role(username):
    if username == 'admin': return jsonify({"error":"Non autorisé"}), 400
    users = load_users()
    if username not in users: return jsonify({"error":"Introuvable"}), 404
    d    = request.get_json() or {}
    role = d.get('role', '').strip()
    if role not in RBAC_ROLES:
        return jsonify({"error": f"Rôle invalide. Valeurs acceptées: {', '.join(RBAC_ROLES)}"}), 400
    users[username]['role'] = role
    save_users(users)
    return jsonify({"ok": True, "role": role})

@app.route('/admin/users/<username>/block', methods=['POST'])
@login_required
@admin_required
def admin_block_user(username):
    if username == 'admin': return jsonify({"error":"Non autorisé"}), 400
    users = load_users()
    if username not in users: return jsonify({"error":"Introuvable"}), 404
    d = request.get_json() or {}
    users[username]['blocked'] = bool(d.get('block', True))
    save_users(users)
    return jsonify({"ok": True, "blocked": users[username]['blocked']})

@app.route('/admin/stats')
@login_required
@admin_required
def admin_stats():
    users    = load_users()
    db       = get_db_session()
    rows     = db.query(DBMetric).order_by(DBMetric.timestamp.desc()).all()
    all_sess = []
    for m in rows:
        sd = m.to_dict()
        sd["username"] = m.username
        all_sess.append(sd)
    return jsonify({
        "total_users":    len(users),
        "total_sessions": len(all_sess),
        "total_vulns":    sum(s.get("total_vulns",   0) for s in all_sess),
        "total_patches":  sum(s.get("patches_validated", 0) for s in all_sess),
        "recent":         all_sess[:50],
    })

# ══════════════════════════════════════════════════════════════════
# MAIN ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def index(): return render_template('index.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if not _rate_check(request.remote_addr, 'upload', 10, 60):
        return jsonify({"error": "Trop de requêtes. Réessayez dans une minute."}), 429
    u=current_user(); uld=get_user_upload_dir(u)
    if 'file' not in request.files: return jsonify({"error":"Aucun fichier"}),400
    f=request.files['file']
    if not f.filename: return jsonify({"error":"Nom vide"}),400
    fname=secure_filename(f.filename)
    if not fname: return jsonify({"error":"Nom de fichier invalide"}),400
    ext=os.path.splitext(fname)[1].lower()
    # Allowlist check before writing to disk
    _allowed_upload = set(SUPPORTED_EXTENSIONS) | {'.zip', '.rar'}
    if ext not in _allowed_upload:
        return jsonify({"error":f"Extension '{ext}' non supportée"}),400
    # Prevent silent overwrite: add a short unique suffix if file already exists
    if os.path.exists(os.path.join(uld, fname)):
        base, suf = os.path.splitext(fname)
        fname = f"{base}_{int(time.time())}{suf}"
    fpath=os.path.join(uld,fname)
    f.save(fpath)

    try:
        _ct = json.loads(request.form.get("custom_tools","[]"))
    except (json.JSONDecodeError, TypeError):
        _ct = []
    try:
        _ot = json.loads(request.form.get("optional_tools","[]"))
        if not isinstance(_ot, list):
            _ot = []
    except (json.JSONDecodeError, TypeError):
        _ot = []
    scanners = {
        "semgrep":        request.form.get("semgrep","true").lower()=="true",
        "gitleaks":       request.form.get("gitleaks","true").lower()=="true",
        "snyk":           request.form.get("snyk","true").lower()=="true",
        "zap":            request.form.get("zap","true").lower()=="true",
        "zap_url":        request.form.get("zap_url","").strip(),
        "custom_tools":   _ct,
        "optional_tools": _ot,
    }

    job_id = secrets.token_urlsafe(12)
    ps = get_pipeline(u)
    ps.update({"running": True, "progress": 0, "results": [], "logs": [], "metrics": {}, "job_id": job_id})

    if ext=='.rar':
        def _rar():
            try:
                logp(u,f"📦 Extraction RAR : {fname}")
                files,_=extract_rar(fpath,uld)
                if not files: logp(u,"⚠️ Vide"); ps["running"]=False; return
                logp(u,f"✅ {len(files)} fichier(s)"); run_pipeline(u,files,scanners)
            except Exception as e: logp(u,f"❌ {e}"); ps["running"]=False
        threading.Thread(target=_rar,daemon=True).start()
        return jsonify({"message": "RAR lancé", "job_id": job_id})

    if ext=='.zip':
        def _zip():
            try:
                logp(u,f"📦 Extraction ZIP : {fname}")
                files,_=extract_zip(fpath,uld)
                if not files: logp(u,"⚠️ Vide"); ps["running"]=False; return
                logp(u,f"✅ {len(files)} fichier(s)"); run_pipeline(u,files,scanners)
            except Exception as e: logp(u,f"❌ {e}"); ps["running"]=False
        threading.Thread(target=_zip,daemon=True).start()
        return jsonify({"message": "ZIP lancé", "job_id": job_id})

    threading.Thread(target=run_pipeline,args=(u,[fpath],scanners),daemon=True).start()
    return jsonify({"message": "Analyse lancée", "job_id": job_id})

@app.route('/github', methods=['POST'])
@login_required
def github_analyze():
    if not _rate_check(request.remote_addr, 'github', 5, 60):
        return jsonify({"error": "Trop de requêtes. Réessayez dans une minute."}), 429
    u=current_user(); uld=get_user_upload_dir(u)
    d=request.get_json() or {}; url=d.get('url','').strip()
    try:
        _validate_git_url(url)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    _ot_gh = d.get("optional_tools", [])
    if not isinstance(_ot_gh, list):
        _ot_gh = []
    scanners = {
        "semgrep":        d.get("semgrep", True),
        "gitleaks":       d.get("gitleaks", True),
        "snyk":           d.get("snyk", True),
        "zap":            d.get("zap", True),
        "zap_url":        d.get("zap_url", "").strip(),
        "custom_tools":   d.get("custom_tools", []),
        "optional_tools": _ot_gh,
    }
    job_id = secrets.token_urlsafe(12)
    ps = get_pipeline(u)
    ps.update({"running": True, "progress": 0, "results": [], "logs": [], "metrics": {}, "job_id": job_id})
    def _gh():
        try:
            logp(u,f"📥 Clonage : {url}")
            cp=clone_repo(url,uld); fs=get_supported_files(cp)
            if not fs: logp(u,"⚠️ Vide"); ps["running"]=False; return
            logp(u,f"✅ {len(fs)} fichier(s)"); run_pipeline(u,fs,scanners)
        except Exception as e: logp(u,f"❌ {e}"); ps["running"]=False
    threading.Thread(target=_gh,daemon=True).start()
    return jsonify({"message": "GitHub lancé", "job_id": job_id})

@app.route('/status')
@login_required
def status():
    u  = current_user()
    ps = get_pipeline(u)
    job_id = request.args.get('job_id')
    if job_id and ps.get('job_id') != job_id:
        return jsonify({"error": "job_id not found", "running": False}), 404
    return jsonify(ps)

@app.route('/files')
@login_required
def list_files():
    u       = current_user()
    job_id  = request.args.get('job_id', '').strip()

    # Scoped to a specific analysis job: return only files produced by that job
    if job_id:
        ps = get_pipeline(u)
        if ps.get('job_id') == job_id:
            return jsonify(ps.get('metrics', {}).get('patched_files', []))
        return jsonify([])

    # No job_id: return recent patched files from the user's directory
    user_dir  = get_user_upload_dir(u)
    role      = session.get('role', 'user')
    show_all  = request.args.get('all', 'false').lower() == 'true' and role == 'admin'
    minutes   = int(request.args.get('minutes', 60))
    cutoff    = time.time() - minutes * 60 if not show_all else 0
    files = []
    for root, dirs, fnames in os.walk(user_dir):
        for fname in fnames:
            if '_patched' not in fname: continue
            if '_temp_check' in fname: continue
            fp = os.path.join(root, fname)
            st = os.stat(fp)
            if st.st_mtime < cutoff:
                continue
            files.append({
                "name":       fname,
                "path":       fp,
                "size":       round(st.st_size / 1024, 1),
                "patched_at": datetime.fromtimestamp(st.st_mtime).strftime("%d/%m/%Y %H:%M"),
            })
    files.sort(key=lambda x: x["patched_at"], reverse=True)
    return jsonify(files)

# ── False Positives (Module 4A) ───────────────────────────────────────────────

def _fp_key(cwe: str, message_snippet: str) -> str:
    import hashlib
    raw = f"{cwe}::{message_snippet[:80]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def is_false_positive(cwe: str, message: str, threshold: int = 2) -> bool:
    try:
        db  = get_db_session()
        key = _fp_key(cwe, message)
        row = db.query(DBFalsePositive).filter_by(vuln_key=key).first()
        return bool(row and (row.confirmed_count or 0) >= threshold)
    except Exception:
        return False

@app.route('/false-positive', methods=['POST'])
@login_required
def mark_false_positive():
    import json as _json
    d   = request.get_json() or {}
    cwe = d.get("cwe", "").strip()
    msg = d.get("message", "").strip()
    if not cwe:
        return jsonify({"error": "CWE requis"}), 400
    db  = get_db_session()
    key = _fp_key(cwe, msg)
    row = db.query(DBFalsePositive).filter_by(vuln_key=key).first()
    u   = current_user()
    now = datetime.now()
    if row is None:
        row = DBFalsePositive(
            vuln_key=key, cwe=cwe, message_snippet=msg[:80],
            reporters=_json.dumps([u]), confirmed_count=1,
            reported_by=u, created_at=now, last_seen=now,
        )
        db.add(row)
    else:
        try:
            reporters = _json.loads(row.reporters or "[]")
        except Exception:
            reporters = []
        if u not in reporters:
            reporters.append(u)
        row.reporters       = _json.dumps(reporters)
        row.confirmed_count = len(reporters)
        row.last_seen       = now
    db.commit()
    audit_log("false_positive_marked", details={"cwe": cwe, "confirmed": row.confirmed_count})
    return jsonify({"ok": True, "confirmed_count": row.confirmed_count,
                    "auto_filtered": row.confirmed_count >= 2})

@app.route('/false-positives', methods=['GET'])
@login_required
def list_false_positives():
    db  = get_db_session()
    rows = db.query(DBFalsePositive).order_by(DBFalsePositive.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rows])

@app.route('/false-positive/<key>', methods=['DELETE'])
@login_required
@admin_required
def delete_false_positive(key):
    db  = get_db_session()
    row = db.query(DBFalsePositive).filter_by(vuln_key=key).first()
    if row:
        db.delete(row)
        db.commit()
    return jsonify({"ok": True})

# ── Assignments (Module 5A) ───────────────────────────────────────────────────

@app.route('/assign', methods=['POST'])
@login_required
def assign_vuln():
    d        = request.get_json() or {}
    vuln_id  = d.get("vuln_id", "").strip()
    assignee = d.get("assignee", "").strip()
    deadline = d.get("deadline", "")
    cwe      = d.get("cwe", "")
    msg      = d.get("message", "")
    if not vuln_id or not assignee:
        return jsonify({"error": "vuln_id et assignee requis"}), 400
    users = load_users()
    if assignee not in users:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    db  = get_db_session()
    row = db.query(DBAssignment).filter_by(vuln_key=vuln_id).first()
    u   = current_user()
    if row:
        row.assignee    = assignee
        row.deadline    = deadline
        row.assigned_by = u
        row.cwe         = cwe
        row.message     = msg[:100]
    else:
        row = DBAssignment(
            vuln_key=vuln_id, cwe=cwe, message=msg[:100],
            assignee=assignee, assigned_by=u, deadline=deadline,
            status="open", created_at=datetime.now(),
        )
        db.add(row)
    db.commit()
    audit_log("vuln_assigned", details={"vuln_id": vuln_id, "assignee": assignee})
    if INTELLIGENCE_OK:
        try:
            send_all_notifications({"type": "assignment", "assignee": assignee, "cwe": cwe}, [], u)
        except Exception:
            pass
    return jsonify({"ok": True})

@app.route('/assignments', methods=['GET'])
@login_required
def list_assignments():
    u    = current_user()
    role = session.get('role', 'user')
    db   = get_db_session()
    if role == 'admin':
        rows = db.query(DBAssignment).order_by(DBAssignment.created_at.desc()).all()
    else:
        rows = db.query(DBAssignment).filter(
            (DBAssignment.assignee == u) | (DBAssignment.assigned_by == u)
        ).order_by(DBAssignment.created_at.desc()).all()
    return jsonify([r.to_dict() for r in rows])

# ── Comments (Module 5B) ──────────────────────────────────────────────────────

def _extract_mentions(text: str):
    return list(set(re.findall(r'@(\w+)', text)))

@app.route('/comments/<vuln_id>', methods=['GET'])
@login_required
def get_comments(vuln_id):
    db   = get_db_session()
    rows = (db.query(DBComment)
              .filter_by(vuln_key=vuln_id)
              .order_by(DBComment.created_at.asc())
              .limit(200)
              .all())
    return jsonify([r.to_dict() for r in rows])

@app.route('/comments/<vuln_id>', methods=['POST'])
@login_required
def post_comment(vuln_id):
    import json as _json
    d    = request.get_json() or {}
    text = d.get("text", "").strip()
    if not text:
        return jsonify({"error": "Commentaire vide"}), 400
    if len(text) > 2000:
        return jsonify({"error": "Commentaire trop long (max 2000 caractères)"}), 400
    u        = current_user()
    mentions = _extract_mentions(text)
    hex_id   = secrets.token_hex(6)
    db       = get_db_session()
    row = DBComment(
        hex_id=hex_id, vuln_key=vuln_id, username=u,
        text=text, mentions=_json.dumps(mentions), created_at=datetime.now(),
    )
    db.add(row)
    db.commit()
    audit_log("comment_posted", details={"vuln_id": vuln_id, "mentions": mentions})
    return jsonify({"ok": True, "comment": row.to_dict()})

@app.route('/comments/<vuln_id>/<comment_id>', methods=['DELETE'])
@login_required
def delete_comment(vuln_id, comment_id):
    u    = current_user()
    role = session.get('role', 'user')
    db   = get_db_session()
    row  = (db.query(DBComment)
              .filter_by(vuln_key=vuln_id, hex_id=comment_id)
              .first())
    if not row:
        return jsonify({"error": "Commentaire introuvable ou non autorisé"}), 403
    if row.username != u and role != 'admin':
        return jsonify({"error": "Commentaire introuvable ou non autorisé"}), 403
    db.delete(row)
    db.commit()
    return jsonify({"ok": True})

@app.route('/history')
@login_required
def history():
    """Return user history. If project_id is provided, return saved analyses of that project."""
    u = current_user()
    project_id = request.args.get("project_id", "").strip()

    try:
        if project_id:
            projects = _load_projects()
            p = projects.get(project_id)

            if not p:
                return jsonify([])

            allowed = (
                session.get("role") == "admin"
                or p.get("owner") == u
                or u in p.get("members", [])
            )

            try:
                allowed = allowed or _is_project_member(project_id, u)
            except Exception:
                pass

            if not allowed:
                return jsonify([])

            analyses = _get_project_analyses(project_id)
            normalized = []

            for a in analyses:
                s = dict(a)
                s["project_id"] = project_id
                s["project_name"] = p.get("name", project_id)

                results = s.get("results") or s.get("vulns") or []

                s["total_vulns"] = (
                    s.get("total_vulns")
                    or s.get("total_detected")
                    or s.get("total")
                    or len(results)
                    or 0
                )

                s["patches_validated"] = (
                    s.get("patches_validated")
                    or s.get("validated")
                    or s.get("patches_applied")
                    or 0
                )

                s["patches_rejected"] = (
                    s.get("patches_rejected")
                    or s.get("rejected")
                    or 0
                )

                s["success_rate"] = s.get("success_rate", 0)
                s["mttr_seconds"] = s.get("mttr_seconds", s.get("mttr", "—"))
                s["total_duration"] = s.get("total_duration", s.get("duration", "—"))

                if not s.get("files_analyzed"):
                    files = {}
                    for r in results:
                        f = r.get("file") or r.get("file_path") or r.get("filename")
                        if f:
                            name = os.path.basename(str(f).replace("\\\\", "/"))
                            files[name] = files.get(name, 0) + 1
                    s["files_analyzed"] = [{"name": name, "vulns": count} for name, count in files.items()]

                normalized.append(s)

            normalized.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return jsonify(normalized)

        db = get_db_session()
        rows = (
            db.query(DBMetric)
              .filter_by(username=u)
              .order_by(DBMetric.timestamp.desc())
              .all()
        )

        sessions = []
        for m in rows:
            try:
                sessions.append(m.to_dict())
            except Exception:
                continue

        return jsonify(sessions)

    except Exception as e:
        print(f"[HISTORY ERROR] {e}")
        return jsonify([])



@app.route('/projects/api/<project_id>/files/download')
@login_required
def project_file_download(project_id):
    if not _project_has_access(project_id):
        return jsonify({"error": "Accès refusé"}), 403

    requested = request.args.get("file", "").strip()
    safe_path = _safe_project_download_path(project_id, requested)

    if not safe_path:
        return jsonify({"error": "Fichier introuvable ou non autorisé"}), 404

    return send_file(
        safe_path,
        as_attachment=True,
        download_name=os.path.basename(safe_path)
    )


@app.route('/download')
@login_required
def download():
    p=request.args.get('file','')
    uld=get_user_upload_dir(current_user())
    if p and os.path.exists(p) and os.path.realpath(p).startswith(os.path.realpath(uld)):
        return send_file(p,as_attachment=True)
    return jsonify({"error":"Fichier non trouvé"}),404

@app.route('/download-all')
@login_required
def download_all():
    ps=get_pipeline(current_user()); seen=[]; patches=[]
    for r in ps.get("results",[]):
        p=r.get("patched","")
        if r.get("success") and p and os.path.exists(p) and p not in seen:
            seen.append(p); patches.append(p)
    if not patches: return jsonify({"error":"Aucun patch"}),404
    if len(patches)==1: return send_file(patches[0],as_attachment=True)
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    zn=f"patchmind_{ts}.zip"; zp=os.path.join(tempfile.gettempdir(),zn)
    with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as zf:
        for p in patches: zf.write(p,os.path.basename(p))
    return send_file(zp,as_attachment=True,download_name=zn)

@app.route('/reanalyze', methods=['POST'])
@login_required
def reanalyze():
    u = current_user()
    d = request.get_json() or {}
    path = d.get('path', '').strip()
    if not path:
        return jsonify({"error": "Chemin manquant"}), 400
    uld = get_user_upload_dir(u)
    if not os.path.realpath(path).startswith(os.path.realpath(uld)):
        return jsonify({"error": "Accès refusé"}), 403
    if not os.path.exists(path):
        return jsonify({"error": "Fichier introuvable"}), 404
    job_id = secrets.token_urlsafe(12)
    ps = get_pipeline(u)
    ps.update({"running": True, "progress": 0, "results": [], "logs": [], "metrics": {}, "job_id": job_id})
    threading.Thread(target=run_pipeline, args=(u, [path]), daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id})

@app.route('/report')
@login_required
def generate_report():
    ps      = get_pipeline(current_user())
    results = ps.get("results", [])
    m       = ps.get("metrics", {})
    if not results:
        return jsonify({"error": "Aucune analyse disponible"}), 404

    # ── CWE descriptions (French) ─────────────────────────────────
    CWE_DESCS = {
        'CWE-89':  'Injection SQL — des données utilisateur sont insérées directement dans une requête SQL sans paramétrage.',
        'CWE-79':  'Cross-Site Scripting (XSS) — du code JavaScript malveillant peut s\'exécuter dans le navigateur.',
        'CWE-22':  'Path Traversal — un attaquant peut accéder à des fichiers hors du répertoire autorisé.',
        'CWE-78':  'Injection de commandes OS — des commandes arbitraires peuvent être exécutées sur le serveur.',
        'CWE-95':  'Eval Injection — du code arbitraire peut être évalué et exécuté dynamiquement.',
        'CWE-327': 'Algorithme cryptographique obsolète (MD5/SHA1) — facile à casser par force brute.',
        'CWE-502': 'Désérialisation non sécurisée — peut permettre l\'exécution de code arbitraire.',
        'CWE-798': 'Identifiants codés en dur — les secrets sont exposés dans le code source.',
        'CWE-434': 'Upload de fichier non sécurisé — des fichiers malveillants peuvent être exécutés.',
        'CWE-918': 'Server-Side Request Forgery — le serveur effectue des requêtes pour le compte d\'un attaquant.',
        'CWE-611': 'Injection XXE — des entités XML externes malveillantes peuvent être injectées.',
        'CWE-352': 'CSRF — des actions non autorisées peuvent être effectuées à l\'insu de l\'utilisateur.',
        'CWE-200': 'Exposition d\'informations sensibles — des données confidentielles sont divulguées.',
        'CWE-306': 'Authentification manquante — des fonctions critiques sont accessibles sans authentification.',
        'CWE-732': 'Permissions de fichier incorrectes — des fichiers sensibles sont accessibles à trop d\'utilisateurs.',
    }

    # ── Severity helpers ──────────────────────────────────────────
    def sev_class(sev_str):
        s = str(sev_str).upper()
        if 'CRITICAL' in s or 'CRITIQUE' in s: return 'critical'
        if 'HIGH'     in s or 'HAUTE'    in s: return 'high'
        if 'MEDIUM'   in s or 'MOYENNE'  in s: return 'medium'
        if 'LOW'      in s or 'FAIBLE'   in s: return 'low'
        return 'info'

    # ── Build per-result context ──────────────────────────────────
    conf_labels = {
        'cache':  '⚡ Déjà validé',
        'high':   '✓ Prêt à appliquer',
        'medium': '~ Vérifier le diff',
        'low':    '⚠ Correction manuelle',
    }
    enriched = []
    for r in results:
        cwe   = r.get('cwe','').split(':')[0].strip()
        # Re-resolve CWE if still unknown
        if not cwe or cwe == "CWE-UNKNOWN":
            cwe = resolve_cwe(r)
            r = dict(r, cwe=cwe)
        conf  = r.get('confidence', 0)
        fc    = r.get('from_cache', False)
        diff  = r.get('diff', '')
        cwe_display = display_cwe(cwe, r.get('message', ''))
        enriched.append({
            **r,
            'cwe':               cwe,
            'cwe_display':       cwe_display,
            'cwe_desc':          CWE_DESCS.get(cwe, ''),
            'explanation':       r.get('explanation') or _VULN_EXPLANATIONS.get(cwe, '') or explain_vuln(cwe, r.get('message','')),
            'fix_recommendation': r.get('solution') or _FIX_RECOMMENDATIONS.get(cwe, ''),
            'severity_class':    sev_class(r.get('severity','')),
            'severity_label':    str(r.get('severity',''))[:30],
            'conf_label':        conf_labels['cache'] if fc else
                                 conf_labels['high']  if conf >= 80 else
                                 conf_labels['medium'] if conf >= 65 else
                                 conf_labels['low'],
            'diff_lines':        diff.splitlines() if diff else [],
        })

    # ── Severity breakdown ────────────────────────────────────────
    sev_map = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for r in enriched:
        sev_map[r['severity_class']] = sev_map.get(r['severity_class'], 0) + 1

    SEV_DESCS = {
        'critical': 'Exploitation triviale, impact maximal, correction immédiate requise',
        'high':     'Risque élevé, à corriger en priorité',
        'medium':   'Risque modéré, à traiter rapidement',
        'low':      'Risque faible, à traiter lors du prochain sprint',
        'info':     'Informatif, aucune action immédiate requise',
    }
    severity_breakdown = [
        (k.upper(), v, round(v/len(enriched)*100, 1) if enriched else 0, SEV_DESCS[k])
        for k, v in sev_map.items() if v > 0
    ]

    # ── SVG bar chart (severity) ──────────────────────────────────
    sev_colors = {'critical':'#dc2626','high':'#ea580c','medium':'#d97706','low':'#0077cc','info':'#64748b'}
    bar_w = 480; bar_h = 140; n = len(sev_map)
    bars_svg_parts = []
    max_v = max(sev_map.values()) or 1
    bw = 50; gap = 20; x0 = 30
    for i, (k, v) in enumerate(sev_map.items()):
        x = x0 + i * (bw + gap)
        bh = int((v / max_v) * 90) if v else 0
        y  = 100 - bh
        bars_svg_parts.append(
            f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" fill="{sev_colors.get(k,"#64748b")}" rx="3"/>'
            f'<text x="{x+bw//2}" y="{y-4}" text-anchor="middle" font-size="11" fill="#1e293b" font-weight="bold">{v}</text>'
            f'<text x="{x+bw//2}" y="115" text-anchor="middle" font-size="9" fill="#64748b">{k.upper()}</text>'
        )
    severity_svg = (
        f'<svg width="{bar_w}" height="{bar_h}" xmlns="http://www.w3.org/2000/svg">'
        f'<rect width="{bar_w}" height="{bar_h}" fill="#f8fafc" rx="6"/>'
        + ''.join(bars_svg_parts) +
        f'</svg>'
    )

    # ── Aggregate stats ───────────────────────────────────────────
    total_vulns   = m.get('total', len(enriched))
    validated     = m.get('validated', sum(1 for r in enriched if r.get('success')))
    rejected      = m.get('rejected', total_vulns - validated)
    success_rate  = m.get('success_rate', round(validated/total_vulns*100, 1) if total_vulns else 0)
    mttr          = m.get('mttr', 0)
    duration      = m.get('duration', 0)
    cache_hits    = sum(1 for r in enriched if r.get('from_cache'))
    avg_conf      = round(sum(r.get('confidence',0) for r in enriched) / len(enriched), 1) if enriched else 0
    files_set     = list(dict.fromkeys(r.get('file','') for r in enriched))

    scanners_list = ['Semgrep SAST', 'GitLeaks', 'Snyk/OSV']
    if ps.get('zap'): scanners_list.append('ZAP DAST')
    custom_tool_results = ps.get('custom_tools', [])
    for ct in custom_tool_results:
        ct_name = ct.get('tool', 'Outil personnalisé')
        if ct_name not in scanners_list:
            scanners_list.append(ct_name)

    # ── Render HTML report (opens in browser tab) ────────────────
    from flask import render_template as rt
    html_str = rt(
        'report_template.html',
        username       = current_user(),
        gen_date       = datetime.now().strftime('%d/%m/%Y à %H:%M'),
        files_analyzed = ', '.join(files_set[:5]) + ('…' if len(files_set) > 5 else ''),
        total_vulns    = total_vulns,
        validated      = validated,
        rejected       = rejected,
        success_rate   = success_rate,
        mttr           = mttr,
        duration       = duration,
        cache_hits     = cache_hits,
        cache_savings  = cache_hits * 20,
        avg_confidence = avg_conf,
        severity_breakdown = severity_breakdown,
        severity_svg   = severity_svg,
        scanners_list  = scanners_list,
        scanners_used  = ' · '.join(scanners_list),
        results           = enriched,
        gitleaks_results  = ps.get('gitleaks', []),
        snyk_results      = ps.get('snyk', []),
        zap_results       = ps.get('zap', []),
        custom_tool_results = custom_tool_results,
    )
    return html_str, 200, {'Content-Type': 'text/html; charset=utf-8'}

# ══════════════════════════════════════════════════════════════════
# DEMANDES D'ACCÈS
# ══════════════════════════════════════════════════════════════════

def load_requests() -> list:
    db = get_db_session()
    return [r.to_dict() for r in db.query(DBAccessRequest).all()]

def save_requests(reqs: list) -> None:
    db = get_db_session()
    for req in reqs:
        rid = req.get("id")
        if not rid:
            continue
        row = db.query(DBAccessRequest).filter_by(id=rid).first()
        if row:
            for k in ("status", "reviewed_by", "username"):
                if k in req:
                    setattr(row, k, req[k])
            # persist reviewed_at / approved_at / rejected_at into the reviewed_at column
            for ts_key in ("reviewed_at", "approved_at", "rejected_at"):
                if ts_key in req and req[ts_key]:
                    ts_val = req[ts_key]
                    if isinstance(ts_val, str):
                        try:
                            ts_val = datetime.fromisoformat(ts_val)
                        except ValueError:
                            ts_val = datetime.now()
                    row.reviewed_at = ts_val
                    break
        else:
            from datetime import datetime as _dt
            created = req.get("created_at")
            if isinstance(created, str):
                try:   created = _dt.fromisoformat(created)
                except ValueError: created = _dt.now()
            # Pack company + use_case into reason JSON to avoid schema change
            company  = req.get("company", "")
            use_case = req.get("use_case", "")
            plain_reason = req.get("reason", "")
            if company or use_case:
                reason_val = json.dumps(
                    {"reason": plain_reason, "company": company, "use_case": use_case},
                    ensure_ascii=False
                )
            else:
                reason_val = plain_reason
            db.add(DBAccessRequest(
                id             = rid,
                email          = req.get("email", ""),
                full_name      = req.get("full_name", req.get("name", "")),
                reason         = reason_val,
                status         = req.get("status", "pending"),
                role_requested = req.get("role", req.get("role_requested", "analyst")),
                created_at     = created,
                reviewed_by    = req.get("reviewed_by"),
                username       = req.get("username"),
            ))
    db.commit()

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + '!@#$'
    return ''.join(secrets.choice(chars) for _ in range(length))

def send_credentials_email(to_email, full_name, username, password):
    """Envoie les credentials par email à l'utilisateur approuvé."""
    if not EMAIL_ENABLED:
        print(f"[EMAIL] Non configuré — credentials pour {to_email}: {username} / {password}")
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '🔒 Votre accès PatchMind est approuvé !'
        msg['From']    = f'PatchMind <{EMAIL_SENDER}>'
        msg['To']      = to_email

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#f9f9f9;padding:32px;border-radius:12px;">
          <div style="text-align:center;margin-bottom:32px;">
            <h1 style="font-size:28px;font-weight:800;color:#1A3A2A;margin:0;">
              Patch<span style="color:#2D5A3D;">Mind</span>
            </h1>
            <p style="color:#7A6E66;font-size:13px;margin-top:4px;">Automated Security Platform</p>
          </div>

          <div style="background:#fff;border-radius:10px;padding:28px;border:1px solid #E0D9D0;">
            <h2 style="color:#1A1612;font-size:20px;margin:0 0 8px;">
              Bonjour {full_name} 👋
            </h2>
            <p style="color:#3D3530;font-size:14px;line-height:1.7;margin:0 0 24px;">
              Votre demande d'accès à <strong>PatchMind</strong> a été approuvée !
              Voici vos identifiants de connexion :
            </p>

            <div style="background:#F0EDE8;border-radius:8px;padding:20px;margin-bottom:24px;border-left:4px solid #2D5A3D;">
              <div style="margin-bottom:12px;">
                <span style="font-size:11px;color:#7A6E66;text-transform:uppercase;letter-spacing:1px;">Identifiant</span>
                <div style="font-family:monospace;font-size:18px;font-weight:700;color:#1A3A2A;margin-top:4px;">{username}</div>
              </div>
              <div>
                <span style="font-size:11px;color:#7A6E66;text-transform:uppercase;letter-spacing:1px;">Mot de passe temporaire</span>
                <div style="font-family:monospace;font-size:18px;font-weight:700;color:#1A3A2A;margin-top:4px;">{password}</div>
              </div>
            </div>

            <a href="http://localhost:5000/login"
               style="display:block;text-align:center;background:#1A3A2A;color:#fff;padding:14px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;margin-bottom:20px;">
              → Se connecter maintenant
            </a>

            <div style="background:#FFF8E1;border-radius:8px;padding:14px;border:1px solid #FFE082;">
              <p style="margin:0;font-size:13px;color:#7A6E66;line-height:1.6;">
                ⚠️ <strong>Important :</strong> Changez votre mot de passe dès la première connexion
                et activez la <strong>double authentification (2FA)</strong> depuis votre espace.
              </p>
            </div>
          </div>

          <p style="text-align:center;color:#7A6E66;font-size:12px;margin-top:20px;">
            PatchMind © 2026 · Automated Vulnerability Remediation System
          </p>
        </div>
        """

        msg.attach(MIMEText(html, 'html'))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.sendmail(EMAIL_SENDER, to_email, msg.as_string())
        print(f"[EMAIL] ✅ Envoyé à {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL] ❌ Erreur : {e}")
        return False

def send_project_invitation_email(to_email, invited_by, project_name, invite_url, role, expires_at):
    """Send a project collaboration invitation email."""
    if not EMAIL_ENABLED:
        print(f"[EMAIL] Non configuré — invitation pour {to_email}: {invite_url}")
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'Invitation à collaborer sur "{project_name}" — PatchMind'
        msg['From']    = f'PatchMind <{EMAIL_SENDER}>'
        msg['To']      = to_email
        role_label     = 'Membre' if role == 'member' else 'Lecteur'
        expires_str    = expires_at.strftime('%d/%m/%Y') if expires_at else ''
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#f9f9f9;padding:32px;border-radius:12px;">
          <div style="text-align:center;margin-bottom:32px;">
            <h1 style="font-size:28px;font-weight:800;color:#1A3A2A;margin:0;">
              Patch<span style="color:#2D5A3D;">Mind</span>
            </h1>
            <p style="color:#7A6E66;font-size:13px;margin-top:4px;">Automated Security Platform</p>
          </div>
          <div style="background:#fff;border-radius:10px;padding:28px;border:1px solid #E0D9D0;">
            <h2 style="color:#1A1612;font-size:20px;margin:0 0 16px;">Invitation à collaborer</h2>
            <p style="color:#3D3530;font-size:14px;line-height:1.7;margin:0 0 20px;">
              <strong>{invited_by}</strong> vous invite à rejoindre le projet
              <strong>"{project_name}"</strong> en tant que <strong>{role_label}</strong>.
            </p>
            <div style="background:#F0EDE8;border-radius:8px;padding:14px;margin-bottom:24px;border-left:4px solid #2D5A3D;">
              <p style="margin:0;font-size:13px;color:#3D3530;">
                ⏳ Cette invitation expire le <strong>{expires_str}</strong>
              </p>
            </div>
            <a href="{invite_url}"
               style="display:block;text-align:center;background:#1A3A2A;color:#fff;padding:14px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;margin-bottom:16px;">
              → Voir l'invitation
            </a>
            <p style="font-size:11px;color:#7A6E66;text-align:center;margin:0;">
              Ou copiez ce lien : {invite_url}
            </p>
          </div>
          <p style="text-align:center;color:#7A6E66;font-size:12px;margin-top:20px;">
            PatchMind © 2026 · Automated Vulnerability Remediation System
          </p>
        </div>
        """
        msg.attach(MIMEText(html, 'html'))
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.sendmail(EMAIL_SENDER, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL] ❌ Invitation : {e}")
        return False


@app.route('/request-access', methods=['GET', 'POST'])
def request_access():
    if request.method == 'POST':
        try:
            d = request.get_json() or {}
            # Accept field-name variants (nom/full_name, usecase/use_case, societe/company, etc.)
            full_name = (d.get('full_name') or d.get('nom') or d.get('name') or '').strip()
            email     = d.get('email', '').strip()
            company   = (d.get('company') or d.get('societe') or '').strip()
            use_case  = (d.get('use_case') or d.get('usecase') or d.get('justification') or d.get('message') or '').strip()

            if not full_name:
                return jsonify({"ok": False, "error": "Le nom complet est requis"}), 400
            if not email:
                return jsonify({"ok": False, "error": "L'adresse email est requise"}), 400
            if '@' not in email or '.' not in email.split('@')[-1]:
                return jsonify({"ok": False, "error": "Adresse email invalide"}), 400

            reqs = load_requests()
            # Block only active pending requests — approved/rejected history is fine
            if any(r.get('email') == email and r.get('status') == 'pending' for r in reqs):
                return jsonify({"ok": False, "error": "Une demande est déjà en attente pour cet email"}), 400

            users = load_users()
            # Block only active accounts — soft-deleted users may re-request access
            if any(u.get('email') == email and u.get('active', True) for u in users.values()):
                return jsonify({"ok": False, "error": "Un compte actif existe déjà avec cet email"}), 400

            reqs.append({
                "id":         secrets.token_hex(8),
                "full_name":  full_name,
                "email":      email,
                "company":    company,
                "use_case":   use_case,
                "status":     "pending",
                "created_at": datetime.now().isoformat()
            })
            save_requests(reqs)
            return jsonify({"ok": True, "message": "Demande envoyée ! L'équipe PatchMind vous contactera sous 24h."})
        except Exception as e:
            print(f"[REQUEST-ACCESS] Erreur : {e}")
            return jsonify({"ok": False, "error": "Erreur serveur. Veuillez réessayer."}), 500
    return render_template('request_access.html')

@app.route('/admin/requests', methods=['GET'])
@login_required
@admin_required
def admin_list_requests():
    reqs = load_requests()
    pending = [r for r in reqs if r.get('status') == 'pending']
    return jsonify(pending)

@app.route('/admin/requests/<req_id>/approve', methods=['POST'])
@login_required
@admin_required
def admin_approve_request(req_id):
    try:
        reqs = load_requests()
        req  = next((r for r in reqs if r.get('id') == req_id), None)
        if not req:
            return jsonify({"error": "Demande introuvable"}), 404
        if req.get('status') != 'pending':
            return jsonify({"error": f"Cette demande est déjà {req.get('status')}"}), 400

        email     = req.get('email', '').strip()
        full_name = req.get('full_name', req.get('name', '')).strip()
        if not email:
            return jsonify({"error": "Email manquant dans la demande"}), 400

        users    = load_users()
        password = generate_password()

        # Check for an existing user with this email (may be soft-deleted)
        existing_username = next(
            (uname for uname, u in users.items() if u.get('email') == email),
            None
        )

        reactivated = False
        if existing_username:
            existing = users[existing_username]
            if existing.get('active', True):
                return jsonify({"error": "Un compte actif existe déjà avec cet email"}), 400
            # Reactivate the soft-deleted account
            username = existing_username
            save_users({username: {
                **existing,
                "password":             generate_password_hash(password),
                "role":                 "user",
                "full_name":            full_name,
                "company":              req.get("company", ""),
                "active":               True,
                "blocked":              False,
                "totp_enabled":         False,
                "must_change_password": True,
            }})
            reactivated = True
        else:
            # Derive a unique username (skip ALL existing slots, active or not)
            base = email.split('@')[0].lower().replace('.', '_').replace('-', '_')
            username, i = base, 1
            while username in users:
                username = f"{base}{i}"; i += 1

            save_users({username: {
                "password":             generate_password_hash(password),
                "role":                 "user",
                "full_name":            full_name,
                "email":                email,
                "company":              req.get("company", ""),
                "created_at":           datetime.now().isoformat(),
                "totp_secret":          generate_totp_secret(),
                "totp_enabled":         False,
                "active":               True,
                "blocked":              False,
                "must_change_password": True,
            }})
            os.makedirs(os.path.join(DATA_DIR, username, 'uploads'), exist_ok=True)

        # Marquer comme approuvée
        now_iso = datetime.now().isoformat()
        for r in reqs:
            if r.get('id') == req_id:
                r['status']      = 'approved'
                r['username']    = username
                r['reviewed_by'] = session.get('username', 'admin')
                r['approved_at'] = now_iso
        save_requests(reqs)

        # Envoyer email automatiquement
        email_sent = send_credentials_email(
            to_email  = email,
            full_name = full_name,
            username  = username,
            password  = password
        )

        action = "réactivé" if reactivated else "créé"
        msg = f"Compte {action} : {username}"
        if not email_sent:
            msg += f" — mot de passe : {password}"

        return jsonify({
            "ok":          True,
            "username":    username,
            "reactivated": reactivated,
            "email_sent":  email_sent,
            "message":     msg,
        })
    except Exception as e:
        print(f"[APPROVE] Erreur approbation {req_id}: {e}")
        return jsonify({"error": f"Erreur serveur : {str(e)}"}), 500

@app.route('/admin/requests/<req_id>/reject', methods=['POST'])
@login_required
@admin_required
def admin_reject_request(req_id):
    try:
        reqs = load_requests()
        req  = next((r for r in reqs if r.get('id') == req_id), None)
        if not req:
            return jsonify({"error": "Demande introuvable"}), 404
        if req.get('status') != 'pending':
            return jsonify({"error": f"Cette demande est déjà {req.get('status')}"}), 400

        now_iso = datetime.now().isoformat()
        for r in reqs:
            if r.get('id') == req_id:
                r['status']      = 'rejected'
                r['reviewed_by'] = session.get('username', 'admin')
                r['rejected_at'] = now_iso
        save_requests(reqs)
        return jsonify({"ok": True})
    except Exception as e:
        print(f"[REJECT] Erreur rejet {req_id}: {e}")
        return jsonify({"error": f"Erreur serveur : {str(e)}"}), 500

# ══════════════════════════════════════════════════════════════════
# AUDIT LOG
# ══════════════════════════════════════════════════════════════════

@app.route('/admin/audit')
@login_required
@admin_required
def admin_audit():
    return render_template('audit.html')

@app.route('/admin/audit/api')
@login_required
@admin_required
def admin_audit_api():
    page     = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    event_f  = request.args.get('event', '').strip()
    user_f   = request.args.get('user', '').strip()
    db       = get_db_session()
    query    = db.query(DBAuditLog)
    if event_f:
        query = query.filter(DBAuditLog.event.contains(event_f))
    if user_f:
        query = query.filter(DBAuditLog.user.contains(user_f))
    total   = query.count()
    start   = (page - 1) * per_page
    entries = query.order_by(DBAuditLog.ts.desc()).offset(start).limit(per_page).all()
    return jsonify({"entries": [e.to_dict() for e in entries], "total": total,
                    "page": page, "per_page": per_page})

@app.route('/admin/audit/export')
@login_required
@admin_required
def admin_audit_export():
    import csv, io as _io
    db      = get_db_session()
    entries = db.query(DBAuditLog).order_by(DBAuditLog.ts.asc()).all()
    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "event", "user", "ip", "details"])
    for e in entries:
        d = e.to_dict()
        writer.writerow([d.get("ts",""), d.get("event",""), d.get("user",""),
                         d.get("ip",""), json.dumps(d.get("details",{}))])
    audit_log("audit_export")
    return send_file(
        _io.BytesIO(buf.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='audit_log.csv'
    )

# ══════════════════════════════════════════════════════════════════
# ADMIN MONITORING
# ══════════════════════════════════════════════════════════════════

@app.route('/admin/monitoring')
@login_required
@admin_required
def admin_monitoring():
    return render_template('monitoring.html')

@app.route('/admin/monitoring/api')
@login_required
@admin_required
def admin_monitoring_api():
    from generator.generator import get_cache_stats
    try:
        cache = get_cache_stats()
    except Exception:
        cache = {}

    # Active pipelines
    active = sum(1 for ps in _pipelines.values() if ps.get("running"))
    total_analyses = 0
    try:
        users = load_users()
        for uname in users:
            mp = get_user_metrics_path(uname)
            if os.path.exists(mp):
                d = _read_json(mp, {})
                total_analyses += len(d.get("sessions", []))
    except Exception:
        pass

    # Error rate from consensus log
    consensus_log_data = []
    cl = os.path.join(BASE_DIR, 'data', 'consensus_log.json')
    if os.path.exists(cl):
        try:
            with open(cl, 'r', encoding='utf-8') as f:
                consensus_log_data = json.load(f)
        except Exception:
            pass
    fallback_count = sum(1 for e in consensus_log_data if e.get('winner','') != 'groq' or '1/' in e.get('agreement',''))

    return jsonify({
        "active_pipelines":  active,
        "total_users":       len(load_users()),
        "total_analyses":    total_analyses,
        "cache":             cache,
        "consensus_entries": len(consensus_log_data),
        "fallback_rate":     round(fallback_count / max(len(consensus_log_data), 1) * 100, 1),
        "consensus_ok":      CONSENSUS_OK,
        "rbac_ok":           RBAC_OK,
    })

import os

# ══════════════════════════════════════════════════════════════════
# TOOL API  (GET /api/tools, POST /api/tools/recommend, POST /api/tools/run)
# ══════════════════════════════════════════════════════════════════

@app.route('/api/tools', methods=['GET'])
@login_required
def api_tools_list():
    """Return only installed/available tools."""
    return jsonify({"ok": True, "tools": _tool_registry.list_available()})


@app.route('/api/tools/recommend', methods=['POST'])
@login_required
def api_tools_recommend():
    """Recommend tools for a target path inside the user's workspace."""
    d = request.get_json() or {}
    target = (d.get('target_path') or '').strip()
    if not target:
        return jsonify({"ok": False, "error": "target_path requis"}), 400

    user_workspace = get_user_upload_dir(current_user())

    # Resolve and validate path stays within user's workspace
    abs_target = os.path.realpath(os.path.join(user_workspace, target))
    if not abs_target.startswith(os.path.realpath(user_workspace) + os.sep):
        if abs_target != os.path.realpath(user_workspace):
            return jsonify({"ok": False, "error": "Accès refusé — chemin hors du workspace"}), 403
    if not os.path.exists(abs_target):
        return jsonify({"ok": False, "error": "Chemin introuvable"}), 404

    # recommend() returns list of to_info_dict() + "reason" key — only show installed tools
    all_recs = _tool_registry.recommend(abs_target)
    recommendations = [r for r in all_recs if r.get("available")]
    return jsonify({"ok": True, "recommendations": recommendations})


@app.route('/api/tools/run', methods=['POST'])
@login_required
def api_tools_run():
    """Execute a named tool against a path in the user's workspace."""
    if not _rate_check(request.remote_addr, 'api-tools-run', 10, 60):
        return jsonify({"ok": False, "error": "Trop de requêtes. Réessayez dans une minute."}), 429

    # Permission check — only roles with run_scan may execute tools
    u = current_user()
    users = load_users()
    role = users.get(u, {}).get("role", "analyst")
    if not has_permission(role, "run_scan"):
        return jsonify({"ok": False, "error": "Permission insuffisante"}), 403

    d = request.get_json() or {}
    tool_name = (d.get('tool_name') or '').strip()
    target    = (d.get('target_path') or '').strip()
    use_cache = bool(d.get('use_cache', True))

    if not tool_name:
        return jsonify({"ok": False, "error": "tool_name requis"}), 400
    if not target:
        return jsonify({"ok": False, "error": "target_path requis"}), 400

    # Validate tool name is registered
    if not _tool_registry.get(tool_name):
        known = [t["name"] for t in _tool_registry.list_all()]
        return jsonify({"ok": False, "error": f"Outil inconnu. Disponibles: {', '.join(known)}"}), 404

    user_workspace = get_user_upload_dir(u)

    # Resolve and verify path containment
    abs_target = os.path.realpath(os.path.join(user_workspace, target))
    if not abs_target.startswith(os.path.realpath(user_workspace)):
        return jsonify({"ok": False, "error": "Accès refusé — chemin hors du workspace"}), 403
    if not os.path.exists(abs_target):
        return jsonify({"ok": False, "error": "Chemin introuvable"}), 404

    try:
        result = _tool_registry.run_tool(
            name           = tool_name,
            target_path    = abs_target,
            username       = u,
            workspace      = user_workspace,
            use_cache      = use_cache,
        )
        findings = result.get("findings", [])
        audit_log("tool_run", user=u, details={
            "tool":           tool_name,
            "target":         abs_target,
            "ok":             result.get("ok"),
            "findings_count": len(findings),
        })
        # Strip raw output (may be MBs) — send only findings and metadata
        response = {
            "ok":           True,
            "tool_name":    tool_name,
            "findings":     findings,
            "findings_count": len(findings),
            "from_cache":   result.get("from_cache", False),
            "duration_ms":  int(result.get("duration", 0) * 1000),
            "error":        result.get("error", ""),
        }
        return jsonify(response)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    except Exception as e:
        return jsonify({"ok": False, "error": f"Erreur interne: {e}"}), 500


if __name__=='__main__':
    load_users()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port, use_reloader=False)