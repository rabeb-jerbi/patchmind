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
from flask import (Flask, render_template, request, jsonify,
                   send_file, redirect, url_for, session)
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
from scanner.scanner          import run_scan
from scanner.gitleaks_scanner import run_gitleaks
from scanner.snyk_scanner     import run_snyk
from enricher.enricher        import get_cves_by_cwe
from generator.generator      import generate_patch
from validator.validator      import validate_patch
from metrics.metrics          import PatchMindMetrics

# Intelligence + Intégrations (import optionnel)
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from intelligence  import analyze_trends, benchmark_user, predict_risk
    from integrations  import send_all_notifications
    INTELLIGENCE_OK = True
except ImportError:
    INTELLIGENCE_OK = False

app = Flask(__name__)
app.secret_key  = os.environ.get('PATCHMIND_SECRET', 'patchmind-2fa-secret-2026-changeme')
app.permanent_session_lifetime = timedelta(hours=8)

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_FILE = os.path.join(BASE_DIR, 'data', 'users.json')
DATA_DIR   = os.path.join(BASE_DIR, 'data', 'users')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# ── EMAIL CONFIG ── (modifier avec tes vraies infos)
EMAIL_SENDER   = os.environ.get('PATCHMIND_EMAIL', 'votre.email@gmail.com')
EMAIL_PASSWORD = os.environ.get('PATCHMIND_EMAIL_PASSWORD', 'votre_app_password')
EMAIL_ENABLED  = EMAIL_SENDER != 'votre.email@gmail.com'

os.makedirs(DATA_DIR, exist_ok=True)

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

# ══════════════════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════════════════

def _read_json(path, default=None):
    try:
        with open(path,'r',encoding='utf-8') as f: return json.load(f)
    except: return default if default is not None else {}

def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path,'w',encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_users():
    if not os.path.exists(USERS_FILE):
        default = {"admin": {
            "password":    generate_password_hash("Admin@2026!"),
            "role":        "admin",
            "full_name":   "Administrator",
            "created_at":  datetime.now().isoformat(),
            "totp_secret": pyotp.random_base32() if TOTP_SUPPORTED else None,
            "totp_enabled": False,
            "active":      True
        }}
        _write_json(USERS_FILE, default)
        return default
    return _read_json(USERS_FILE)

def save_users(u): _write_json(USERS_FILE, u)

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
            if request.is_json or request.method != 'GET':
                return jsonify({"error":"Non authentifié"}), 401
            return redirect('/login')
        if not session.get('2fa_ok') and session.get('need_2fa'):
            return redirect('/verify-2fa')
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
            "results":  [], "metrics": {}, "logs": [],
            "gitleaks": [],   # Secrets détectés
            "snyk":     [],   # Dépendances vulnérables
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

def extract_zip(zip_path, uld):
    name = os.path.splitext(os.path.basename(zip_path))[0]
    dest = os.path.join(uld, name+'_extracted')
    if os.path.exists(dest): shutil.rmtree(dest)
    os.makedirs(dest,exist_ok=True)
    with zipfile.ZipFile(zip_path,'r') as zf:
        for m in zf.namelist():
            mp = os.path.realpath(os.path.join(dest,m))
            if mp.startswith(os.path.realpath(dest)): zf.extract(m,dest)
    return get_supported_files(dest), dest

def extract_rar(rar_path, uld):
    if not RAR_SUPPORTED: raise RuntimeError("rarfile non installé")
    name = os.path.splitext(os.path.basename(rar_path))[0]
    dest = os.path.join(uld, name+'_extracted')
    if os.path.exists(dest): shutil.rmtree(dest)
    os.makedirs(dest,exist_ok=True)
    with rarfile.RarFile(rar_path,'r') as rf: rf.extractall(dest)
    return get_supported_files(dest), dest

def clone_repo(url, uld):
    import git
    name = url.rstrip('/').split('/')[-1].replace('.git','')
    dest = os.path.join(uld, name)
    if os.path.exists(dest): shutil.rmtree(dest)
    git.Repo.clone_from(url, dest); return dest

def norm_cwe(raw):
    return re.sub(r'^(?i)CWE-0*(\d+)$', lambda m:f'CWE-{m.group(1)}',
                  raw.split(':')[0].strip())

def save_session_history(username, m):
    path = get_user_metrics_path(username)
    data = _read_json(path, {"sessions":[]})
    data.setdefault("sessions",[])
    data["sessions"].append({
        "timestamp":         datetime.now().isoformat(),
        "total_vulns":       m["total"],
        "patches_validated": m["validated"],
        "patches_rejected":  m["rejected"],
        "success_rate":      m["success_rate"],
        "mttr_seconds":      m["mttr"],
        "total_duration":    m["duration"],
        "patched_files":     m.get("patched_files",[])
    })
    _write_json(path, data)

def _compute_confidence(ok, from_cache, cwe, fixed_code):
    """Calcule un score de confiance sur le patch généré."""
    if not ok:
        return 0
    score = 60  # base si validé
    if from_cache:
        score += 30  # patch déjà validé = très fiable
    else:
        score += 10  # validé par Semgrep
    # Bonus si le code contient les patterns attendus
    patterns = {
        "CWE-89":  ["?", "%s", "prepare", "parameterized", "execute"],
        "CWE-79":  ["escape", "htmlspecialchars", "textContent", "template", "sanitize"],
        "CWE-78":  ["shell=False", "execFile", "ProcessBuilder", "escapeshellarg"],
        "CWE-327": ["sha256", "SHA-256", "bcrypt", "sha512"],
        "CWE-22":  ["realpath", "normalize", "startsWith", "basename"],
        "CWE-502": ["json.loads", "JSON.parse", "safe_load"],
        "CWE-798": ["os.getenv", "process.env", "System.getenv", "getenv"],
    }
    expected = patterns.get(cwe, [])
    if expected and any(p.lower() in fixed_code.lower() for p in expected):
        score += 10
    return min(score, 100)

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

def run_pipeline(username, file_paths):
    ps = get_pipeline(username)
    ps.update({"running":True,"progress":0,"results":[],"logs":[],"metrics":{},"gitleaks":[],"snyk":[]})
    metrics = PatchMindMetrics(); all_vulns = []

    # Dossier racine
    root_dir = os.path.dirname(file_paths[0]) if file_paths else ""

    try:
        # ── GitLeaks ──────────────────────────────────────────────
        logp(username,"🔑 Scan secrets (GitLeaks)...")
        try:
            gl = run_gitleaks(root_dir)
            ps["gitleaks"] = gl
            logp(username, f"🔑 {len(gl)} secret(s) détecté(s)" if gl else "✅ Aucun secret détecté")
        except Exception as e:
            logp(username, f"⚠️ GitLeaks : {e}")

        # ── Snyk/OSV ──────────────────────────────────────────────
        logp(username,"📦 Scan dépendances (Snyk/OSV)...")
        try:
            snyk = run_snyk(root_dir)
            ps["snyk"] = snyk
            logp(username, f"📦 {len(snyk)} dépendance(s) vulnérable(s)" if snyk else "✅ Aucune dépendance vulnérable")
        except Exception as e:
            logp(username, f"⚠️ Snyk : {e}")

        # ── Semgrep SAST ──────────────────────────────────────────
        for fp in file_paths:
            logp(username,f"🔍 Scan de {os.path.basename(fp)}...")
            vulns = run_scan(fp); seen = set()
            for v in vulns:
                key = (v["line"],v["cwe"].split(":")[0],v["file"])
                if key not in seen: seen.add(key); all_vulns.append(v)

        if not all_vulns and not ps["gitleaks"] and not ps["snyk"]:
            logp(username,"✅ Aucune vulnérabilité trouvée !"); ps["running"]=False; return

        if all_vulns:
            logp(username,f"⚠️  {len(all_vulns)} vulnérabilité(s) code détectée(s)")

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

                fixed_code = cached if cached else generate_patch(vt)

                with lock:
                    logp(username, f"✅ [{i}/{len(all_vulns)}] Validation...")

                ok, _ = validate_patch(src, fixed_code, vuln)

                # Score de confiance
                confidence = _compute_confidence(ok, from_cache, cwe_clean, fixed_code)

                # Diff visuel
                diff = _compute_diff(original_code, fixed_code) if ok else ""

                with lock:
                    metrics.end_vuln(ok)
                    patched_exists = ok and os.path.exists(patched)
                    completed[0] += 1
                    ps["progress"] = int(completed[0] / len(all_vulns) * 100)
                    logp(username, f"{'✅' if ok else '❌'} [{i}/{len(all_vulns)}] {'VALIDÉ' if ok else 'REJETÉ'} {'(cache ⚡)' if from_cache else ''} — confiance: {confidence}%")

                return {
                    "cwe":          vuln['cwe'].split(':')[0].strip(),
                    "file":         os.path.basename(orig_path),
                    "line":         vuln["line"],
                    "severity":     sev,
                    "success":      ok,
                    "message":      vuln["message"][:100],
                    "patched":      patched if patched_exists else "",
                    "patched_name": os.path.basename(patched) if patched_exists else "",
                    "analyzed_at":  datetime.now().strftime("%H:%M:%S"),
                    "from_cache":   from_cache,
                    "confidence":   confidence,
                    "diff":         diff,
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
        ps["results"] = [r for _, r in results_raw]

        metrics.finalize()
        total = len(ps["results"]); succ = sum(1 for r in ps["results"] if r["success"])
        cache_hits = sum(1 for r in ps["results"] if r.get("from_cache"))
        if cache_hits > 0:
            logp(username, f"⚡ {cache_hits} patch(es) depuis cache — {cache_hits * 20}s économisés !")

        seen_p, patches = [], []
        for r in ps["results"]:
            p = r.get("patched","")
            if r["success"] and p and p not in seen_p:
                seen_p.append(p); patches.append({"name":os.path.basename(p),"path":p})

        ps["metrics"]={
            "total":total,"validated":succ,"rejected":total-succ,
            "success_rate":round(succ/total*100,1) if total else 0,
            "mttr":round(metrics.session.get("mttr_seconds",0),2),
            "duration":round(metrics.session.get("total_duration",0),2),
            "patched_files":patches
        }
        save_session_history(username,ps["metrics"])
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
        logp(username,f"❌ Erreur : {e}")
    ps["running"]=False

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
            return jsonify({"error":"Identifiants incorrects"}), 401
        if not check_password_hash(users[u]['password'], p):
            record_fail(ip)
            fails = _login_attempts.get(ip,{}).get('count',0)
            remaining_att = MAX_ATTEMPTS - fails
            return jsonify({"error":f"Identifiants incorrects. {remaining_att} tentative(s) restante(s)"}), 401

        reset_attempts(ip)
        session.permanent = False  # Session expire à la fermeture du navigateur
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
        # Admin → /admin, user → /dashboard
        redirect_url = "/admin" if session['role'] == 'admin' else "/dashboard"
        return jsonify({"ok":True,"need_2fa":False,"role":session['role'],"redirect": redirect_url})
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET','POST'])
def verify_2fa():
    if '2fa_ok' not in session: return redirect('/login')
    if session.get('2fa_ok'):   return redirect('/dashboard')
    if request.method == 'POST':
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
            redirect_url = "/admin" if session.get('role') == 'admin' else "/dashboard"
            return jsonify({"ok": True, "redirect": redirect_url})
        return jsonify({"error":"Code incorrect. Vérifiez votre application."}), 401
    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect('/login')

@app.route('/me')
@login_required
def me():
    users = load_users()
    u     = current_user()
    has_2fa = users.get(u,{}).get('totp_enabled', False)
    return jsonify({
        "username": u,
        "role":     session.get('role','user'),
        "fullname": session.get('fullname', u),
        "has_2fa":  has_2fa
    })

# ══════════════════════════════════════════════════════════════════
# 2FA SETUP ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/setup-2fa', methods=['GET'])
@login_required
def setup_2fa_page():
    return render_template('setup_2fa.html')

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
# ADMIN ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route('/admin')
@login_required
@admin_required
def admin_page(): return render_template('admin.html')

@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_list_users():
    users = load_users(); result = []
    for uname, ud in users.items():
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
        })
    return jsonify(result)

@app.route('/admin/users', methods=['POST'])
@login_required
@admin_required
def admin_create_user():
    d = request.get_json() or {}
    u = d.get('username','').strip()
    p = d.get('password','')
    if not u or not p: return jsonify({"error":"Champs requis"}), 400
    if len(p) < 8:     return jsonify({"error":"Mot de passe trop court (8 car. min)"}), 400
    users = load_users()
    if u in users: return jsonify({"error":"Utilisateur déjà existant"}), 400
    users[u] = {
        "password":    generate_password_hash(p),
        "role":        d.get('role','user'),
        "full_name":   d.get('full_name',u),
        "created_at":  datetime.now().isoformat(),
        "totp_secret": generate_totp_secret(),
        "totp_enabled":False,
        "active":      True
    }
    save_users(users)
    os.makedirs(os.path.join(DATA_DIR,u,'uploads'),exist_ok=True)
    return jsonify({"ok":True})

@app.route('/admin/users/<username>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_user(username):
    if username == 'admin': return jsonify({"error":"Impossible de supprimer admin"}), 400
    users = load_users()
    if username not in users: return jsonify({"error":"Introuvable"}), 404
    user_email = users[username].get('email', '')
    del users[username]; save_users(users)
    # Nettoyer le dossier utilisateur
    d = os.path.join(DATA_DIR, username)
    if os.path.exists(d): shutil.rmtree(d)
    # Nettoyer les demandes liées à cet email
    if user_email:
        reqs = load_requests()
        reqs = [r for r in reqs if r.get('email') != user_email]
        save_requests(reqs)
    return jsonify({"ok":True})

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

@app.route('/admin/stats')
@login_required
@admin_required
def admin_stats():
    users = load_users(); all_sess = []
    for uname in users:
        data = _read_json(get_user_metrics_path(uname),{"sessions":[]})
        for s in data.get("sessions",[]):
            s["username"] = uname; all_sess.append(s)
    all_sess.sort(key=lambda x:x.get("timestamp",""),reverse=True)
    return jsonify({
        "total_users":    len(users),
        "total_sessions": len(all_sess),
        "total_vulns":    sum(s.get("total_vulns",0) for s in all_sess),
        "total_patches":  sum(s.get("patches_validated",0) for s in all_sess),
        "recent":         all_sess[:50]
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
    u=current_user(); uld=get_user_upload_dir(u)
    if 'file' not in request.files: return jsonify({"error":"Aucun fichier"}),400
    f=request.files['file']
    if not f.filename: return jsonify({"error":"Nom vide"}),400
    fname=secure_filename(f.filename); fpath=os.path.join(uld,fname)
    f.save(fpath); ext=os.path.splitext(fname)[1].lower()
    ps=get_pipeline(u)
    ps.update({"running":True,"progress":0,"results":[],"logs":[],"metrics":{}})

    def _run(files):
        threading.Thread(target=run_pipeline,args=(u,files),daemon=True).start()

    if ext=='.rar':
        def _rar():
            try:
                logp(u,f"📦 Extraction RAR : {fname}")
                files,_=extract_rar(fpath,uld)
                if not files: logp(u,"⚠️ Vide"); ps["running"]=False; return
                logp(u,f"✅ {len(files)} fichier(s)"); run_pipeline(u,files)
            except Exception as e: logp(u,f"❌ {e}"); ps["running"]=False
        threading.Thread(target=_rar,daemon=True).start()
        return jsonify({"message":"RAR lancé"})

    if ext=='.zip':
        def _zip():
            try:
                logp(u,f"📦 Extraction ZIP : {fname}")
                files,_=extract_zip(fpath,uld)
                if not files: logp(u,"⚠️ Vide"); ps["running"]=False; return
                logp(u,f"✅ {len(files)} fichier(s)"); run_pipeline(u,files)
            except Exception as e: logp(u,f"❌ {e}"); ps["running"]=False
        threading.Thread(target=_zip,daemon=True).start()
        return jsonify({"message":"ZIP lancé"})

    if ext not in SUPPORTED_EXTENSIONS:
        return jsonify({"error":f"Extension '{ext}' non supportée"}),400
    threading.Thread(target=run_pipeline,args=(u,[fpath]),daemon=True).start()
    return jsonify({"message":"Analyse lancée"})

@app.route('/github', methods=['POST'])
@login_required
def github_analyze():
    u=current_user(); uld=get_user_upload_dir(u)
    d=request.get_json() or {}; url=d.get('url','').strip()
    if not url or not url.startswith('https://github.com/'):
        return jsonify({"error":"URL invalide"}),400
    ps=get_pipeline(u)
    ps.update({"running":True,"progress":0,"results":[],"logs":[],"metrics":{}})
    def _gh():
        try:
            logp(u,f"📥 Clonage : {url}")
            cp=clone_repo(url,uld); fs=get_supported_files(cp)
            if not fs: logp(u,"⚠️ Vide"); ps["running"]=False; return
            logp(u,f"✅ {len(fs)} fichier(s)"); run_pipeline(u,fs)
        except Exception as e: logp(u,f"❌ {e}"); ps["running"]=False
    threading.Thread(target=_gh,daemon=True).start()
    return jsonify({"message":"GitHub lancé"})

@app.route('/status')
@login_required
def status(): return jsonify(get_pipeline(current_user()))

@app.route('/files')
@login_required
def list_files():
    uld=get_user_upload_dir(current_user()); files=[]
    for fname in os.listdir(uld):
        fp=os.path.join(uld,fname)
        if not os.path.isfile(fp): continue
        if '_patched' in fname or '_extracted' in fname: continue
        _bn, _bext = os.path.splitext(fname)
        pname = _bn + '_patched' + _bext
        ppath=os.path.join(uld,pname); st=os.stat(fp)
        files.append({"name":fname,"path":fp,
            "size":round(st.st_size/1024,1),
            "uploaded_at":datetime.fromtimestamp(st.st_mtime).strftime("%d/%m/%Y %H:%M"),
            "has_patch":os.path.exists(ppath),
            "patched_path":ppath if os.path.exists(ppath) else ""})
    files.sort(key=lambda x:x["uploaded_at"],reverse=True)
    return jsonify(files)

@app.route('/history')
@login_required
def history():
    data=_read_json(get_user_metrics_path(current_user()),{"sessions":[]})
    return jsonify(data.get("sessions",[]))

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

@app.route('/report')
@login_required
def generate_report():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.units import cm
    except ImportError:
        return jsonify({"error":"pip install reportlab"}),500

    ps=get_pipeline(current_user()); results=ps.get("results",[]); m=ps.get("metrics",{})
    if not results: return jsonify({"error":"Aucune analyse"}),404

    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    fname=f"patchmind_report_{current_user()}_{ts}.pdf"
    fpath=os.path.join(tempfile.gettempdir(),fname)
    doc=SimpleDocTemplate(fpath,pagesize=A4,leftMargin=2*cm,rightMargin=2*cm,topMargin=2*cm,bottomMargin=2*cm)
    styles=getSampleStyleSheet(); story=[]

    story.append(Paragraph("PatchMind — Rapport d'analyse de sécurité",
        ParagraphStyle('T',parent=styles['Title'],fontSize=20,
                       textColor=colors.HexColor('#00ff88'),spaceAfter=4)))
    story.append(Paragraph(
        f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} · Utilisateur : {current_user()}",
        ParagraphStyle('s',parent=styles['Normal'],fontSize=9,textColor=colors.grey,spaceAfter=16)))
    story.append(HRFlowable(width="100%",thickness=1,color=colors.HexColor('#00ff88')))
    story.append(Spacer(1,0.4*cm))

    story.append(Paragraph("Résumé de session",styles['Heading2']))
    t=Table([["Métrique","Valeur"],
             ["Vulnérabilités",str(m.get("total","—"))],
             ["Patches validés",str(m.get("validated","—"))],
             ["Patches rejetés",str(m.get("rejected","—"))],
             ["Success rate",f"{m.get('success_rate','—')}%"],
             ["MTTR moyen",f"{m.get('mttr','—')}s"],
             ["Durée totale",f"{m.get('duration','—')}s"]],
            colWidths=[9*cm,8*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0c1118')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#00ff88')),
        ('FONTSIZE',(0,0),(-1,-1),10),
        ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#1a2535')),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#111822'),colors.HexColor('#0c1118')]),
        ('TEXTCOLOR',(0,1),(-1,-1),colors.HexColor('#cdd9e5')),
        ('PADDING',(0,0),(-1,-1),8)]))
    story.append(t); story.append(Spacer(1,0.5*cm))

    story.append(Paragraph("Vulnérabilités détectées",styles['Heading2']))
    rows=[["CWE","Fichier","Ligne","Sévérité","Statut"]]
    for r in results:
        rows.append([r["cwe"],r["file"],str(r["line"]),r["severity"][:28],"VALIDÉ" if r["success"] else "REJETÉ"])
    vt=Table(rows,colWidths=[2.5*cm,4.5*cm,1.5*cm,5.5*cm,3*cm])
    style_cmds=[
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0c1118')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#00c4ff')),
        ('FONTSIZE',(0,0),(-1,-1),8),
        ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#1a2535')),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#111822'),colors.HexColor('#0c1118')]),
        ('TEXTCOLOR',(0,1),(-1,-1),colors.HexColor('#cdd9e5')),
        ('PADDING',(0,0),(-1,-1),6)]
    for i,r in enumerate(results):
        style_cmds.append(('TEXTCOLOR',(4,i+1),(4,i+1),
            colors.HexColor('#00ff88') if r["success"] else colors.HexColor('#ff4757')))
    vt.setStyle(TableStyle(style_cmds))
    story.append(vt); story.append(Spacer(1,0.4*cm))
    story.append(Paragraph("Rapport confidentiel — PatchMind Automated Security Platform © 2026",
        ParagraphStyle('f',parent=styles['Normal'],fontSize=7,textColor=colors.grey)))
    doc.build(story)
    return send_file(fpath,as_attachment=True,download_name=fname,mimetype='application/pdf')

# ══════════════════════════════════════════════════════════════════
# DEMANDES D'ACCÈS
# ══════════════════════════════════════════════════════════════════

REQUESTS_FILE = os.path.join(BASE_DIR, 'data', 'requests.json')

def load_requests():
    return _read_json(REQUESTS_FILE, [])

def save_requests(reqs):
    _write_json(REQUESTS_FILE, reqs)

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

@app.route('/request-access', methods=['GET', 'POST'])
def request_access():
    if request.method == 'POST':
        d = request.get_json() or {}
        full_name = d.get('full_name', '').strip()
        email     = d.get('email', '').strip()
        company   = d.get('company', '').strip()
        use_case  = d.get('use_case', '').strip()

        if not all([full_name, email, company, use_case]):
            return jsonify({"error": "Tous les champs sont requis"}), 400

        # Vérifier email basique
        if '@' not in email or '.' not in email.split('@')[-1]:
            return jsonify({"error": "Email invalide"}), 400

        reqs = load_requests()

        # Vérifier doublon email
        if any(r.get('email') == email for r in reqs):
            return jsonify({"error": "Une demande existe déjà pour cet email"}), 400

        # Vérifier que l'email n'est pas déjà un compte
        users = load_users()
        if any(u.get('email') == email for u in users.values()):
            return jsonify({"error": "Un compte existe déjà avec cet email"}), 400

        reqs.append({
            "id":        secrets.token_hex(8),
            "full_name": full_name,
            "email":     email,
            "company":   company,
            "use_case":  use_case,
            "status":    "pending",
            "created_at": datetime.now().isoformat()
        })
        save_requests(reqs)
        return jsonify({"ok": True, "message": "Demande envoyée ! L'équipe PatchMind vous contactera sous 24h."})
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
    reqs = load_requests()
    req  = next((r for r in reqs if r['id'] == req_id), None)
    if not req:
        return jsonify({"error": "Demande introuvable"}), 404

    # Générer username depuis email
    username = req['email'].split('@')[0].lower().replace('.', '_').replace('-', '_')
    users    = load_users()

    # Éviter doublon username
    base, i = username, 1
    while username in users:
        username = f"{base}{i}"; i += 1

    password = generate_password()
    users[username] = {
        "password":    generate_password_hash(password),
        "role":        "user",
        "full_name":   req['full_name'],
        "email":       req['email'],
        "company":     req['company'],
        "created_at":  datetime.now().isoformat(),
        "totp_secret": generate_totp_secret(),
        "totp_enabled": False,
        "active":      True
    }
    save_users(users)
    os.makedirs(os.path.join(DATA_DIR, username, 'uploads'), exist_ok=True)

    # Marquer comme approuvée
    for r in reqs:
        if r['id'] == req_id:
            r['status']      = 'approved'
            r['username']    = username
            r['approved_at'] = datetime.now().isoformat()
    save_requests(reqs)

    # Envoyer email automatiquement
    email_sent = send_credentials_email(
        to_email  = req['email'],
        full_name = req['full_name'],
        username  = username,
        password  = password
    )

    return jsonify({
        "ok":        True,
        "username":  username,
        "email_sent": email_sent,
        "message":  f"Compte créé : {username}" + ("" if email_sent else f" — mot de passe : {password}")
    })

@app.route('/admin/requests/<req_id>/reject', methods=['POST'])
@login_required
@admin_required
def admin_reject_request(req_id):
    reqs = load_requests()
    for r in reqs:
        if r['id'] == req_id:
            r['status']     = 'rejected'
            r['rejected_at'] = datetime.now().isoformat()
    save_requests(reqs)
    return jsonify({"ok": True})

if __name__=='__main__':
    load_users()
    app.run(debug=False,host='0.0.0.0',port=5000,use_reloader=False)