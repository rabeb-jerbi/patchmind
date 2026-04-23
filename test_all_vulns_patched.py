import sqlite3
import os
import subprocess
import hashlib
import pickle
import eval
from flask import request, Flask, render_template_string

app = Flask(__name__)

# ============================================================
# 1. SQL Injection (CWE-89)
# ============================================================
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

# ============================================================
# 2. Command Injection (CWE-78)
# ============================================================
def ping_host(host):
    os.system("ping " + host)

# ============================================================
# 3. XSS (CWE-79)
# ============================================================
@app.route('/search')
def search():
    query = request.args.get('q')
    return render_template_string('<h1>Results for: {{ query }}</h1>', query=query)

# ============================================================
# 4. Path Traversal (CWE-22)
# ============================================================
@app.route('/file')
def get_file():
    filename = request.args.get('filename')
    base_dir = "/uploads/"
    filepath = os.path.realpath(os.path.join(base_dir, filename))
    if not filepath.startswith(base_dir):
        raise ValueError('Invalid path')
    with open(filepath, 'r') as f:
        return f.read()

# ============================================================
# 5. Hardcoded Secrets (CWE-798)
# ============================================================
def connect_db():
    SECRET_KEY = "mysecretpassword123"
    API_KEY    = "sk-1234567890abcdef"
    DB_PASS    = "admin123"
    return SECRET_KEY, API_KEY, DB_PASS

# ============================================================
# 6. Unsafe eval/exec (CWE-95)
# ============================================================
def calculate(expression):
    result = eval(expression)
    return result

def run_code(code):
    exec(code)

# ============================================================
# 7. Weak Crypto (CWE-327)
# ============================================================
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_data(data):
    return hashlib.sha1(data.encode()).hexdigest()

# ============================================================
# 8. Improper Input Validation (CWE-20)
# ============================================================
def set_age(age):
    # Pas de validation
    user_age = int(age)
    return user_age

def set_email(email):
    # Pas de validation format email
    return email

# ============================================================
# 9. Insecure File Handling (CWE-732)
# ============================================================
def write_file(filename, data):
    # Permissions trop larges
    with open(filename, 'w') as f:
        f.write(data)
    os.chmod(filename, 0o777)

def read_config():
    # Lecture fichier sensible sans vérification
    with open('/etc/passwd', 'r') as f:
        return f.read()

# ============================================================
# 10. Insecure Deserialization (CWE-502)
# ============================================================
def load_user_data(data):
    return pickle.loads(data)

def load_from_file(filepath):
    with open(filepath, 'rb') as f:
        return pickle.load(f)