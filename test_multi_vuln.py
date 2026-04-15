import sqlite3
import os
from flask import request, Flask

app = Flask(__name__)

# Vulnérabilité 1 : SQL Injection (CWE-89)
def get_user(user_id):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

# Vulnérabilité 2 : XSS (CWE-79)
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"

# Vulnérabilité 3 : Path Traversal (CWE-22)
@app.route('/file')
def get_file():
    filename = request.args.get('filename')
    filepath = "/uploads/" + filename
    with open(filepath, 'r') as f:
        return f.read()