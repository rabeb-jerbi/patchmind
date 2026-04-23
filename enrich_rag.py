"""
Script de nettoyage + enrichissement RAG.
- Supprime les doublons et exemples trop longs (validated > 400 chars)
- Garde uniquement local + osv+github + manual
- Ajoute des exemples courts et ciblés par langage/CWE
Lance depuis la racine : python enrich_rag.py
"""
import json, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAG_FILE = os.path.join(BASE_DIR, "data", "rag_examples.json")

# ── Exemples courts et ciblés ────────────────────────────────────────────────
CLEAN_EXAMPLES = {

"CWE-89": [
    {"source":"manual","description":"SQL Injection Python sqlite3 concat",
     "vulnerable":"query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"\ncursor.execute(query)",
     "fixed":"cursor.execute(\"SELECT * FROM users WHERE username = %s\", (username,))"},
    {"source":"manual","description":"SQL Injection Python f-string",
     "vulnerable":"cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
     "fixed":"cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"},
    {"source":"manual","description":"SQL Injection JavaScript template literal",
     "vulnerable":"const q = `SELECT * FROM users WHERE id = ${userId}`;\nconn.query(q);",
     "fixed":"conn.query(\"SELECT * FROM users WHERE id = ?\", [userId]);"},
    {"source":"manual","description":"SQL Injection JavaScript concat",
     "vulnerable":"const query = \"SELECT * FROM users WHERE username = '\" + username + \"'\";\ndb.query(query, callback);",
     "fixed":"db.query(\"SELECT * FROM users WHERE username = ?\", [username], callback);"},
    {"source":"manual","description":"SQL Injection Java Statement",
     "vulnerable":"String q = \"SELECT * FROM users WHERE username = '\" + username + \"'\";\nstmt.executeQuery(q);",
     "fixed":"PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE username = ?\");\nps.setString(1, username);\nps.executeQuery();"},
    {"source":"manual","description":"SQL Injection PHP mysqli concat",
     "vulnerable":"$q = \"SELECT * FROM users WHERE username = '$username'\";\nmysqli_query($conn, $q);",
     "fixed":"$stmt = $conn->prepare(\"SELECT * FROM users WHERE username = ?\");\n$stmt->bind_param(\"s\", $username);\n$stmt->execute();"},
    {"source":"manual","description":"SQL Injection PHP PDO",
     "vulnerable":"$pdo->query(\"SELECT * FROM users WHERE id = \" . $id);",
     "fixed":"$stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = ?\");\n$stmt->execute([$id]);"},
    {"source":"manual","description":"SQL Injection Go concat",
     "vulnerable":"query := \"SELECT * FROM users WHERE username = '\" + username + \"'\"\ndb.Query(query)",
     "fixed":"rows, err := db.Query(\"SELECT * FROM users WHERE username = ?\", username)"},
    {"source":"manual","description":"SQL Injection Go fmt.Sprintf",
     "vulnerable":"q := fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id)\ndb.Query(q)",
     "fixed":"rows, err := db.Query(\"SELECT * FROM users WHERE id = ?\", id)"},
    {"source":"manual","description":"SQL Injection Ruby ActiveRecord",
     "vulnerable":"User.where(\"username = '#{params[:username]}'\")",
     "fixed":"User.where(\"username = ?\", params[:username])"},
],

"CWE-79": [
    {"source":"manual","description":"XSS Python Flask f-string",
     "vulnerable":"return f\"<h1>Hello {request.args.get('name')}</h1>\"",
     "fixed":"from markupsafe import escape\nreturn f\"<h1>Hello {escape(request.args.get('name', ''))}</h1>\""},
    {"source":"manual","description":"XSS Python concat string HTML",
     "vulnerable":"return '<h1>Hello ' + username + '</h1>'",
     "fixed":"from markupsafe import escape\nreturn '<h1>Hello ' + escape(username) + '</h1>'"},
    {"source":"manual","description":"XSS JavaScript innerHTML",
     "vulnerable":"document.getElementById('output').innerHTML = userInput;",
     "fixed":"document.getElementById('output').textContent = userInput;"},
    {"source":"manual","description":"XSS JavaScript Express res.send",
     "vulnerable":"res.send('<h1>Results for: ' + query + '</h1>');",
     "fixed":"const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');\nres.send('<h1>Results for: ' + esc(query) + '</h1>');"},
    {"source":"manual","description":"XSS Java Servlet out.println",
     "vulnerable":"out.println(\"<html><body>Hello \" + request.getParameter(\"name\") + \"</body></html>\");",
     "fixed":"import org.apache.commons.text.StringEscapeUtils;\nString safe = StringEscapeUtils.escapeHtml4(request.getParameter(\"name\"));\nout.println(\"<html><body>Hello \" + safe + \"</body></html>\");"},
    {"source":"manual","description":"XSS PHP echo variable GET",
     "vulnerable":"echo \"<p>Hello \" . $_GET['name'] . \"</p>\";",
     "fixed":"echo \"<p>Hello \" . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . \"</p>\";"},
    {"source":"manual","description":"XSS PHP echo search",
     "vulnerable":"echo \"Search: \" . $search;",
     "fixed":"echo \"Search: \" . htmlspecialchars($search, ENT_QUOTES, 'UTF-8');"},
    {"source":"manual","description":"XSS Go fmt.Fprintf HTML avec variable",
     "vulnerable":"func renderPage(w http.ResponseWriter, r *http.Request) {\n    name := r.URL.Query().Get(\"name\")\n    fmt.Fprintf(w, \"<html><body>Hello \"+name+\"</body></html>\")\n}",
     "fixed":"import \"html/template\"\nfunc renderPage(w http.ResponseWriter, r *http.Request) {\n    name := r.URL.Query().Get(\"name\")\n    tmpl := template.Must(template.New(\"page\").Parse(`<html><body>Hello {{.}}</body></html>`))\n    tmpl.Execute(w, name)\n}"},
    {"source":"manual","description":"XSS Go fmt.Sprintf HTML",
     "vulnerable":"html := fmt.Sprintf(\"<h1>%s</h1>\", userInput)\nfmt.Fprint(w, html)",
     "fixed":"import \"html/template\"\ntmpl := template.Must(template.New(\"\").Parse(\"<h1>{{.}}</h1>\"))\ntmpl.Execute(w, userInput)"},
    {"source":"manual","description":"XSS document.write location.search",
     "vulnerable":"document.write('<p>' + location.search + '</p>');",
     "fixed":"const p = document.createElement('p');\np.textContent = location.search;\ndocument.body.appendChild(p);"},
],

"CWE-78": [
    {"source":"manual","description":"Command Injection Python os.system",
     "vulnerable":"os.system(\"ping -c 1 \" + host)",
     "fixed":"subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False, capture_output=True, timeout=10)"},
    {"source":"manual","description":"Command Injection Python os.popen",
     "vulnerable":"result = os.popen(\"ls \" + directory).read()",
     "fixed":"result = subprocess.run([\"ls\", directory], shell=False, capture_output=True, text=True).stdout"},
    {"source":"manual","description":"Command Injection Python subprocess shell=True",
     "vulnerable":"subprocess.run(\"nmap \" + target, shell=True)",
     "fixed":"subprocess.run([\"nmap\", target], shell=False, capture_output=True, timeout=30)"},
    {"source":"manual","description":"Command Injection JavaScript exec concat",
     "vulnerable":"exec('ping -c 1 ' + host, callback);",
     "fixed":"const {execFile} = require('child_process');\nexecFile('ping', ['-c', '1', host], callback);"},
    {"source":"manual","description":"Command Injection Java Runtime.exec",
     "vulnerable":"Runtime.getRuntime().exec(\"ping \" + host);",
     "fixed":"new ProcessBuilder(\"ping\", \"-c\", \"1\", host).redirectErrorStream(true).start();"},
    {"source":"manual","description":"Command Injection PHP shell_exec",
     "vulnerable":"$output = shell_exec(\"ping -c 1 \" . $host);",
     "fixed":"$output = shell_exec(\"ping -c 1 \" . escapeshellarg($host));"},
    {"source":"manual","description":"Command Injection Go bash -c",
     "vulnerable":"out, _ := exec.Command(\"bash\", \"-c\", \"ping -c 1 \"+host).Output()",
     "fixed":"out, err := exec.Command(\"ping\", \"-c\", \"1\", host).Output()"},
],

"CWE-22": [
    {"source":"manual","description":"Path Traversal Python open direct",
     "vulnerable":"with open('/var/www/files/' + filename, 'r') as f:\n    return f.read()",
     "fixed":"import os\nbase = '/var/www/files/'\nsafe = os.path.realpath(os.path.join(base, filename))\nif not safe.startswith(base): raise ValueError('Access denied')\nwith open(safe) as f: return f.read()"},
    {"source":"manual","description":"Path Traversal JavaScript fs.readFile",
     "vulnerable":"fs.readFile('/uploads/' + filename, 'utf8', cb);",
     "fixed":"const safe = path.resolve('/uploads/', filename);\nif (!safe.startsWith(path.resolve('/uploads/'))) return res.status(403).send('Forbidden');\nfs.readFile(safe, 'utf8', cb);"},
    {"source":"manual","description":"Path Traversal Java FileReader",
     "vulnerable":"new FileReader(\"/var/data/\" + filename);",
     "fixed":"Path base = Paths.get(\"/var/data/\").normalize();\nPath safe = base.resolve(filename).normalize();\nif (!safe.startsWith(base)) throw new SecurityException();\nnew FileReader(safe.toFile());"},
    {"source":"manual","description":"Path Traversal PHP file_get_contents",
     "vulnerable":"$content = file_get_contents('/uploads/' . $filename);",
     "fixed":"$base = realpath('/uploads/');\n$safe = realpath($base . '/' . basename($filename));\nif (!$safe || strpos($safe,$base)!==0) die('Access denied');\n$content = file_get_contents($safe);"},
    {"source":"manual","description":"Path Traversal Go ioutil.ReadFile",
     "vulnerable":"content, _ := ioutil.ReadFile(\"/var/data/\" + filename)",
     "fixed":"baseDir := \"/var/data/\"\nsafePath := filepath.Join(baseDir, filepath.Clean(filename))\nif !strings.HasPrefix(safePath, filepath.Clean(baseDir)) {\n    http.Error(w, \"Forbidden\", 403); return\n}\ncontent, err := ioutil.ReadFile(safePath)"},
],

"CWE-327": [
    {"source":"manual","description":"Weak Crypto Python MD5 password",
     "vulnerable":"hashlib.md5(password.encode()).hexdigest()",
     "fixed":"hashlib.sha256(password.encode()).hexdigest()"},
    {"source":"manual","description":"Weak Crypto Python SHA1",
     "vulnerable":"hashlib.sha1(data.encode()).hexdigest()",
     "fixed":"hashlib.sha256(data.encode()).hexdigest()"},
    {"source":"manual","description":"Weak Crypto JavaScript MD5",
     "vulnerable":"crypto.createHash('md5').update(password).digest('hex');",
     "fixed":"crypto.createHash('sha256').update(password).digest('hex');"},
    {"source":"manual","description":"Weak Crypto Java MD5",
     "vulnerable":"MessageDigest.getInstance(\"MD5\");",
     "fixed":"MessageDigest.getInstance(\"SHA-256\");"},
    {"source":"manual","description":"Weak Crypto PHP md5",
     "vulnerable":"$hash = md5($password);",
     "fixed":"$hash = password_hash($password, PASSWORD_BCRYPT);"},
    {"source":"manual","description":"Weak Crypto Go MD5",
     "vulnerable":"import \"crypto/md5\"\nh := md5.New()\nh.Write([]byte(password))\nreturn fmt.Sprintf(\"%x\", h.Sum(nil))",
     "fixed":"import \"crypto/sha256\"\nh := sha256.Sum256([]byte(password))\nreturn fmt.Sprintf(\"%x\", h)"},
],

"CWE-502": [
    {"source":"manual","description":"Insecure Deserialization Python pickle.loads",
     "vulnerable":"return pickle.loads(data)",
     "fixed":"import json\nreturn json.loads(data)"},
    {"source":"manual","description":"Insecure Deserialization Python pickle.load file",
     "vulnerable":"return pickle.load(f)",
     "fixed":"import json\nreturn json.load(f)"},
    {"source":"manual","description":"Insecure Deserialization Python yaml.load",
     "vulnerable":"data = yaml.load(user_input)",
     "fixed":"data = yaml.safe_load(user_input)"},
    {"source":"manual","description":"Insecure Deserialization Java ObjectInputStream",
     "vulnerable":"Object obj = new ObjectInputStream(inputStream).readObject();",
     "fixed":"// Use JSON with Jackson\nMyClass obj = new ObjectMapper().readValue(inputStream, MyClass.class);"},
],

"CWE-798": [
    {"source":"manual","description":"Hardcoded credentials Python SECRET_KEY",
     "vulnerable":"SECRET_KEY = 'mysecretpassword123'",
     "fixed":"import os\nSECRET_KEY = os.getenv('SECRET_KEY')"},
    {"source":"manual","description":"Hardcoded credentials Python API_KEY",
     "vulnerable":"API_KEY = 'sk-1234567890abcdef'",
     "fixed":"import os\nAPI_KEY = os.getenv('API_KEY')"},
    {"source":"manual","description":"Hardcoded credentials JavaScript",
     "vulnerable":"const DB_PASS = \"root1234\";\nconst JWT_SECRET = \"mysecretkey\";",
     "fixed":"const DB_PASS = process.env.DB_PASSWORD;\nconst JWT_SECRET = process.env.JWT_SECRET;"},
    {"source":"manual","description":"Hardcoded credentials Java",
     "vulnerable":"private static final String DB_PASSWORD = \"admin123\";",
     "fixed":"private static final String DB_PASSWORD = System.getenv(\"DB_PASSWORD\");"},
    {"source":"manual","description":"Hardcoded credentials PHP",
     "vulnerable":"define('DB_PASSWORD', 'admin123');",
     "fixed":"define('DB_PASSWORD', getenv('DB_PASSWORD'));"},
    {"source":"manual","description":"Hardcoded credentials Go const",
     "vulnerable":"const DBPassword = \"admin123\"\nconst APIKey = \"sk-1234\"",
     "fixed":"var DBPassword = os.Getenv(\"DB_PASSWORD\")\nvar APIKey = os.Getenv(\"API_KEY\")"},
],

"CWE-95": [
    {"source":"manual","description":"Code Injection Python eval",
     "vulnerable":"result = eval(user_input)",
     "fixed":"import ast\nresult = ast.literal_eval(user_input)"},
    {"source":"manual","description":"Code Injection Python exec",
     "vulnerable":"exec(user_code)",
     "fixed":"raise PermissionError('Code execution not allowed')"},
    {"source":"manual","description":"Code Injection PHP eval",
     "vulnerable":"eval(\"$result = \" . $user_input . \";\");",
     "fixed":"// Never use eval() with user input — use whitelist of operations"},
],

"CWE-611": [
    {"source":"manual","description":"XXE PHP DOMDocument loadXML",
     "vulnerable":"$doc = new DOMDocument();\n$doc->loadXML($xmlData);",
     "fixed":"libxml_disable_entity_loader(true);\n$doc = new DOMDocument();\n$doc->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD);"},
    {"source":"manual","description":"XXE Java DocumentBuilder",
     "vulnerable":"DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();\ndb.parse(xmlInput);",
     "fixed":"DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\ndbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\nDocumentBuilder db = dbf.newDocumentBuilder();\ndb.parse(xmlInput);"},
    {"source":"manual","description":"XXE Python lxml",
     "vulnerable":"from lxml import etree\ntree = etree.parse(xml_file)",
     "fixed":"from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\ntree = etree.parse(xml_file, parser)"},
],

"CWE-352": [
    {"source":"manual","description":"CSRF JavaScript Express missing token",
     "vulnerable":"app.post('/transfer', (req, res) => { processTransfer(req.body); });",
     "fixed":"const csrf = require('csurf');\nconst csrfProtection = csrf({ cookie: true });\napp.post('/transfer', csrfProtection, (req, res) => { processTransfer(req.body); });"},
    {"source":"manual","description":"CSRF PHP missing token check",
     "vulnerable":"if ($_POST['action'] === 'delete') { deleteUser($_POST['id']); }",
     "fixed":"if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {\n    die('CSRF token mismatch');\n}\nif ($_POST['action'] === 'delete') { deleteUser($_POST['id']); }"},
],

"CWE-434": [
    {"source":"manual","description":"Unrestricted File Upload PHP",
     "vulnerable":"$target = 'uploads/' . $_FILES['file']['name'];\nmove_uploaded_file($_FILES['file']['tmp_name'], $target);",
     "fixed":"$allowed = ['jpg','jpeg','png','pdf'];\n$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));\nif (!in_array($ext, $allowed)) die('Type not allowed');\n$target = 'uploads/' . uniqid() . '.' . $ext;\nmove_uploaded_file($_FILES['file']['tmp_name'], $target);"},
    {"source":"manual","description":"Unrestricted File Upload Python Flask",
     "vulnerable":"file.save(os.path.join('uploads', file.filename))",
     "fixed":"ALLOWED = {'jpg','jpeg','png','pdf'}\nfn = secure_filename(file.filename)\nif '.' not in fn or fn.rsplit('.',1)[1].lower() not in ALLOWED: abort(400)\nfile.save(os.path.join('uploads', fn))"},
],

"CWE-319": [
    {"source":"manual","description":"Cleartext Transmission Go HTTP",
     "vulnerable":"http.ListenAndServe(\":8080\", nil)",
     "fixed":"http.ListenAndServeTLS(\":8443\", \"cert.pem\", \"key.pem\", nil)"},
    {"source":"manual","description":"Cleartext Transmission Python requests",
     "vulnerable":"requests.post('http://api.example.com/login', data=creds)",
     "fixed":"requests.post('https://api.example.com/login', data=creds, verify=True)"},
],

"CWE-330": [
    {"source":"manual","description":"Weak Random Python random.randint",
     "vulnerable":"import random\ntoken = str(random.randint(100000, 999999))",
     "fixed":"import secrets\ntoken = secrets.token_hex(32)"},
    {"source":"manual","description":"Weak Random JavaScript Math.random",
     "vulnerable":"const token = Math.random().toString(36).substr(2);",
     "fixed":"const token = require('crypto').randomBytes(32).toString('hex');"},
    {"source":"manual","description":"Weak Random Java Random",
     "vulnerable":"int token = new Random().nextInt(999999);",
     "fixed":"byte[] token = new byte[32];\nnew SecureRandom().nextBytes(token);"},
    {"source":"manual","description":"Weak Random PHP rand",
     "vulnerable":"$token = rand(100000, 999999);",
     "fixed":"$token = bin2hex(random_bytes(32));"},
],

"CWE-601": [
    {"source":"manual","description":"Open Redirect Python Flask",
     "vulnerable":"return redirect(request.args.get('next'))",
     "fixed":"from urllib.parse import urlparse\nnext_url = request.args.get('next', '/')\nif urlparse(next_url).netloc: next_url = '/'\nreturn redirect(next_url)"},
    {"source":"manual","description":"Open Redirect PHP header",
     "vulnerable":"header('Location: ' . $_GET['redirect']);",
     "fixed":"$r = $_GET['redirect'] ?? '/';\nif (parse_url($r, PHP_URL_HOST)) die('Invalid redirect');\nheader('Location: ' . $r);"},
],

}

def clean_and_enrich():
    # Charger la base
    if os.path.exists(RAG_FILE):
        with open(RAG_FILE, "r", encoding="utf-8") as f:
            db = json.load(f)
        print(f"📂 Base chargée : {sum(len(v) for v in db.values())} exemples")
    else:
        db = {}
        print("📂 Nouvelle base")

    # ── ÉTAPE 1 : Nettoyer les exemples validated trop longs ──────────────────
    removed = 0
    for cwe in list(db.keys()):
        clean = []
        for ex in db[cwe]:
            src = ex.get("source","")
            vuln_len = len(ex.get("vulnerable",""))
            fixed_len = len(ex.get("fixed",""))
            # Garder : local, osv+github, manual — supprimer validated trop longs
            if src == "validated" and (vuln_len > 350 or fixed_len > 350):
                removed += 1
                continue
            # Supprimer les exemples où vulnerable == fixed (inutiles)
            if ex.get("vulnerable","")[:100] == ex.get("fixed","")[:100]:
                removed += 1
                continue
            clean.append(ex)
        db[cwe] = clean
    print(f"🧹 {removed} exemples inutiles supprimés")

    # ── ÉTAPE 2 : Dédupliquer ────────────────────────────────────────────────
    dedup = 0
    for cwe in list(db.keys()):
        seen = set()
        unique = []
        for ex in db[cwe]:
            key = ex.get("vulnerable","")[:80]
            if key not in seen:
                seen.add(key)
                unique.append(ex)
            else:
                dedup += 1
        db[cwe] = unique
    print(f"🔁 {dedup} doublons supprimés")

    # ── ÉTAPE 3 : Ajouter les nouveaux exemples ciblés ───────────────────────
    added = 0
    for cwe, examples in CLEAN_EXAMPLES.items():
        existing = db.get(cwe, [])
        existing_keys = {e.get("vulnerable","")[:80] for e in existing}
        for ex in examples:
            ex["cwe"] = cwe
            key = ex["vulnerable"][:80]
            if key not in existing_keys:
                existing.append(ex)
                existing_keys.add(key)
                added += 1
        db[cwe] = existing

    print(f"✅ {added} nouveaux exemples ajoutés")

    # Sauvegarder
    with open(RAG_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    total = sum(len(v) for v in db.values())
    print(f"\n📚 Base finale : {total} exemples pour {len(db)} CWE")
    print(f"💾 Sauvegardé : {RAG_FILE}")
    print("\nDétail :")
    for cwe, exs in sorted(db.items()):
        manual = sum(1 for e in exs if e.get("source")=="manual")
        local  = sum(1 for e in exs if e.get("source")=="local")
        osv    = sum(1 for e in exs if e.get("source")=="osv+github")
        val    = sum(1 for e in exs if e.get("source")=="validated")
        print(f"  {cwe:12s}: {len(exs):3d} total  ({manual} manual, {local} local, {osv} osv, {val} validated)")

if __name__ == "__main__":
    clean_and_enrich()