"""Local vulnerable test application for Titan Scanner validation.

Run: python local_lab/app.py
Then scan: http://localhost:5000
"""

from flask import Flask, request, jsonify, make_response, send_from_directory
import jwt
import re
import os
import shutil
import subprocess
import sys
import time
import uuid

app = Flask(__name__)
try:
    from scenario_fixtures import scenario_fixtures_bp
except ImportError:  # imported as a package (local_lab.app)
    from .scenario_fixtures import scenario_fixtures_bp
app.register_blueprint(scenario_fixtures_bp)

try:
    from shop import shop_bp
except ImportError:  # imported as a package (local_lab.app)
    from .shop import shop_bp
app.register_blueprint(shop_bp)

try:
    from streaming import streaming_bp
except ImportError:  # imported as a package (local_lab.app)
    from .streaming import streaming_bp
app.register_blueprint(streaming_bp)
app.secret_key = "supersecretkey"

# === 1. SQL Injection ===
# Simulated database for extraction exercises (M3): a small users table that
# the UNION/boolean probes can query against.
LAB_USERS = [
    {"id": 1, "username": "admin", "email": "admin@lab.local", "role": "admin"},
    {"id": 2, "username": "alice", "email": "alice@lab.local", "role": "user"},
    {"id": 3, "username": "bob", "email": "bob@lab.local", "role": "user"},
    {"id": 4, "username": "guest", "email": "guest@lab.local", "role": "viewer"},
]


@app.route("/sqli", methods=["GET"])
def sqli():
    user_id = request.args.get("id", "1")
    # Vulnerable: string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    upper = user_id.upper()

    def _eval_cond(cond: str) -> bool:
        """Evaluate the extractor's boolean probes against LAB_USERS.

        Mirrors the test stub's semantics exactly: length probes
        `LENGTH((SELECT col FROM t LIMIT r,1))>=N` and char probes
        `ASCII(SUBSTRING((SELECT col FROM t LIMIT r,1),p,1))>C` (both the
        `>=` and `>` binary-search operators). Unknown expressions evaluate
        conservatively true so the oracle never freezes the search.
        """
        m_len = re.search(
            r"LENGTH\s*\(\s*\(\s*SELECT\s+(\w+)\s+FROM\s+\w+\s+LIMIT\s+(\d+),1\s*\)\s*\)\s*>=\s*(\d+)",
            cond.upper(),
        )
        if m_len:
            col, ridx, n = m_len.group(1), int(m_len.group(2)), int(m_len.group(3))
            if ridx >= len(LAB_USERS):
                return False
            return len(str(LAB_USERS[ridx].get(col.lower(), ""))) >= n
        m = re.search(
            r"ASCII\s*\(\s*SUBSTRING\s*\(\s*\(\s*SELECT\s+(\w+)\s+FROM\s+\w+\s+LIMIT\s+(\d+),1\s*\)\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*(>=|>)\s*(\d+)",
            cond.upper(),
        )
        if not m:
            return True  # unknown expression -> conservative true
        col, ridx, pos, op, threshold = (
            m.group(1),
            int(m.group(2)),
            int(m.group(3)),
            m.group(4),
            int(m.group(5)),
        )
        if ridx >= len(LAB_USERS):
            return False
        val = str(LAB_USERS[ridx].get(col.lower(), ""))
        if pos > len(val):
            return False
        ascii_val = ord(val[pos - 1])
        return ascii_val > threshold if op == ">" else ascii_val >= threshold

    # Boolean oracle: the injected condition decides true/false. Greedy
    # capture up to the final ")--" because the condition nests parentheses.
    m_cond = re.search(r"OR \((.+)\)--", upper)
    if m_cond:
        return jsonify({"query": query, "result": "admin" if _eval_cond(m_cond.group(1)) else ""})
    if "OR 1=1" in upper:
        return jsonify({"query": query, "result": "admin,user,guest"})
    if "AND 1=2" in upper:
        return jsonify({"query": query, "result": ""})
    # ORDER BY N -- column-count probe for UNION extraction.
    m = re.search(r"ORDER BY\s+(\d+)--", upper)
    if m:
        n = int(m.group(1))
        cols = len(LAB_USERS[0])
        if n <= cols:
            return jsonify({"query": query, "result": ["ok"] * n})
        return jsonify({"query": query, "result": ""})
    # UNION SELECT col1,col2,... FROM users -- data extraction (echoes the
    # selected values mapped from the simulated table). The FROM clause is
    # split off FIRST so the column list never swallows "FROM users".
    m = re.search(r"UNION\s+SELECT\s+(.+?)\s+FROM\s+(\w+)--", upper)
    if m:
        cols = [p.strip().strip("'") for p in m.group(1).split(",")]
        tbl = m.group(2).upper()
        if tbl == "USERS":
            # Real-DB semantics: a UNION must match the base query's column
            # count (`SELECT * FROM users` = 4). Mismatched unions error out.
            if len(cols) != len(LAB_USERS[0]):
                return jsonify({"query": query, "result": ""})
            rows = []
            for u in LAB_USERS:
                vals = []
                for c in cols:
                    up = c.upper()
                    if up == "USERNAME":
                        vals.append(u["username"])
                    elif up == "EMAIL":
                        vals.append(u["email"])
                    elif up == "ROLE":
                        vals.append(u["role"])
                    elif up == "ID":
                        vals.append(str(u["id"]))
                    else:
                        vals.append(c)
                rows.append(vals)
            return jsonify({"query": query, "result": rows})
        return jsonify({"query": query, "result": ""})
    return jsonify({"query": query, "result": "admin"})


# === 1b. SQLi — MSSQL / PostgreSQL / comment-bypass shapes (SHARPEN-S3) ===
# Real codebases mix DB flavours; the detector must confirm timing sinks it
# never shipped before (WAITFOR, pg_sleep, BENCHMARK) and payloads that
# survived a naive regex WAF via /**/ comment tokens.
@app.route("/sqli_mssql", methods=["GET"])
def sqli_mssql():
    # Vulnerable: MSSQL-style sink. WAITFOR DELAY is a real 3s delay.
    user_id = request.args.get("id", "1")
    if "WAITFOR DELAY" in user_id.upper():
        time.sleep(3)
        return jsonify({"query": user_id, "result": ""})
    # Error oracle: a quote breaks the query and MSSQL complains verbosely.
    if "'" in user_id:
        return "Microsoft OLE DB Driver for SQL Server: Incorrect syntax near the keyword 'and'.", 500
    return jsonify({"query": user_id, "result": "admin"})


@app.route("/sqli_pg", methods=["GET"])
def sqli_pg():
    # Vulnerable: PostgreSQL-style sink with pg_sleep timing.
    user_id = request.args.get("id", "1")
    if "PG_SLEEP" in user_id.upper():
        time.sleep(3)
        return jsonify({"query": user_id, "result": ""})
    if "'" in user_id:
        return "psycopg2.errors.SyntaxError: syntax error at or near \"1\"", 500
    return jsonify({"query": user_id, "result": "admin"})


@app.route("/sqli_comment_bypass", methods=["GET"])
def sqli_comment_bypass():
    # Vulnerable sink behind a NAIVE WAF: it blocks "OR 1=1" and "SLEEP(3)"
    # literally, but /**/ comment tokens sail through (the classic regex WAF
    # hole). The detector's comment-bypass payloads must confirm it.
    user_id = request.args.get("id", "1")
    stripped = user_id.replace("/**/", "")
    if "WAITFOR DELAY" in stripped.upper():
        time.sleep(3)
        return jsonify({"query": user_id, "result": ""})
    if "SLEEP(" in stripped.upper() and "PG_SLEEP" not in stripped.upper():
        time.sleep(3)
        return jsonify({"query": user_id, "result": ""})
    if "OR 1=1" in stripped.upper():
        return jsonify({"query": user_id, "result": "admin,user,guest"})
    if "AND 1=2" in stripped.upper():
        return jsonify({"query": user_id, "result": ""})
    return jsonify({"query": user_id, "result": "admin"})


# === 2. Reflected XSS ===
@app.route("/xss", methods=["GET"])
def xss():
    name = request.args.get("name", "")
    # Vulnerable: no escaping
    return f"<h1>Hello {name}</h1>"


# === 3. LFI ===
@app.route("/lfi", methods=["GET"])
def lfi():
    file = request.args.get("file", "")
    # Vulnerable: direct file inclusion. Paths resolve relative to the lab's
    # own directory so the advertised baseline ``file=app.py`` actually reads
    # (the homepage link), no matter which cwd the lab was launched from —
    # otherwise the baseline itself errors and the detector's baseline
    # differential cancels out. The traversal sink is unchanged.
    try:
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, file), "r") as f:
            return f.read()
    except Exception as e:
        return str(e)


# === 3.5 SSRF ===
@app.route("/ssrf", methods=["GET"])
def ssrf():
    url = request.args.get("url", "")
    # Vulnerable: fetches ANY url server-side (classic SSRF sink). Bounded to
    # 5s so a slow/hanging target can't stall scans or the test suite.
    if not url:
        return "provide ?url=", 400
    try:
        import urllib.request

        with urllib.request.urlopen(url, timeout=5) as r:
            return r.read(20000).decode("utf-8", errors="replace")
    except Exception as e:
        return f"fetch failed: {e}", 502


@app.route("/internal/meta")
def internal_meta():
    # The "internal service" the SSRF sink can reach — cloud-metadata style
    # content the detector verifies against (ami-id is a canonical marker).
    return "ami-id: i-0lab1234\ninstance-type: t3.micro\nregion: us-east-1\n"


# === 4. Command Injection ===
@app.route("/cmd", methods=["GET"])
def cmd():
    host = request.args.get("host", "localhost")
    # Vulnerable: shell execution (output discarded — the endpoint is blind,
    # exactly like a real ping/health endpoint).
    #
    # The child is BOUND to 5s: payloads like `| ping -n 3 127.0.0.1` make
    # GNU ping resolve the bare host `3` over DNS, which can stall for minutes
    # on a slow/blocked resolver (seen on GitHub Actions runners). An unbounded
    # os.system would hang scans and the test suite — the 5s cap keeps the lab
    # realistic while bounding worst-case latency.
    try:
        # The sink simulates a Unix-style ping healthcheck (GNU `ping -c`).
        # On Windows the default shell is cmd.exe, which does not understand
        # bash payloads (`;curl ... | bash`) — Track E agents never call home.
        # Run through bash explicitly when available so the sink behaves like
        # the Linux lab it models and bash staging payloads land.
        if sys.platform != "win32" and shutil.which("bash"):
            subprocess.run(
                [shutil.which("bash"), "-c", f"ping -c 1 {host}"],
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            cmd_str = f"ping -n 1 {host}" if sys.platform == "win32" else f"ping -c 1 {host}"
            subprocess.run(
                cmd_str,
                shell=True,
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except subprocess.TimeoutExpired:
        pass
    return jsonify({"status": "pong"})


# === 4b. File Upload (weak filter — M2 webshell channel) ===
# Stores uploads under local_lab/uploads/ and serves them from /uploads/<name>.
# The filter is deliberately weak: it rejects a trailing ".php" but trusts the
# final extension, so "shell.php.jpg" sails through and PHP still executes it
# when the web server maps .jpg to the PHP handler (Apache+mod_php default
# AddHandler). This is the classic double-extension bypass.
LAB_UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(LAB_UPLOAD_DIR, exist_ok=True)


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file") or request.files.get("upload")
    if not file or not file.filename:
        return jsonify({"error": "no file"}), 400
    name = file.filename
    # Weak filter: only blocks names that END in .php (case-insensitive).
    if name.lower().endswith(".php"):
        return jsonify({"error": "php not allowed"}), 403
    # Save under a server-generated name to keep the traversal surface boring.
    stored = f"{uuid.uuid4().hex[:8]}_{name}"
    file.save(os.path.join(LAB_UPLOAD_DIR, stored))
    return jsonify({"uploaded": True, "filename": stored, "url": f"/uploads/{stored}"})


@app.route("/uploads/<path:filename>")
def uploaded_file(filename: str):
    safe = os.path.basename(filename)
    return send_from_directory(LAB_UPLOAD_DIR, safe)


# === 5. IDOR ===
@app.route("/api/user", methods=["GET"])
def get_user():
    user_id = request.args.get("id", "1")
    # Vulnerable: no auth check
    users = {
        "1": {"name": "Admin", "role": "admin", "ssn": "123-45-6789"},
        "2": {"name": "User", "role": "user", "ssn": "987-65-4321"},
    }
    return jsonify(users.get(user_id, {}))


# === 6. JWT None Algorithm ===
@app.route("/api/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username and password:
        # Vulnerable: signs with none algorithm
        token = jwt.encode({"user": username, "role": "admin"}, None, algorithm="none")
        return jsonify({"token": token})
    return jsonify({"error": "invalid"}), 401


# === 7. CORS Misconfiguration ===
@app.route("/api/data", methods=["GET"])
def api_data():
    resp = make_response(jsonify({"secret": "api_key_12345"}))
    # Vulnerable: allows any origin
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


# === 8. Missing Security Headers ===
@app.route("/")
def index():
    return """
    <html>
    <head><title>Vulnerable Lab</title></head>
    <body>
        <h1>Vulnerable Application Lab</h1>
        <ul>
            <li><a href="/sqli?id=1">SQL Injection</a></li>
            <li><a href="/xss?name=test">XSS</a></li>
            <li><a href="/lfi?file=app.py">LFI</a></li>
            <li><a href="/cmd?host=localhost">Command Injection</a></li>
            <li><a href="/api/user?id=1">IDOR</a></li>
            <li><a href="/api/login">JWT None Algorithm</a></li>
            <li><a href="/api/data">CORS Misconfiguration</a></li>
            <li><a href="/hash">Weak Crypto (MD5)</a></li>
            <li><a href="/config">Hardcoded Credentials</a></li>
            <li><a href="/ssrf?url=http://127.0.0.1:5000/internal/meta">SSRF</a></li>
            <li><a href="/internal/meta">Internal Metadata</a></li>
        </ul>
        <form action="/sqli" method="GET">
            <input name="id" value="1">
            <button type="submit">SQLi Form</button>
        </form>
        <form action="/xss" method="GET">
            <input name="name" value="test">
            <button type="submit">XSS Form</button>
        </form>
    </body>
    </html>
    """


# === 9. Weak Crypto (MD5) ===
@app.route("/hash", methods=["POST"])
def hash_password():
    password = request.form.get("password", "")
    import hashlib
    # Vulnerable: uses MD5
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"hash": hashed})


# === 10. Hardcoded Credentials ===
@app.route("/config", methods=["GET"])
def config():
    return jsonify({
        "database_password": "SuperSecret123!",
        "api_key": "AIzaSyD-EXAMPLE-KEY",
        "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }        )


# === 11. Client-side redirect hijacks (Track F) ===
# The zairaku.rest shape: a CLEAN HTTP 200 whose hijack lives in client-side
# JS / meta tags — invisible to curl, only a browser sees it. These endpoints
# are safe for the Flask test client (no external navigation actually happens
# in tests; the RedirectDetector reads the recorded navigation attempts).


@app.route("/redirect-meta")
def redirect_meta():
    # Meta-refresh hijack fired on page parse.
    return (
        "<html><head><meta http-equiv=\"refresh\" "
        "content=\"0;url=https://evil.example/steal\"></head>"
        "<body><h1>Legit page</h1></body></html>"
    )


@app.route("/redirect-js")
def redirect_js():
    # Script-driven hijack: location.replace fired on load.
    return (
        "<html><body><h1>Legit page</h1>"
        "<script>window.location.replace('https://evil.example/phish');</script>"
        "</body></html>"
    )


@app.route("/redirect-clean")
def redirect_clean():
    # Benign control: same-origin link, no hijack.
    return (
        "<html><head><meta http-equiv=\"refresh\" "
        "content=\"0;url=/\"></head><body>ok</body></html>"
    )


if __name__ == "__main__":
    print("[+] Starting vulnerable app on http://localhost:5000")
    print("[+] Endpoints: /sqli, /sqli_mssql, /sqli_pg, /sqli_comment_bypass, /xss, /lfi, /ssrf, /internal/meta, /cmd, /upload, /api/user, /api/login, /api/data, /hash, /config, /redirect-meta, /redirect-js")
    print("[+] Titan Shop: /shop (auth /shop/register, /shop/login, /shop/admin, /shop/reset; catalog /shop/products, /shop/product/<id>, /shop/product/<id>/review; orders /shop/checkout, /shop/order/<id>; payments /shop/pay, /shop/payments, /shop/refund/<id>, /shop/webhook/payment)")
    print("[+] STREAM-PEAK: /stream (player; leaks signing salt in JS), /stream/play/<id> (token-gated), /stream/sign (unauthenticated signing oracle), /stream/admin (forged-token gate), /stream/cdn/edge (anti-scraper challenge)")
    # Default to loopback + no debug: the lab is deliberately vulnerable, so it
    # must not be reachable from the network or carry the Werkzeug interactive
    # debugger (an RCE console) unless the operator explicitly opts in.
    app.run(
        host=os.environ.get("TITAN_LAB_HOST", "127.0.0.1"),
        port=int(os.environ.get("TITAN_LAB_PORT", "5000")),
        debug=os.environ.get("TITAN_LAB_DEBUG", "") == "1",
    )
