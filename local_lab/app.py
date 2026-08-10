"""Local vulnerable test application for Titan Scanner validation.

Run: python local_lab/app.py
Then scan: http://localhost:5000
"""

from flask import Flask, request, jsonify, make_response
import jwt
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"

# === 1. SQL Injection ===
@app.route("/sqli", methods=["GET"])
def sqli():
    user_id = request.args.get("id", "1")
    # Vulnerable: string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # Simulate SQL execution for the boolean oracle: a real database would
    # return different records for a tautology vs. a contradiction.
    upper = user_id.upper()
    if "OR 1=1" in upper:
        result = "admin,user,guest"  # tautology: all users
    elif "AND 1=2" in upper:
        result = ""  # contradiction: no users
    else:
        result = "admin"
    return jsonify({"query": query, "result": result})


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
    # Vulnerable: direct file inclusion
    try:
        with open(file, "r") as f:
            return f.read()
    except Exception as e:
        return str(e)


# === 4. Command Injection ===
@app.route("/cmd", methods=["GET"])
def cmd():
    host = request.args.get("host", "localhost")
    # Vulnerable: shell execution
    os.system(f"ping -c 1 {host}")
    return jsonify({"status": "pong"})


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


if __name__ == "__main__":
    print("[+] Starting vulnerable app on http://localhost:5000")
    print("[+] Endpoints: /sqli, /xss, /lfi, /cmd, /api/user, /api/login, /api/data, /hash, /config")
    app.run(host="0.0.0.0", port=5000, debug=True)
