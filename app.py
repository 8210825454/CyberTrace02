import os, re, json, csv, io, uuid, hashlib, sqlite3, zipfile, shutil, subprocess, smtplib, secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import Flask, request, jsonify, render_template, render_template_string, send_file, abort, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import yaml

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
EVIDENCE = DATA / "evidence"
REPORTS = DATA / "reports"
PACKAGES = DATA / "packages"
for folder in (DATA, EVIDENCE, REPORTS, PACKAGES):
    folder.mkdir(parents=True, exist_ok=True)
DB = DATA / "cybertrace.db"
ALLOWED = {".raw", ".mem", ".dmp", ".lime", ".pcap", ".pcapng", ".evtx", ".log", ".txt"}
app = Flask(__name__)

app.secret_key = os.getenv("CYBERTRACE_SECRET_KEY", "local-development-only-change-me")
if os.getenv("RENDER") == "true" and app.secret_key == "local-development-only-change-me":
    raise RuntimeError("Set a strong CYBERTRACE_SECRET_KEY in Render environment.")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("RENDER") == "true"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access CyberTrace."
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "512")) * 1024 * 1024

def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row

    # User accounts
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            created TEXT NOT NULL
        )
    """)

    user_columns = [row["name"] for row in c.execute("PRAGMA table_info(users)").fetchall()]
    if "username" not in user_columns:
        c.execute("ALTER TABLE users ADD COLUMN username TEXT")
        # Existing accounts use the email prefix as a default username.
        for row in c.execute("SELECT id,email FROM users WHERE username IS NULL").fetchall():
            base_name = row["email"].split("@")[0]
            candidate = base_name
            n = 1
            while c.execute("SELECT 1 FROM users WHERE username=?", (candidate,)).fetchone():
                candidate = f"{base_name}{n}"; n += 1
            c.execute("UPDATE users SET username=? WHERE id=?", (candidate, row["id"]))

    c.execute("""CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL, expires TEXT NOT NULL, used INTEGER DEFAULT 0
    )""")

    # Evidence records
    c.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            filename TEXT,
            path TEXT,
            sha256 TEXT,
            created TEXT,
            size INTEGER,
            owner_id INTEGER
        )
    """)

    # Add owner_id to an existing evidence table if needed
    columns = [
        row["name"] for row in
        c.execute("PRAGMA table_info(evidence)").fetchall()
    ]

    if "owner_id" not in columns:
        c.execute("ALTER TABLE evidence ADD COLUMN owner_id INTEGER")

    # Chain of custody
    c.execute("""
        CREATE TABLE IF NOT EXISTS custody (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT,
            event TEXT,
            timestamp TEXT,
            prev_hash TEXT,
            record_hash TEXT,
            signature TEXT,
            details TEXT
        )
    """)

    c.commit()
    return c
class User(UserMixin):
    def __init__(self, user_id, email):
        self.id = str(user_id)
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    c = db()

    user = c.execute(
        "SELECT id, email FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    c.close()

    if user:
        return User(user["id"], user["email"])

    return None

def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def signing_key():
    key_path = DATA / "custody_ed25519.pem"
    if key_path.exists():
        return serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    try: os.chmod(key_path, 0o600)
    except OSError: pass
    return key

def add_custody(c, evidence_id, event, evidence_sha, details=None):
    last = c.execute("SELECT record_hash FROM custody ORDER BY seq DESC LIMIT 1").fetchone()
    prev = last["record_hash"] if last else "GENESIS"
    ts = now()
    payload = json.dumps({
        "evidence_id": evidence_id, "event": event, "timestamp": ts,
        "prev_hash": prev, "evidence_sha256": evidence_sha, "details": details or {}
    }, sort_keys=True, separators=(",", ":")).encode()
    record_hash = hashlib.sha256(payload).hexdigest()
    signature = signing_key().sign(record_hash.encode()).hex()
    c.execute("""INSERT INTO custody(evidence_id,event,timestamp,prev_hash,record_hash,signature,details)
                 VALUES(?,?,?,?,?,?,?)""",
              (evidence_id, event, ts, prev, record_hash, signature, json.dumps(details or {})))
    c.commit()

def verify_custody():
    c = db()
    rows = c.execute("SELECT custody.* FROM custody JOIN evidence ON evidence.id=custody.evidence_id WHERE evidence.owner_id=? ORDER BY custody.seq", (int(current_user.get_id()),)).fetchall()
    pub = signing_key().public_key()
    previous = "GENESIS"
    results = []
    valid = True
    for row in rows:
        ok = row["prev_hash"] == previous
        try:
            pub.verify(bytes.fromhex(row["signature"]), row["record_hash"].encode())
        except (InvalidSignature, ValueError):
            ok = False
        if not ok: valid = False
        results.append({"seq": row["seq"], "evidence_id": row["evidence_id"],
                        "event": row["event"], "valid": ok, "record_hash": row["record_hash"]})
        previous = row["record_hash"]
    return {"valid": valid, "records": len(rows), "details": results}

def extract_iocs(text):
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    domains = sorted(set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)))
    hashes = sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", text)))
    return {"ipv4": ips, "domains": domains, "sha256": hashes}

def yara_scan(path):
    try:
        import yara
        rule_files = {p.stem: str(p) for p in (ROOT / "rules" / "yara").glob("*.yar")}
        if not rule_files: return []
        compiled = yara.compile(filepaths=rule_files)
        return [{"rule": m.rule, "tags": list(m.tags), "strings": [str(x) for x in m.strings]}
                for m in compiled.match(str(path), timeout=15)]
    except Exception as e:
        return [{"status": "unavailable", "reason": str(e)}]

def sigma_triage(text):
    # Minimal Sigma selection matcher for simple string/contains rules.
    # It is explicitly not a full Sigma backend or full condition evaluator.
    findings = []
    for rule_path in (ROOT / "rules" / "sigma").glob("*.y*ml"):
        try:
            rule = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
            detection = rule.get("detection", {})
            selection = detection.get("selection", {})
            matched = []
            if isinstance(selection, dict):
                for key, expected in selection.items():
                    vals = expected if isinstance(expected, list) else [expected]
                    if any(str(v).lower() in text.lower() for v in vals):
                        matched.append(str(key))
            if matched:
                findings.append({"rule": rule.get("title", rule_path.stem),
                                 "level": rule.get("level", "unknown"),
                                 "matched_fields": matched,
                                 "note": "Starter keyword/substring match; validate with a full Sigma backend."})
        except Exception as e:
            findings.append({"rule_file": rule_path.name, "error": str(e)})
    return findings

def volatility_analysis(path):
    vol = shutil.which("vol") or shutil.which("volatility")
    if not vol:
        return {"available": False, "message": "Volatility CLI not found. Install Volatility 3 and ensure 'vol' is on PATH."}
    plugins = ["windows.info", "windows.pslist", "windows.netscan", "windows.cmdline"]
    output = {}
    for plugin in plugins:
        try:
            p = subprocess.run([vol, "-f", str(path), plugin], capture_output=True,
                               text=True, timeout=240)
            output[plugin] = {"returncode": p.returncode, "stdout": p.stdout[:40000],
                              "stderr": p.stderr[:5000]}
        except Exception as e:
            output[plugin] = {"error": str(e)}
    return {"available": True, "plugins": output,
            "note": "Plugin success depends on memory image format, OS profile/symbol availability, and Volatility support."}

def analyze_pcap(path):
    result = {"packet_count": 0, "flows": [], "iocs": {"ipv4": [], "domains": [], "sha256": []}}
    try:
        from scapy.all import PcapReader, IP, TCP, UDP, DNSQR
        flows, ips, domains = {}, set(), set()
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                result["packet_count"] += 1
                if IP in pkt:
                    src, dst = pkt[IP].src, pkt[IP].dst
                    ips.update([src, dst])
                    proto, sport, dport = "IP", None, None
                    if TCP in pkt: proto, sport, dport = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
                    elif UDP in pkt: proto, sport, dport = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
                    key = (src, dst, proto, sport, dport)
                    flows[key] = flows.get(key, 0) + 1
                if DNSQR in pkt:
                    try: domains.add(pkt[DNSQR].qname.decode(errors="ignore").rstrip("."))
                    except Exception: pass
        result["flows"] = [{"src": k[0], "dst": k[1], "protocol": k[2],
                            "src_port": k[3], "dst_port": k[4], "packets": v}
                           for k, v in flows.items()]
        result["iocs"] = {"ipv4": sorted(ips), "domains": sorted(domains), "sha256": []}
    except Exception as e:
        result["error"] = str(e)
    return result

def neo4j_write(nodes, edges):
    uri, user, password = os.getenv("NEO4J_URI"), os.getenv("NEO4J_USERNAME"), os.getenv("NEO4J_PASSWORD")
    if not (uri and user and password):
        return {"connected": False, "message": "Neo4j not configured; interactive graph is generated from local analysis reports."}
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session(database=os.getenv("NEO4J_DATABASE", "neo4j")) as session:
            for n in nodes:
                session.run("MERGE (x:CyberTraceNode {id:$id}) SET x.label=$label, x.group=$group",
                            id=n["id"], label=n["label"], group=n.get("group", "entity"))
            for e in edges:
                session.run("""MATCH (a:CyberTraceNode {id:$from}), (b:CyberTraceNode {id:$to})
                               MERGE (a)-[r:RELATED {label:$label}]->(b)""",
                            **{"from": e["from"], "to": e["to"], "label": e.get("label", "related")})
        driver.close()
        return {"connected": True, "message": "Nodes and relationships synchronized to Neo4j."}
    except Exception as e:
        return {"connected": False, "message": "Neo4j connection failed: " + str(e)}

def build_graph():
    c = db()
    rows = c.execute("SELECT id,filename,sha256,size FROM evidence WHERE owner_id=? ORDER BY created", (int(current_user.get_id()),)).fetchall()
    nodes = [{"id": "root", "label": "Evidence Repository", "group": "root",
              "title": "CyberTrace evidence repository"}]
    edges, seen = [], {"root"}
    def node(i, label, group, title=""):
        if i not in seen:
            nodes.append({"id": i, "label": label, "group": group, "title": title or label})
            seen.add(i)
    for row in rows:
        eid = row["id"]
        node(eid, row["filename"], "evidence",
             f"Evidence: {row['filename']}\\nSHA-256: {row['sha256']}\\nSize: {row['size']} bytes")
        edges.append({"from": "root", "to": eid, "label": "registered"})
        report_path = REPORTS / (eid + ".json")
        if not report_path.exists(): continue
        try: report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception: continue
        flows = report.get("network", {}).get("flows", [])
        for i, flow in enumerate(flows):
            src, dst = flow.get("src"), flow.get("dst")
            if src:
                sid = "ip:" + src; node(sid, src, "ip", "IP address: " + src)
                edges.append({"from": eid, "to": sid, "label": "observed source"})
            if dst:
                did = "ip:" + dst; node(did, dst, "ip", "IP address: " + dst)
                edges.append({"from": eid, "to": did, "label": "observed destination"})
            if src and dst:
                fid = f"flow:{eid}:{i}"
                node(fid, f"{flow.get('protocol','IP')} {flow.get('src_port') or ''}→{flow.get('dst_port') or ''}",
                     "flow", json.dumps(flow, indent=2))
                edges += [{"from": sid, "to": fid, "label": "source"},
                          {"from": fid, "to": did, "label": "destination"}]
        for item in report.get("iocs", {}).get("ipv4", []):
            iid = "ioc-ip:" + item; node(iid, item, "ioc", "Extracted IPv4 indicator")
            edges.append({"from": eid, "to": iid, "label": "IOC"})
        for item in report.get("iocs", {}).get("domains", []):
            iid = "domain:" + item; node(iid, item, "domain", "Extracted domain indicator")
            edges.append({"from": eid, "to": iid, "label": "IOC"})
        for item in report.get("attack_mapping", []):
            tid = "attack:" + item.get("id", "unknown")
            node(tid, item.get("id", "ATT&CK") + "\\n" + item.get("name", "Technique"),
                 "attack", "Heuristic ATT&CK mapping; analyst validation required")
            edges.append({"from": eid, "to": tid, "label": "possible technique"})
        for match in report.get("yara_matches", []):
            if match.get("rule"):
                mid = "yara:" + match["rule"]; node(mid, match["rule"], "yara", "YARA rule match")
                edges.append({"from": eid, "to": mid, "label": "YARA match"})
    return nodes, edges


AUTH_CSS = """<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 15% 20%,#173f78 0,transparent 32%),radial-gradient(circle at 85% 80%,#542b82 0,transparent 35%),linear-gradient(135deg,#071326,#101b35 55%,#080f20);font-family:Inter,Segoe UI,Arial;color:#edf5ff}
.auth{width:min(440px,100%);padding:34px;border:1px solid #45628a88;border-radius:24px;background:#101d33eF;box-shadow:0 25px 80px #0008;backdrop-filter:blur(14px)}.logo{width:54px;height:54px;border-radius:16px;display:grid;place-items:center;background:linear-gradient(135deg,#16d6c2,#477bff);font-size:26px;box-shadow:0 8px 25px #167fbd66}.eyebrow{color:#63e5d5;font-size:12px;letter-spacing:2px;font-weight:700;margin-top:20px}h1{font-size:29px;margin:8px 0}.sub{color:#a9bdd8;line-height:1.5;margin:0 0 24px}.field{display:block;margin:15px 0 6px;color:#d8e7ff;font-size:13px}.auth input{width:100%;padding:14px 15px;border-radius:11px;border:1px solid #3b5276;background:#0a1427;color:white;outline:none}.auth input:focus{border-color:#43d8d0;box-shadow:0 0 0 3px #43d8d022}.primary{width:100%;padding:14px;margin-top:20px;border:0;border-radius:11px;color:#06152a;font-weight:800;background:linear-gradient(100deg,#42e2ce,#69a2ff);cursor:pointer}.links{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:19px}.auth a{color:#70d9f3;text-decoration:none;font-size:13px}.msg{padding:11px;border-radius:9px;background:#293c5b;color:#d9ebff;margin:10px 0;font-size:13px}.hint{font-size:12px;color:#90a8c8;margin-top:16px}
</style>"""
def auth_page(title, subtitle, fields, button, links="", note=""):
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CyberTrace | {title}</title>{AUTH_CSS}</head><body><section class="auth"><div class="logo">⌁</div><div class="eyebrow">CYBERTRACE · DIGITAL FORENSICS</div><h1>{title}</h1><p class="sub">{subtitle}</p>{{% with messages=get_flashed_messages() %}}{{% for m in messages %}}<div class="msg">{{{{m}}}}</div>{{% endfor %}}{{% endwith %}}<form method="post">{fields}<button class="primary" type="submit">{button}</button></form><div class="links">{links}</div><div class="hint">{note}</div></section></body></html>"""

REGISTER_HTML = auth_page("Create your account", "Start your secure digital evidence workspace.", '<label class="field">Username</label><input name="username" minlength="3" maxlength="30" required placeholder="Choose a username"><label class="field">Email address</label><input type="email" name="email" required placeholder="you@example.com"><label class="field">Password</label><input type="password" name="password" minlength="12" required placeholder="At least 12 characters">', "Create account", '<a href="/login">Already registered? Sign in</a>', "Use a unique password of at least 12 characters.")
LOGIN_HTML = auth_page("Welcome back", "Sign in to continue your investigation workspace.", '<label class="field">Username or email</label><input name="identity" required autocomplete="username" placeholder="Username or email"><label class="field">Password</label><input type="password" name="password" required autocomplete="current-password" placeholder="Your password">', "Sign in", '<a href="/forgot-username">Forgot username?</a><a href="/forgot-password">Forgot password?</a><a href="/register">Create account</a>', "Protected access · CyberTrace IMP-03")
FORGOT_USER_HTML = auth_page("Recover username", "Enter the email address linked to your account. We’ll email your username if it exists.", '<label class="field">Registered email</label><input type="email" name="email" required placeholder="you@example.com">', "Send username", '<a href="/login">Back to login</a>')
FORGOT_PASS_HTML = auth_page("Reset password", "Enter your registered email to receive a secure reset link.", '<label class="field">Registered email</label><input type="email" name="email" required placeholder="you@example.com">', "Send reset link", '<a href="/login">Back to login</a>')
RESET_HTML = auth_page("Choose a new password", "Set a new password for your CyberTrace account.", '<label class="field">New password</label><input type="password" name="password" minlength="12" required placeholder="At least 12 characters"><label class="field">Confirm password</label><input type="password" name="confirm" minlength="12" required placeholder="Re-enter password">', "Update password", '<a href="/login">Back to login</a>')

def send_mail(to, subject, body):
    host=os.getenv("MAIL_SERVER", "smtp.gmail.com"); port=int(os.getenv("MAIL_PORT", "587"))
    sender=os.getenv("MAIL_USERNAME"); password=os.getenv("MAIL_APP_PASSWORD")
    if not sender or not password:
        raise RuntimeError("Email is not configured. Set MAIL_USERNAME and MAIL_APP_PASSWORD.")
    msg=EmailMessage(); msg["Subject"]=subject; msg["From"]=sender; msg["To"]=to; msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls(); server.login(sender, password); server.send_message(msg)

def reset_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="cybertrace-password-reset-v1")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated: return redirect(url_for("home"))
    if request.method == "POST":
        username=request.form.get("username", "").strip().lower()
        email=request.form.get("email", "").strip().lower(); password=request.form.get("password", "")
        if not re.fullmatch(r"[a-z0-9_.-]{3,30}", username):
            flash("Username must be 3–30 characters: letters, numbers, dot, underscore or hyphen."); return redirect(url_for("register"))
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address."); return redirect(url_for("register"))
        if len(password)<12: flash("Password must be at least 12 characters."); return redirect(url_for("register"))
        c=db()
        try:
            c.execute("INSERT INTO users (email,username,password_hash,created) VALUES (?,?,?,?)",(email,username,generate_password_hash(password),now())); c.commit()
            flash("Account created. Please sign in."); return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email or username is already registered."); return redirect(url_for("register"))
        finally: c.close()
    return render_template_string(REGISTER_HTML)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated: return redirect(url_for("home"))
    if request.method == "POST":
        identity=request.form.get("identity", "").strip().lower(); password=request.form.get("password", "")
        c=db(); user=c.execute("SELECT id,email,username,password_hash FROM users WHERE email=? OR username=?",(identity,identity)).fetchone(); c.close()
        if user and check_password_hash(user["password_hash"], password):
            login_user(User(user["id"], user["email"])); return redirect(url_for("home"))
        flash("Invalid username/email or password.")
    return render_template_string(LOGIN_HTML)

@app.route("/forgot-username", methods=["GET", "POST"])
def forgot_username():
    if request.method == "POST":
        email=request.form.get("email", "").strip().lower(); c=db(); user=c.execute("SELECT username FROM users WHERE email=?",(email,)).fetchone(); c.close()
        if user:
            try: send_mail(email,"Your CyberTrace username",f"Your CyberTrace username is: {user['username']}\n\nIf you did not request this, ignore this email.")
            except Exception: app.logger.exception("Username recovery email failed")
        flash("If an account exists for that email, username recovery instructions have been sent.")
        return redirect(url_for("forgot_username"))
    return render_template_string(FORGOT_USER_HTML)

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email=request.form.get("email", "").strip().lower(); c=db(); user=c.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()
        if user:
            token=reset_serializer().dumps({"uid":user["id"],"nonce":secrets.token_urlsafe(16)})
            c.execute("INSERT INTO password_resets (user_id,token_hash,expires,used) VALUES (?,?,?,0)",(user["id"],hashlib.sha256(token.encode()).hexdigest(),(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat())); c.commit()
            reset_url=url_for("reset_password",token=token,_external=True)
            try: send_mail(email,"Reset your CyberTrace password",f"Use this link within 30 minutes to reset your password:\n{reset_url}\n\nIf you did not request this, ignore this email.")
            except Exception: app.logger.exception("Password reset email failed")
        c.close(); flash("If an account exists for that email, a password reset link has been sent.")
        return redirect(url_for("forgot_password"))
    return render_template_string(FORGOT_PASS_HTML)

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try: payload=reset_serializer().loads(token,max_age=1800)
    except (BadSignature,SignatureExpired): return "This reset link is invalid or expired.",400
    token_hash=hashlib.sha256(token.encode()).hexdigest(); c=db()
    record=c.execute("SELECT id,user_id FROM password_resets WHERE token_hash=? AND used=0",(token_hash,)).fetchone()
    if not record: c.close(); return "This reset link has already been used or is invalid.",400
    if request.method == "POST":
        password=request.form.get("password", ""); confirm=request.form.get("confirm", "")
        if len(password)<12 or password!=confirm:
            flash("Passwords must match and contain at least 12 characters."); c.close(); return render_template_string(RESET_HTML)
        c.execute("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(password),record["user_id"]))
        c.execute("UPDATE password_resets SET used=1 WHERE user_id=?",(record["user_id"],)); c.commit(); c.close()
        flash("Password updated. Please sign in."); return redirect(url_for("login"))
    c.close(); return render_template_string(RESET_HTML)

@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.get("/")
@login_required
def home():
    return render_template("index.html", email=current_user.email)

def owned_evidence(c, eid):
    row = c.execute("SELECT * FROM evidence WHERE id=? AND owner_id=?", (eid, int(current_user.get_id()))).fetchone()
    if row is None:
        abort(404)
    return row

@app.post("/api/evidence")
@login_required
def upload_evidence():
    f = request.files.get("file")
    if not f or not f.filename: return jsonify(error="Select a file"), 400
    filename = secure_filename(f.filename)
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED: return jsonify(error="Unsupported file extension"), 400
    eid = str(uuid.uuid4())
    target = EVIDENCE / f"{eid}_{filename}"
    f.save(target)
    sha = file_hash(target)
    c = db()
    c.execute("INSERT INTO evidence (id,filename,path,sha256,created,size,owner_id) VALUES(?,?,?,?,?,?,?)",
              (eid, filename, str(target.relative_to(ROOT)), sha, now(), target.stat().st_size, int(current_user.get_id())))
    c.commit()
    add_custody(c, eid, "EVIDENCE_REGISTERED", sha, {"filename": filename, "size": target.stat().st_size})
    return jsonify(id=eid, filename=filename, sha256=sha, size=target.stat().st_size)

@app.get("/api/evidence")
@login_required
def list_evidence():
    c = db()
    return jsonify([dict(r) for r in c.execute(
        "SELECT id,filename,sha256,created,size FROM evidence WHERE owner_id=? ORDER BY created DESC", (int(current_user.get_id()),))])

@app.post("/api/analyze/<eid>")
@login_required
def analyze_evidence(eid):
    c = db()
    row = owned_evidence(c, eid)
    path = ROOT / row["path"]
    ext = path.suffix.lower()
    report = {"evidence_id": eid, "filename": row["filename"], "sha256": file_hash(path),
              "analysis_time": now(), "network": {"flows": []}, "iocs": {"ipv4": [], "domains": [], "sha256": []},
              "artifacts": [], "notes": []}
    if ext in {".pcap", ".pcapng"}:
        report["network"] = analyze_pcap(path)
        report["iocs"] = report["network"].get("iocs", report["iocs"])
        report["artifacts"] = report["network"].get("flows", [])
    elif ext in {".raw", ".mem", ".dmp", ".lime"}:
        report["memory"] = volatility_analysis(path)
        raw = json.dumps(report["memory"])
        report["iocs"] = extract_iocs(raw)
        report["timeline"] = [{"timestamp": now(), "event": "Memory analysis executed",
                               "source": row["filename"], "details": "Volatility plugin output captured"}]
    elif ext in {".log", ".txt"}:
        text = path.read_text(errors="replace")[:5_000_000]
        report["iocs"] = extract_iocs(text)
        report["sigma_findings"] = sigma_triage(text)
        report["artifacts"] = [{"line": i+1, "text": line[:500]} for i, line in enumerate(text.splitlines())
                               if any(k in line.lower() for k in ("failed", "denied", "error", "powershell", "malware", "login"))][:1000]
        report["timeline"] = [{"timestamp": now(), "event": "Log triage", "source": row["filename"],
                               "details": f"{len(report['artifacts'])} keyword-relevant lines"}]
    elif ext == ".evtx":
        try:
            from Evtx.Evtx import Evtx
            events = []
            with Evtx(str(path)) as log:
                for record in log.records():
                    if len(events) >= 5000: break
                    events.append({"record_id": record.record_id(), "timestamp": str(record.timestamp()),
                                   "xml": record.xml()[:4000]})
            report["evtx_events"] = events
            report["timeline"] = [{"timestamp": e["timestamp"], "event": "Windows Event", "source": row["filename"],
                                   "details": f"Event record {e['record_id']}"} for e in events]
            report["iocs"] = extract_iocs(json.dumps(events))
        except Exception as e:
            report["notes"].append("EVTX parser unavailable or failed: " + str(e))
    report["yara_matches"] = yara_scan(path)
    joined = json.dumps(report).lower()
    report["attack_mapping"] = []
    if "powershell" in joined: report["attack_mapping"].append({"id": "T1059.001", "name": "PowerShell (heuristic)"})
    if "failed" in joined or "login" in joined: report["attack_mapping"].append({"id": "T1110", "name": "Brute Force (heuristic)"})
    report["threat_intel"] = correlate_threat_intel(report["iocs"])
    report_path = REPORTS / f"{eid}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    add_custody(c, eid, "ANALYSIS_COMPLETED", report["sha256"], {"report": report_path.name})
    return jsonify(report)

def correlate_threat_intel(iocs):
    result = {"matches": [], "sources": [], "note": "External feeds require API credentials/configuration."}
    key = os.getenv("OTX_API_KEY")
    if key:
        try:
            import requests
            headers = {"X-OTX-API-KEY": key}
            for ip in iocs.get("ipv4", [])[:30]:
                r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                                 headers=headers, timeout=12)
                if r.ok:
                    j = r.json()
                    if j.get("pulse_info", {}).get("count", 0):
                        result["matches"].append({"type": "ipv4", "indicator": ip,
                                                  "pulse_count": j["pulse_info"]["count"], "source": "AlienVault OTX"})
            result["sources"].append("AlienVault OTX")
        except Exception as e:
            result["note"] = "OTX query error: " + str(e)
    # TAXII configuration is detected here; ingestion is an explicit optional operation.
    if os.getenv("TAXII_DISCOVERY_URL"):
        result["taxii_configured"] = True
    return result

@app.post("/api/threat-intel/taxii-sync")
@login_required
def taxii_sync():
    url, collection_id = os.getenv("TAXII_DISCOVERY_URL"), os.getenv("TAXII_COLLECTION_ID")
    if not (url and collection_id):
        return jsonify(error="Set TAXII_DISCOVERY_URL and TAXII_COLLECTION_ID in environment"), 400
    try:
        from taxii2client.v21 import Server
        verify = os.getenv("TAXII_VERIFY_TLS", "true").lower() == "true"
        server = Server(url, user=os.getenv("TAXII_USERNAME"), password=os.getenv("TAXII_PASSWORD"), verify=verify)
        collections = [c for api in server.api_roots for c in api.collections]
        collection = next((c for c in collections if c.id == collection_id), None)
        if not collection: return jsonify(error="Configured TAXII collection not found"), 404
        bundle = collection.get_objects()
        dest = DATA / "taxii_latest.json"
        dest.write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")
        return jsonify(success=True, object_count=len(bundle.get("objects", [])), saved=str(dest.relative_to(ROOT)))
    except Exception as e:
        return jsonify(error="TAXII sync failed: " + str(e)), 500

@app.get("/api/graph")
@login_required
def graph_api():
    nodes, edges = build_graph()
    neo = neo4j_write(nodes, edges)
    return jsonify(nodes=nodes, edges=edges, summary={"nodes": len(nodes), "edges": len(edges)},
                   neo4j=neo,
                   notice="Threat/ATT&CK relationships are evidence-derived. ATT&CK mappings are heuristic and require analyst validation.")

@app.get("/api/custody/verify")
@login_required
def custody_api():
    return jsonify(verify_custody())

@app.get("/api/custody")
@login_required
def custody_records():
    c = db()
    return jsonify([dict(r) for r in c.execute("SELECT custody.* FROM custody JOIN evidence ON evidence.id=custody.evidence_id WHERE evidence.owner_id=? ORDER BY custody.seq", (int(current_user.get_id()),))])

@app.post("/api/package/<eid>")
@login_required
def package_evidence(eid):
    c = db()
    row = owned_evidence(c, eid)
    evidence_path = ROOT / row["path"]
    report_path = REPORTS / f"{eid}.json"
    manifest = {"package_id": str(uuid.uuid4()), "created": now(), "evidence_id": eid,
                "filename": row["filename"], "sha256": file_hash(evidence_path),
                "report_included": report_path.exists(), "signature_algorithm": "Ed25519"}
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    signature = signing_key().sign(hashlib.sha256(canonical).hexdigest().encode()).hex()
    dest = PACKAGES / f"CyberTrace_Evidence_{eid}.zip"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(evidence_path, f"evidence/{row['filename']}")
        if report_path.exists(): z.write(report_path, "analysis/report.json")
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
        z.writestr("manifest.sha256", hashlib.sha256(canonical).hexdigest())
        z.writestr("manifest.ed25519", signature)
        z.writestr("custody_verification.json", json.dumps(verify_custody(), indent=2))
        pub = signing_key().public_key().public_bytes(serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
        z.writestr("public_key.pem", pub)
    add_custody(c, eid, "SIGNED_EVIDENCE_PACKAGE_CREATED", manifest["sha256"], {"package": dest.name})
    return send_file(dest, as_attachment=True, download_name=dest.name)

@app.get("/api/report/<eid>")
@login_required
def download_report(eid):
    p = REPORTS / f"{eid}.json"
    if not p.exists(): abort(404)
    return send_file(p, as_attachment=True, download_name=f"CyberTrace_Report_{eid}.json")

@app.get("/api/stix/<eid>")
@login_required
def stix_export(eid):
    c = db()
    row = owned_evidence(c, eid)
    try:
        from stix2 import Bundle, Identity, Note, Indicator
        ident = Identity(name="CyberTrace", identity_class="system")
        objects = [ident, Note(content=f"Evidence {row['filename']} SHA-256 {row['sha256']}",
                               created_by_ref=ident.id)]
        rp = REPORTS / f"{eid}.json"
        if rp.exists():
            rep = json.loads(rp.read_text(encoding="utf-8"))
            for ip in rep.get("iocs", {}).get("ipv4", [])[:50]:
                objects.append(Indicator(name=f"Observed IPv4 {ip}",
                    pattern=f"[ipv4-addr:value = '{ip}']", pattern_type="stix", created_by_ref=ident.id))
        bundle = Bundle(objects=objects)
        return app.response_class(bundle.serialize(pretty=True), mimetype="application/stix+json")
    except Exception as e:
        return jsonify(error="STIX export failed: " + str(e)), 500

if __name__ == "__main__":
    db()
    app.run(host="127.0.0.1", port=5000, debug=False)
