import os, re, json, csv, io, uuid, hashlib, sqlite3, zipfile, shutil, subprocess, ipaddress
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, send_file, abort
from werkzeug.utils import secure_filename
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
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "512")) * 1024 * 1024

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS evidence(
        id TEXT PRIMARY KEY, filename TEXT, path TEXT, sha256 TEXT, created TEXT, size INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS custody(
        seq INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id TEXT, event TEXT, timestamp TEXT,
        prev_hash TEXT, record_hash TEXT, signature TEXT, details TEXT)""")
    c.commit()
    return c

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
    rows = c.execute("SELECT * FROM custody ORDER BY seq").fetchall()
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
    rows = c.execute("SELECT id,filename,sha256,size FROM evidence ORDER BY created").fetchall()
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

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/evidence")
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
    c.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?)",
              (eid, filename, str(target.relative_to(ROOT)), sha, now(), target.stat().st_size))
    c.commit()
    add_custody(c, eid, "EVIDENCE_REGISTERED", sha, {"filename": filename, "size": target.stat().st_size})
    return jsonify(id=eid, filename=filename, sha256=sha, size=target.stat().st_size)

@app.get("/api/evidence")
def list_evidence():
    c = db()
    return jsonify([dict(r) for r in c.execute(
        "SELECT id,filename,sha256,created,size FROM evidence ORDER BY created DESC")])

@app.post("/api/analyze/<eid>")
def analyze_evidence(eid):
    c = db()
    row = c.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    if not row: abort(404)
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
            queried = 0
            for ip in iocs.get("ipv4", []):
                try:
                    # Do not send RFC1918, loopback, link-local, multicast, or reserved addresses to OTX.
                    if not ipaddress.ip_address(ip).is_global:
                        continue
                except ValueError:
                    continue
                if queried >= 15:
                    break
                queried += 1
                r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                                 headers=headers, timeout=12)
                if r.ok:
                    j = r.json()
                    pulse_count = j.get("pulse_info", {}).get("count", 0)
                    if pulse_count:
                        result["matches"].append({"type": "ipv4", "indicator": ip,
                                                  "pulse_count": pulse_count, "source": "AlienVault OTX"})
            result["sources"].append("AlienVault OTX")
        except Exception as e:
            result["note"] = "OTX query error: " + str(e)
    # TAXII configuration is detected here; ingestion is an explicit optional operation.
    if os.getenv("TAXII_DISCOVERY_URL"):
        result["taxii_configured"] = True
    return result

@app.post("/api/threat-intel/taxii-sync")
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
def graph_api():
    nodes, edges = build_graph()
    neo = neo4j_write(nodes, edges)
    return jsonify(nodes=nodes, edges=edges, summary={"nodes": len(nodes), "edges": len(edges)},
                   neo4j=neo,
                   notice="Threat/ATT&CK relationships are evidence-derived. ATT&CK mappings are heuristic and require analyst validation.")

@app.get("/api/custody/verify")
def custody_api():
    return jsonify(verify_custody())

@app.get("/api/custody")
def custody_records():
    c = db()
    return jsonify([dict(r) for r in c.execute("SELECT * FROM custody ORDER BY seq")])

@app.post("/api/package/<eid>")
def package_evidence(eid):
    c = db()
    row = c.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    if not row: abort(404)
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
def download_report(eid):
    p = REPORTS / f"{eid}.json"
    if not p.exists(): abort(404)
    return send_file(p, as_attachment=True, download_name=f"CyberTrace_Report_{eid}.json")

@app.get("/api/stix/<eid>")
def stix_export(eid):
    c = db()
    row = c.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    if not row: abort(404)
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
