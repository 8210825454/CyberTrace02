# CyberTrace – IMP-03 Complete Hackathon Prototype

## Official challenge alignment
- Automated volatile memory dump analysis: Volatility 3 integration (`windows.info`, `windows.pslist`, `windows.netscan`, `windows.cmdline`) and a basic event timeline.
- Cryptographically verifiable evidence: SHA-256, Ed25519 signed append-only custody records, hash-chain verification, and signed manifest evidence ZIP.
- Threat intelligence and graph visualization: IOC extraction, optional AlienVault OTX API lookups, configurable TAXII collection sync, STIX 2.1 export, interactive vis-network graph, and optional Neo4j persistence.
- Stack: Python, Volatility, YARA, Sigma rule files, Rust streaming SHA-256 utility, Neo4j, STIX/TAXII.

## Windows 11 setup
1. Install Python 3.11+ and (for Rust tool) Rust via rustup.
2. Extract this project.
3. Open PowerShell in the folder containing `app.py`.
4. Run:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\run_windows.ps1
   ```
5. Open http://127.0.0.1:5000

## YARA
YARA is optional. Try:
` .\.venv\Scripts\python.exe -m pip install yara-python `
If installation fails on your Python version, use a supported Python build/wheel or install YARA separately. The app reports YARA as unavailable rather than crashing.

## Rust parser
In a second PowerShell:
```powershell
cd rust_parser
cargo build --release
.\target\release\cybertrace-parser.exe C:\path\to\authorized-evidence.pcap
```

## Optional Neo4j
Set `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, and optional `NEO4J_DATABASE` in your environment. The app will sync graph nodes/relationships when configured. Without Neo4j, the graph still renders from local SQLite/report data.

## Optional OTX
Set `OTX_API_KEY` before launching the app. The analysis module queries OTX for extracted IPv4 indicators.

## Optional TAXII
Set `TAXII_DISCOVERY_URL`, `TAXII_COLLECTION_ID`, and credentials if needed. Use the dashboard's TAXII sync action.

## Important accuracy and safety notes
- This is a hackathon prototype, not a production forensic suite or certified evidence system.
- Volatility output depends on genuine compatible memory images and symbols; unsupported images may fail.
- Timeline events are currently basic/derived. A full forensic timeline requires parsing plugin outputs into normalized timestamped events.
- The included Sigma matcher is a limited keyword/substring triage implementation, not a full Sigma specification engine. Integrate pySigma with a backend for complete Sigma semantics.
- ATT&CK mappings are heuristic and must be validated by an analyst; this does not prove an attack.
- OTX and TAXII require network access and valid feed configuration. No credentials are bundled.
- Evidence packaging signs the manifest and includes the evidence/report and custody status. Protect the private Ed25519 key; do not publish it.
- The local starter has no user authentication, multi-tenant authorization, malware sandbox, or hardened public-upload controls. Do not expose it to the public internet as-is. Use only evidence you are authorized to examine.
