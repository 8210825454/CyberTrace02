# Public demo deployment (Render + GitHub)

## OTX API key (keep it secret)
The application already reads `OTX_API_KEY` from the server environment. It is never needed in browser JavaScript and must not be committed to GitHub or pasted into chat.

### Local Windows test
In the same PowerShell window, before starting CyberTrace:
```powershell
$env:OTX_API_KEY = "PASTE_YOUR_PRIVATE_OTX_KEY_HERE"
.\.venv\Scripts\python.exe app.py
```
Then upload and analyze an authorized PCAP/log containing public IPv4 indicators. OTX is queried during analysis. Private/local IPs are intentionally excluded. Remove the key from that PowerShell session with:
```powershell
Remove-Item Env:OTX_API_KEY
```

## Deploy the public app
1. Create a GitHub repository and upload the project source.
2. Do NOT upload `.env`, `data/`, uploaded evidence, SQLite DB, `.pem` signing keys, or API keys.
3. On Render, choose New > Blueprint and connect the GitHub repository containing `render.yaml`, or create a Web Service manually.
4. Use:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 300`
   - Plan: Free (demo/testing only)
5. In Render > your service > Environment, add `OTX_API_KEY` with your OTX key as its value. Do not place the key in source code. Save and redeploy.
6. When deployment finishes, open the `onrender.com` URL.

## Free hosting limitations
Render free web services sleep after 15 minutes without inbound traffic and can take about a minute to wake. Their filesystem is ephemeral: uploaded evidence, SQLite DB, and generated packages can be lost on spin-down, restart, or redeploy. Free services do not include persistent disks. Treat this as a temporary public demo, not a durable evidence repository.

## Security warning before making uploads public
This hackathon prototype does not yet include full user authentication, per-user authorization, malware sandboxing, secure multi-tenant isolation, durable evidence storage, or robust abuse controls. Do not allow arbitrary strangers to upload real memory dumps, logs, PCAPs, or confidential evidence. For a public demo, use synthetic sample evidence and keep real evidence uploads restricted until authentication, storage isolation, quotas, and sandboxing are added.

## OTX behavior
OTX API lookups occur when evidence is analyzed. The application only sends globally routable IPv4 indicators to OTX and caps the lookup count per analysis. OTX API usage/limits are subject to the provider's terms and account limits.
