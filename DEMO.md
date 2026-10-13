# Running & presenting the project (no AWS needed)

This guide is for whoever presents the project. The whole system runs on one laptop:
a local backend replays the AWS data pipeline (same ingest, enrichment and ML code
as the Lambdas) and the React dashboard shows it on a 3D globe.

**No accounts or API keys are needed.** Clone, run one command, present.

---

## 1. Install (once)

| Tool | Why | Get it |
|------|-----|--------|
| **Node.js LTS** (20+) | dashboard | https://nodejs.org/ |
| **Python 3.10+** | demo backend (standard library only, no `pip install` needed) | https://www.python.org/downloads/ — on Windows tick **"Add python.exe to PATH"** |
| Docker Desktop *(optional)* | run a real Cowrie honeypot live | https://www.docker.com/products/docker-desktop/ |

## 2. Get the code

```bash
git clone https://github.com/aryandiastech/Global-Honeypot-Threat-Map.git
cd Global-Honeypot-Threat-Map
```

(or open the folder in VS Code and use its terminal: **Terminal → New Terminal**)

## 3. Start it

**Windows:** double-click **`start-demo.bat`**

**macOS / Linux / Git Bash:**

```bash
./start-demo.sh
```

It installs the dashboard on the first run (about a minute, needs internet), starts the backend on
`http://localhost:8000` and opens the dashboard at **http://localhost:5173**. Stop it with `Ctrl+C`.

The globe uses **MapLibre + OpenFreeMap** (free, no key). The laptop needs internet for the map background;
the stats, botnets and feed work offline.

<details>
<summary>Optional: use the Mapbox globe instead</summary>

1. Sign up at https://account.mapbox.com/auth/signup/ and copy the **Default public token** (`pk.…`) from
   https://account.mapbox.com/access-tokens/.
2. Paste it into `frontend/.env` → `VITE_MAPBOX_TOKEN=pk.…` and restart. The dashboard switches to Mapbox automatically.

</details>

<details>
<summary>Manual start (two terminals)</summary>

```bash
python demo/server.py --live
```

```bash
cd frontend
npm install
npm run dev
```

</details>

## 4. What you'll see

- **KPI bar**: total events, unique attackers, countries, botnets found by the ML, cracked logins, and a 24 h activity sparkline.
- **Globe**: attack arcs from each attacker to the honeypot sensor it hit (Mumbai `ap-south-1` or N. Virginia `us-east-1`). Arc colour = botnet cluster, blue = lone scanner, bright arcs = the last 90 s. Click a dot for IP, location, network and abuse score.
- **Botnet clusters**: DBSCAN groups IPs by *behaviour* (shared password dictionary, shared payload commands, same SSH client), not by location. Each cluster gets a tactic tag (IoT worm, malware dropper, SSH-key backdoor…). **Click a cluster** to isolate it on the map and in the feed.
- **Live attack feed**: new simulated attacks arrive every ~4 s (`--live`), and the dashboard polls every 5 s.
- The **badge** (top right) says where the data comes from: `Local backend · simulated`, `AWS · live`, or `Offline snapshot`.

## 5. Optional: a real honeypot, live on stage

With Docker Desktop running, start a real Cowrie SSH honeypot:

```bash
cd honeypots/cowrie
docker compose up --build
```

Then start the demo with real log tailing:

```powershell
.\start-demo.ps1 -WithCowrie
```

```bash
./start-demo.sh --cowrie
```

Now attack it from another terminal (or a classmate's laptop on the same Wi-Fi, using your IP). Cowrie accepts most passwords for `root` and logs every keystroke:

```bash
ssh -p 2222 root@localhost
```

Within ~2 s your login attempts and commands appear in the feed. Private/LAN IPs are placed at a "Local lab" marker
(change it with `--lab-latlon LAT,LON`).

## 6. Suggested 5-minute presentation flow

1. **Problem** (30 s): internet-facing SSH is attacked within minutes, but raw logs don't show *who is coordinated*.
2. **Architecture** (1 min): Cowrie on Fargate in 2 regions → S3 → ingest Lambda → DynamoDB → enrich Lambda (IPinfo + AbuseIPDB) → scheduled DBSCAN Lambda → HTTP API → React + Mapbox. Show `wiki/pages/System-Architecture.md`.
3. **Live dashboard** (2 min): spin the globe, point out bright new arcs, click a botnet (e.g. *Malware dropper*): its IPs span several countries but run the same `wget … && ./x.sh` payload. That's the ML insight.
4. **Real honeypot** (1 min, optional): `ssh -p 2222 root@localhost`, type `uname -a`, and watch it appear.
5. **Honesty slide** (30 s): the demo uses simulated traffic because the AWS stack is torn down. The code paths are identical, and `DEPLOY-AWS.md` redeploys it to any account in about 15 minutes.

## Data & safety notes

- Simulated attackers use only **reserved documentation IP ranges** (RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24` and RFC 2544 `198.18.0.0/15`), so no real person's IP is ever shown as an attacker.
  Locations, networks and abuse scores are synthetic and marked "(simulated)".
- Data is reproducible (`--seed 1337`). Change the seed for a different dataset, or set `--hours` for the backfill length.
- Optional real enrichment for real Cowrie traffic: set `IPINFO_TOKEN` / `ABUSEIPDB_KEY` environment variables before
  starting the backend, and it reuses the enrich Lambda's lookup code.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Red "Failed to fetch … is the backend running" | Start `python demo/server.py --live`, or clear `VITE_API_URL` in `frontend/.env` to use the offline snapshot |
| Globe is black / no countries | No internet for the map background (OpenFreeMap); data still shows |
| "Map error: … 401" | Only with a Mapbox token: token typo or URL restriction. Clear `VITE_MAPBOX_TOKEN` to use the free map |
| `python` not found on Windows | Reinstall Python with "Add to PATH", or use `py demo/server.py --live` |
| Port 8000 busy | `python demo/server.py --live --port 8010`, and set `VITE_API_URL=http://localhost:8010` |
| `start-demo.ps1` blocked | Use `start-demo.bat`, or `powershell -ExecutionPolicy Bypass -File .\start-demo.ps1` |
