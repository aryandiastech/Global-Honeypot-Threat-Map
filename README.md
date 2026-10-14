# Global Honeypot Threat Map

Decentralized Dockerized SSH honeypots (Cowrie) on AWS Fargate in two regions, a serverless pipeline
(S3 → Lambda → **DynamoDB** → enrichment), unsupervised ML that groups attackers into **botnets**, and a
React 3D globe (MapLibre + OpenFreeMap, or Mapbox when a token is set) showing attacks live.

> **Presenting without AWS?** Clone, then run `start-demo.bat` (Windows) or `./start-demo.sh`. The whole pipeline
> runs locally on simulated traffic. **No accounts or API keys needed.** See **[DEMO.md](DEMO.md)**.
>
> **Deploying for real?** See **[DEPLOY-AWS.md](DEPLOY-AWS.md)**. It also covers recovering the original AWS account.

## Architecture

```
 Attackers ──SSH:2222──► Cowrie (Fargate Spot, ap-south-1 + us-east-1)
                           │ entrypoint.py + log_shipper.py (every 60 s)
                           ▼
                     S3 raw-log bucket ──ObjectCreated──► ingest Lambda ──► DynamoDB events
                                                                               │ stream (INSERT)
                                                         enrich Lambda ◄───────┘  IPinfo geo + AbuseIPDB score
                                                         cluster Lambda (every 30 min, DBSCAN) → cluster_id
                                                                               │
 React + MapLibre dashboard ◄── poll ── HTTP API  GET /events ◄── read Lambda ◄──┘

 Local demo:  simulator / real cowrie.json ──► demo/server.py (same ingest + clustering code) ──► same GET /events
```

## Repository layout

| Path | Purpose |
|------|---------|
| `honeypots/cowrie/` | Cowrie SSH honeypot image (distroless-safe Python entrypoint + S3 log shipper), `docker compose` |
| `pipeline/ingest_lambda/` | S3-triggered Lambda: Cowrie JSONL → DynamoDB (`normalize_cowrie_record` is shared with the demo) |
| `pipeline/enrich_lambda/` | DynamoDB Stream consumer: IPinfo geo + AbuseIPDB reputation (INSERT-only, cached per IP) |
| `pipeline/cluster_lambda/` | Scheduled botnet clustering; `botnet_clustering.py` is the single ML implementation |
| `pipeline/read_api/` | HTTP API Lambda: `GET /events` |
| `ml/` | Attack-type AI/ML (`attack_analysis.py`: Naive Bayes + k-means + PCA) and the offline botnet CLI (`cluster_events.py`) |
| `demo/` | **Local demo backend** (`server.py`) + attack simulator. No AWS, stdlib only |
| `frontend/` | React + Vite dashboard: MapLibre globe by default, Mapbox GL when a token is set |
| `infra/sam/` | SAM template: bucket, table + GSIs, 4 Lambdas, HTTP API |
| `infra/ecs/` | CloudFormation: ECS cluster, task, security group, Fargate Spot service |
| `tests/` | Stdlib unit tests (`python -m unittest discover -s tests`) |
| `wiki/` | 14-page project wiki (methodology, design, evaluation) |

## ML: how botnets are found

Each attacking IP becomes a behavioural profile, and IPs are compared with a weighted distance:

| Component | Weight | Signal |
|-----------|--------|--------|
| Credential dictionary | 0.40 | Jaccard distance between the `user:password` sets tried |
| Payload commands | 0.25 | Jaccard distance between commands run after login |
| SSH client | 0.15 | Jaccard distance between client version strings |
| Behaviour ratios | 0.20 | login / command / success ratios |

DBSCAN (`eps=0.25`, `min_samples=3`, precomputed metric) finds dense groups and leaves one-off scanners as noise.
On the simulator's ground truth it recovers all 6 botnets with 100% purity and puts all lone scanners in noise,
stable for `eps` from 0.20 to 0.30 (`tests/test_pipeline.py` checks this). Geography is deliberately not a feature:
real botnets are spread worldwide, and the map shows that.

The implementation is pure Python (scikit-learn used if installed), so the Lambda ships without numpy/scipy.

## ML: what kind of attack was it?

`ml/attack_analysis.py` works per **attack session** (botnet clustering works per IP):

1. **Features**: behaviour tokens (login attempts, success, commands, download) plus tokens from every shell command.
2. **Classification**: multinomial **Naive Bayes** trained on a labelled corpus of 50 known honeypot attack
   patterns, covering 7 types mapped to **MITRE ATT&CK**. It reports confidence and the features behind each
   decision. Leave-one-out accuracy is 92%, and it agrees 100% with the simulator's ground truth.
3. **Clustering**: spherical **k-means** on TF-IDF vectors, k chosen by silhouette (about 0.94 on demo data),
   plus a **PCA** projection for the scatter plot. Clusters and classifier labels agree on about 98% of attacks.

The dashboard's **Database · AI/ML** view shows all of it, and `POST /analysis/scan` runs it on the backend.

## Project status

| Track | Status |
|------|--------|
| Honeypot | ✅ Cowrie image (fixed for upstream's distroless base), S3 log shipper, Fargate Spot service + SG template |
| Data plane | ✅ SAM: S3 ingest (batch writes), DynamoDB + timeline GSI, enrich (loop-safe), scheduled clustering, `GET /events` |
| ML | ✅ Behavioural DBSCAN shared by Lambda, CLI and demo; tactic tagging in UI |
| Dashboard | ✅ Globe with great-circle arcs, attacker dots + popups, sensors, KPIs, botnet filter, live feed, AWS/demo/snapshot modes |
| Demo | ✅ Local backend (empty start, Start/Stop live attacks every 13–17 s, real Cowrie tailing), attack detail panel, AI/ML threat database, offline snapshot, one-click start scripts |
| Tests / CI | ✅ Unit tests, Docker build, dashboard build, ML CLI in GitHub Actions |
| Not done (production hardening) | Auth on the read API, alarms/DLQ, WebSockets instead of polling, NLB to expose port 22 |

## Secrets

| Secret | Needed for | Where it goes |
|--------|-----------|---------------|
| Mapbox public token *(optional)* | Mapbox globe instead of the free MapLibre one | `frontend/.env` → `VITE_MAPBOX_TOKEN` (git-ignored) |
| IPinfo token | geo for real traffic on AWS | `sam deploy --parameter-overrides IpinfoToken=…` |
| AbuseIPDB key | reputation on AWS | `sam deploy --parameter-overrides AbuseIpdbKey=…` |

Never commit `.env`. Only `frontend/.env.example` (with empty keys) is tracked.

## Tests

```bash
python -m unittest discover -s tests -v
cd frontend && npm run build
```
