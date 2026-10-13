# Global Honeypot Threat Map

Decentralized Dockerized SSH honeypots (Cowrie) on AWS Fargate in two regions, a serverless pipeline
(S3 → Lambda → **DynamoDB** → enrichment), unsupervised ML that groups attackers into **botnets**, and a
React + Mapbox 3D globe showing attacks live.

> **Presenting without AWS?** Run `start-demo.bat` (Windows) or `./start-demo.sh`. The whole pipeline runs
> locally on simulated traffic. The only key needed is a free Mapbox token. See **[DEMO.md](DEMO.md)**.
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
 React + Mapbox dashboard ◄── poll ── HTTP API  GET /events ◄── read Lambda ◄──┘

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
| `ml/` | Offline CLI over exported events (`cluster_events.py`) |
| `demo/` | **Local demo backend** (`server.py`) + attack simulator. No AWS, stdlib only |
| `frontend/` | React + Vite + Mapbox GL dashboard |
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

## Project status

| Track | Status |
|------|--------|
| Honeypot | ✅ Cowrie image (fixed for upstream's distroless base), S3 log shipper, Fargate Spot service + SG template |
| Data plane | ✅ SAM: S3 ingest (batch writes), DynamoDB + timeline GSI, enrich (loop-safe), scheduled clustering, `GET /events` |
| ML | ✅ Behavioural DBSCAN shared by Lambda, CLI and demo; tactic tagging in UI |
| Dashboard | ✅ Globe with great-circle arcs, attacker dots + popups, sensors, KPIs, botnet filter, live feed, AWS/demo/snapshot modes |
| Demo | ✅ Local backend (simulated history + live traffic + real Cowrie tailing), offline snapshot, one-click start scripts |
| Tests / CI | ✅ Unit tests, Docker build, dashboard build, ML CLI in GitHub Actions |
| Not done (production hardening) | Auth on the read API, alarms/DLQ, WebSockets instead of polling, NLB to expose port 22 |

## Secrets

| Secret | Needed for | Where it goes |
|--------|-----------|---------------|
| **Mapbox public token** | the globe (demo and AWS) | `frontend/.env` → `VITE_MAPBOX_TOKEN` (git-ignored) |
| IPinfo token | geo for real traffic on AWS | `sam deploy --parameter-overrides IpinfoToken=…` |
| AbuseIPDB key | reputation on AWS | `sam deploy --parameter-overrides AbuseIpdbKey=…` |

Never commit `.env`. Only `frontend/.env.example` (with empty keys) is tracked.

## Tests

```bash
python -m unittest discover -s tests -v
cd frontend && npm run build
```
