# Global Honeypot Threat Map (Pinnacle Project)

This project deploys a **fleet of decentralized honeypots** across multiple AWS regions, captures real-time attack telemetry, processes it with a serverless pipeline, applies **unsupervised ML** to group similar attacks into “botnets”, and visualizes threats on a **live 3D map dashboard**.

## Goals

- Deploy Dockerized honeypots (initially **Cowrie SSH**) across regions.
- Capture attacker events and store them durably.
- Provide a queryable API for “recent events” and later “clusters/reputation”.
- Visualize global attacks (origins → AWS nodes) with live arcs.
- Maintain a **14-page GitHub Wiki** as the primary report.

## Regions

Initial target regions (config: `config/deployment-regions.json`):

- `ap-south-1` (Mumbai)
- `us-east-1` (N. Virginia)

## Current repo components (high-level)

- **Honeypot**: `honeypots/cowrie/` (Dockerfile + compose)
- **Ingest**: S3 ObjectCreated → Lambda → DynamoDB (`infra/sam/`, `pipeline/ingest_lambda/`)
- **Read API**: HTTP `GET /events` (`pipeline/read_api/`)
- **Dashboard**: React + Vite + optional Mapbox (`frontend/`)
- **ML stub**: offline DBSCAN (`ml/`)

## Key links (implementation)

- SAM deploy instructions: `infra/sam/README.md`
- Upload logs to S3: `scripts/cowrie_log_to_s3.py`
- Dashboard env vars: `frontend/.env.example`

