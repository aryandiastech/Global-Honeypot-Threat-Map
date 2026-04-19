# Global Honeypot Threat Map

Pinnacle project: decentralized Dockerized honeypots on AWS (Fargate), serverless ingestion (S3 → Lambda → **DynamoDB**), ML clustering for “botnet” grouping and IP reputation, and a React + Mapbox live dashboard.

## Regions (initial)

- `ap-south-1` (Mumbai)
- `us-east-1` (N. Virginia)

Source of truth: `config/deployment-regions.json`.

## Repository layout

| Path | Purpose |
|------|---------|
| `honeypots/cowrie/` | SSH honeypot image (Cowrie), local `docker compose` |
| `config/` | Shared non-secret config (e.g. region list) |
| _(upcoming)_ `infra/`, `pipeline/`, `frontend/`, `ml/` | IaC, Lambda/ingestion, React app, models |

## When you need third-party keys (you will provide later)

| Secret | Needed when |
|--------|-------------|
| **Mapbox access token** | Building and deploying the React map (Mapbox GL). |
| **IP geolocation API** | Enriching attacker source IPs with lat/lon for arcs on the map (typically in Lambda or stream processing). |
| **Threat intel / reputation API** | Computing or augmenting IP reputation scores (engine or batch job). |

Store all secrets in **AWS Secrets Manager** (or SSM Parameter Store) for runtime; never commit them.

## Pre-build verification (run on your machine)

- `git status` — on a feature branch, clean tree before commits.
- `gh auth status` — GitHub CLI logged in.
- `aws sts get-caller-identity` — expected account.
- Docker Desktop **Engine running**, then `docker version` (client **and** server).
- From `honeypots/cowrie/`: `docker compose up --build`.

## Honeypot quick start

See `honeypots/cowrie/README.md`.
