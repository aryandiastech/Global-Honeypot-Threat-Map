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
| `pipeline/ingest_lambda/` | S3-triggered Lambda: JSONL → DynamoDB |
| `infra/sam/` | AWS SAM template for bucket + Lambda + table |
| `infra/ecs/` | Sample Fargate task definition + notes for Cowrie |
| `.github/workflows/` | CI: Docker build + Python compile for ingest Lambda |
| _(upcoming)_ `frontend/`, `ml/` | React + Mapbox dashboard, clustering / reputation |

## When to create third-party accounts (I will tell you at each step)

| Secret | Create the account / key **right before** we start this work |
|--------|------------------------------------------------------------------|
| **Mapbox access token** | **Frontend milestone** — scaffolding the React app, Mapbox map, and deployment env vars. Until then, not needed. |
| **IP geolocation API** | **Map / enrichment milestone** — when we add lat/lon per `src_ip` (Lambda or stream after ingest). Ingest to DynamoDB works without it. |
| **Threat intel / reputation API** | **Reputation / ML milestone** — when we score IPs or blend external intel into clusters. Clustering on log features can start without it. |

Store all secrets in **AWS Secrets Manager** (or SSM Parameter Store) for runtime; never commit them.

## Git workflow (why you might not see a push every message)

Work lands on **feature branches** and is **pushed after each implemented milestone** (or multi-commit milestone). If a reply is only planning or answering questions, there may be **no new commit** that round. Open PRs on GitHub to review and merge into your main integration branch when ready.

## Pre-build verification (run on your machine)

- `git status` — on a feature branch, clean tree before commits.
- `gh auth status` — GitHub CLI logged in.
- `aws sts get-caller-identity` — expected account.
- Docker Desktop **Engine running**, then `docker version` (client **and** server).
- From `honeypots/cowrie/`: `docker compose up --build`.

## Honeypot quick start

See `honeypots/cowrie/README.md`.
