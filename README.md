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
| `pipeline/read_api/` | HTTP API Lambda: recent events (`GET /events`) |
| `infra/sam/` | AWS SAM template for bucket + Lambda + table |
| `infra/ecs/` | Sample Fargate task definition + notes for Cowrie |
| `.github/workflows/` | CI: Docker, Python Lambdas/scripts, ML stub, frontend build |
| `scripts/` | Ops helpers (e.g. upload Cowrie logs to the raw S3 bucket) |
| `infra/iam/` | Sample ECS task-role policy for S3 uploads |
| `frontend/` | React + Vite + Mapbox GL dashboard + read API feed (polling) |
| `ml/` | Offline DBSCAN clustering stub (`cluster_events.py`) |

## Project status (what is left)

This is an honest “class demo vs production” snapshot.

| Track | In repo now | Typical remaining work |
|------|-------------|-------------------------|
| Honeypot | Cowrie Docker + compose + ECS sample task | Multi-region Fargate **services**, steady **log → S3** (sidecar/schedule), hardening |
| Data plane | SAM: S3 ingest, DynamoDB, timeline GSI, HTTP **GET /events** | `sam deploy` in **each** region, alarms, DLQ, backfills |
| Dashboard | Map (optional token), events list, **15s polling** | **Arcs** (needs geo-IP), auth, prod hosting URL, WebSockets if you want |
| ML / intel | **Offline** DBSCAN stub | Richer features, scheduled job, **reputation** + external intel, write-back to Dynamo |
| Docs / submission | README + folder docs | **14-page GitHub Wiki** + evaluation write-up |

**Rough overall:** about **~60–70%** of a strong end-to-end *demo* is in place; the remaining **~30–40%** is mostly **operations** (multi-region fleet, secrets, monitoring), **visual/geo/intel** layers, **ML depth**, and **Wiki/reporting**—not more “empty repo” work.

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
