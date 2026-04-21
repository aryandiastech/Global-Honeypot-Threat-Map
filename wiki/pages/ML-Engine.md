# AI/ML Engine (Unsupervised Clustering)

## Problem framing

We observe streams of honeypot events (many IPs, many attempts). We want to group similar attack behaviors into clusters that we interpret as **campaigns** or **botnets**.

This is naturally unsupervised because we do not have ground-truth labels for most attacks.

## Baseline approach

1. Extract features per event or per session/IP window.
2. Run an unsupervised clustering algorithm (DBSCAN or K-Means).
3. Assign a `cluster_id` to events / IPs.

### Why DBSCAN

- no need to choose \(K\) (number of clusters) upfront
- supports irregular cluster shapes
- labels outliers as “noise” (`-1`)

## Current implementation in repo (stub)

`ml/cluster_events.py` runs DBSCAN on a toy 2D feature vector:

- hashed `src_ip` (stable numeric)
- hour-of-day from timestamps

This is intentionally simple for the first milestone; the next iteration should use higher-signal features.

## Feature engineering (next)

- ASN / country (from geo-IP)
- auth attempt patterns (usernames, password entropy)
- command sequence embeddings (if enabled in Cowrie)
- temporal patterns (burstiness, inter-arrival)
- destination region/node (which Fargate task was hit)

