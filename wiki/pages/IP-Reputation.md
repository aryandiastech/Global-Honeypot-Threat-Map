# IP Reputation Scoring

## Goal

Provide a simple, explainable score per attacker IP:

- **High score**: repeated attacks, many failures, appears in known bad lists, seen across regions
- **Low score**: one-off noise or benign scans

## Sources of evidence

### 1) Internal signals (available immediately)

- number of events per IP per time window
- number of unique event types (`cowrie_eventid`)
- geographic dispersion (after geo-IP)
- cross-region hits (Mumbai + Virginia)
- cluster membership stability (ML)

### 2) External intel (optional)

- AbuseIPDB / OTX / VirusTotal style APIs
- known ASN reputation feeds

This is where you will need to create a **threat intel API** account/key.

## Scoring model (starter)

An explainable weighted score:

\(score = w_1 \cdot volume + w_2 \cdot diversity + w_3 \cdot crossRegion + w_4 \cdot intel\)

Store:

- `ip_reputation_score` (0–100)
- `ip_reputation_reasons` (top contributing factors)

## Storage

Recommended:

- a separate table keyed by `src_ip` for “current score”
- optional history table for time-series trends

