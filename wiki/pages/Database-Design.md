# Database Design (DynamoDB)

## Table: `ghtm-honeypot-events-<stage>`

Primary key:

- Partition key: `event_id` (string)

This makes each ingested JSON line addressable and supports idempotency patterns.

## Indexes

### 1) `timeline-received_at` (recent-events feed)

- HASH: `timeline_pk` (string; constant `"GLOBAL"`)
- RANGE: `received_at` (string ISO8601)

This powers the dashboard “recent events” view via a **Query** (not a scan).

### 2) `src_ip-received_at` (investigate one attacker)

- HASH: `src_ip`
- RANGE: `received_at`

Used later for “attacker detail” views and reputation history.

## Why DynamoDB

- ingestion is write-heavy and bursty
- dashboard needs predictable low-latency reads
- pay-per-request mode fits student/PoC workloads

## Future schema extensions

Add attributes:

- `geo`: `{ lat, lon, country, city, asn }` (from geo-IP enrichment)
- `cluster_id`: integer/label from ML job
- `ip_reputation`: score + explanations

Or store computed outputs in a separate table (recommended once data grows).

