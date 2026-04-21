# Data Pipeline Overview

The data pipeline guarantees that the raw interactions in our decentralized honeypots are structurally normalized, durably stored, and made available for both the API Frontend and the Machine Learning clustering steps.

## Pipeline Flow (Ingestion)

1. **Honeypot (Log Shipper)**: A custom `log_shipper.py` process running inside our Cowrie ECS Task batches `cowrie.json` outputs and uses the `boto3` library to upload JSONLines to the Raw Log S3 Bucket.
2. **Raw Bucket Trigger**: S3 `ObjectCreated` event triggers our AWS Lambda `ingest_lambda`. 
3. **Normalization**: The Ingest Lambda unzips/parses the JSONLines, grabs critical fields, and inserts them durably into a DynamoDB `EventsTable`.
4. **Geo/Reputation Enrichment**: A secondary AWS Lambda `enrich_lambda` listens to DynamoDB streams. It reaches out to **IPinfo** for geographic coordinates and **AbuseIPDB** for IP reputation, saving these enriched fields back to DynamoDB.

## Why S3 -> Lambda -> DynamoDB?
- Highly scalable and completely serverless, removing the need for an always-on log parsing node.
- DynamoDB enables millisecond query speeds for the `read_api` used by the Frontend visualization map.
- The use of DynamoDB Streams for enrichment creates a completely non-blocking, asynchronous workflow that doesn't slow down initial data persistence.
