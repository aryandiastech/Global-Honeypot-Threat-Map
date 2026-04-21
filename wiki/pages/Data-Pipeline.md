# Data Pipeline (S3 → Lambda → DynamoDB)

## Design

1. Honeypot produces logs (batch files).
2. Logs are uploaded to **S3 raw bucket**.
3. S3 sends an **ObjectCreated** event to **Ingest Lambda**.
4. Lambda reads the object, parses each JSON line, and writes normalized items to DynamoDB.

This design allows reprocessing (from S3) and keeps the “hot path” fast for the dashboard.

## Why S3 events + Lambda

Amazon S3 can send an event to a Lambda function when an object is created/deleted; the function is invoked asynchronously.

Reference: AWS Lambda docs `https://docs.aws.amazon.com/lambda/latest/dg/with-s3.html`

## Ingest implementation (repo)

- SAM template: `infra/sam/template.yaml`
- Lambda handler: `pipeline/ingest_lambda/handler.py`

### Normalized fields (current)

- `event_id` (sha256(bucket, key, line))
- `received_at` (ingest time)
- `timeline_pk = "GLOBAL"` (for recent-events API)
- optional `src_ip`, `cowrie_eventid`, `sensor_timestamp`
- `s3_bucket`, `s3_key`, `line_index`

## Shipping logs to S3 (current approach)

We provide a helper script:

- `scripts/cowrie_log_to_s3.py`

This is enough for demos and for wiring an ECS sidecar/scheduled job later.

