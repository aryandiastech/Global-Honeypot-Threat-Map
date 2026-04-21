# Methodology

This project is implemented in milestones, each producing a runnable, demonstrable artifact.

## Milestone plan

1. **Honeypot container**: build/run Cowrie locally, then push to ECR for Fargate.
2. **Raw log landing zone**: create S3 bucket(s) with secure defaults.
3. **Ingestion**: S3 event triggers Lambda that normalizes JSONL into DynamoDB.
4. **Query API**: HTTP `GET /events` reads “recent events” via DynamoDB GSI.
5. **Dashboard**: React app shows live feed; Mapbox globe enabled with token.
6. **Enrichment**: Geo-IP (lat/lon) + optional threat intel.
7. **ML clustering**: unsupervised grouping + botnet labeling + reputation scoring.
8. **Operations**: multi-region deployment, monitoring, lifecycle, and costs.
9. **Documentation**: wiki pages written alongside implementation.

## Data handling principles

- **Idempotency**: S3 events can be delivered more than once; ingestion should tolerate duplicates.
- **Separation of concerns**:
  - S3 stores **raw** data for reprocessing.
  - DynamoDB stores **normalized** items for fast reads.
  - ML outputs should be stored separately (or as additional attributes) to avoid coupling.
- **Least privilege**: ECS task role only gets what it needs (e.g., `s3:PutObject` to the raw bucket).

## When external APIs are required

- **Mapbox**: only when you enable the 3D globe in production.
- **Geo-IP**: only when you add lat/lon enrichment for arcs.
- **Threat intel**: only when you compute or augment reputation scores.

