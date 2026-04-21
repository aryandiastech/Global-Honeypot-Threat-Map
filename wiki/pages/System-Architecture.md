# System Architecture

## End-to-end flow

```mermaid
flowchart LR
  A[Attackers on Internet] -->|SSH brute force / scans| H1[Cowrie on ECS Fargate<br/>ap-south-1]
  A --> H2[Cowrie on ECS Fargate<br/>us-east-1]

  H1 -->|batch logs| S3a[(S3 Raw Log Bucket<br/>per region)]
  H2 -->|batch logs| S3b[(S3 Raw Log Bucket<br/>per region)]

  S3a -->|ObjectCreated| L1[Ingest Lambda]
  S3b -->|ObjectCreated| L2[Ingest Lambda]

  L1 --> D[(DynamoDB Events Table)]
  L2 --> D

  D --> R[Read API Lambda]
  R --> API[HTTP API Gateway<br/>GET /events]
  API --> UI[React Dashboard]

  D --> ML[ML Job / Batch Processing]
  ML --> D2[(Clusters / Reputation Store)]
  D2 --> UI
```

## Why this architecture

- **Fargate**: runs honeypots as containers with minimal server maintenance.
- **S3**: cheap, durable landing zone for raw logs and reprocessing.
- **Lambda**: event-driven parsing/normalization; scales with data.
- **DynamoDB**: fast reads for dashboard and simple scaling for event ingestion.
- **HTTP API**: lightweight public endpoint to power the dashboard feed.
- **ML batch**: unsupervised clustering can run periodically without impacting ingest.

## References

- AWS: S3 triggers Lambda (`Process Amazon S3 event notifications with Lambda`) `https://docs.aws.amazon.com/lambda/latest/dg/with-s3.html`
- AWS SAM policy templates (simplifies IAM in templates) `https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-policy-templates.html`

