# Infrastructure

| Subfolder | Description |
|-----------|-------------|
| `sam/` | Serverless Application Model — S3 raw logs, ingest Lambda, DynamoDB events table. See `sam/README.md`. |

Deploy stacks **per AWS region** when you run honeypots in `ap-south-1` and `us-east-1` (same template, different `sam deploy --region`).
