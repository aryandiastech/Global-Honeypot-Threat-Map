# Infrastructure

| Subfolder | Description |
|-----------|-------------|
| `sam/` | Serverless Application Model — S3 raw logs, ingest Lambda, DynamoDB events table. See `sam/README.md`. |
| `ecs/` | Sample Fargate task definition and notes for running Cowrie behind ECS. See `ecs/README.md`. |
| `iam/` | Sample IAM policy for ECS task role (S3 raw log uploads). See `iam/README.md`. |

Deploy stacks **per AWS region** when you run honeypots in `ap-south-1` and `us-east-1` (same template, different `sam deploy --region`).
