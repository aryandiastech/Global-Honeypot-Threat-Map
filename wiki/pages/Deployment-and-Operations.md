# Deployment & Operations (Multi-region)

## Multi-region model

We deploy the **same logical stack** in multiple AWS regions:

- Honeypot service(s) in each region (ECS Fargate)
- Raw log bucket in each region (S3)
- Ingest Lambda in each region
- DynamoDB table in each region
- Read API in each region (optional: one “global” API that aggregates later)

Initial regions:

- `ap-south-1`
- `us-east-1`

## Deployment steps (high level)

1. Deploy SAM stack in region A:
   - `sam build`
   - `sam deploy --guided --region ap-south-1`
2. Deploy SAM stack in region B:
   - `sam deploy --guided --region us-east-1`
3. Build and push Cowrie image to ECR per region (or use cross-region replication).
4. Create ECS clusters and Fargate services per region.
5. Ensure log shipping writes to the correct region’s raw bucket.

## Observability checklist

- CloudWatch logs for ECS tasks and Lambdas
- CloudWatch alarms:
  - Lambda errors/throttles
  - DynamoDB throttles
  - S3 4xx/5xx
- Cost controls:
  - S3 lifecycle rules
  - DynamoDB on-demand vs provisioned later

