# IAM snippets

## ECS task role — upload raw logs to S3

Attach the policy in `task-role-s3-put-policy.json` to the **task role** used by your Cowrie (or log-shipper) task. Replace `REPLACE_WITH_RAW_BUCKET_NAME` with the bucket name from the SAM stack output **before** saving the policy in IAM.

If the bucket uses **SSE-KMS**, also grant `kms:Encrypt` (and related) on that CMK.

The **task execution role** should remain separate: it is only for ECR pull + CloudWatch Logs, via `AmazonECSTaskExecutionRolePolicy`.
