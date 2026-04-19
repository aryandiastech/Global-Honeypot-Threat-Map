# ECS Fargate — Cowrie honeypot

This folder holds **sample** artifacts. Replace placeholders (`ACCOUNT_ID`, `REGION`, image URI, IAM ARNs) before registering a task definition.

## Roles you will create in IAM

- **Task execution role** (ECS uses it to pull from ECR and write CloudWatch Logs): attach AWS managed policy `service-role/AmazonECSTaskExecutionRolePolicy`.
- **Task role** (honeypot app uses it for S3 upload / other AWS calls): grant least privilege, e.g. `s3:PutObject` on your raw log bucket prefix.

## Build and push the image

From repo root (Docker running locally):

```powershell
aws ecr create-repository --repository-name ghtm-cowrie --region ap-south-1
# follow aws ecr get-login-password ... docker login ...
docker build -t ghtm-cowrie:latest honeypots/cowrie
docker tag ghtm-cowrie:latest <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/ghtm-cowrie:latest
docker push <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/ghtm-cowrie:latest
```

Repeat for `us-east-1` when you deploy the second region.

## Register task definition and run a service

1. Create CloudWatch log group `/ecs/ghtm-cowrie` (or match `task-definition.sample.json`).
2. Substitute ARNs and image in `task-definition.sample.json`.
3. Register:

```powershell
aws ecs register-task-definition --cli-input-json file://infra/ecs/task-definition.sample.json --region ap-south-1
```

4. Create an **ECS cluster** (Fargate), a **security group** allowing **TCP 2222** from `0.0.0.0/0` (only if you intend a public honeypot), subnets with a route to an **Internet Gateway** for tasks with **public IP assigned**, then create a **Fargate service** with launch type Fargate.

Log shipping to the **ingest** S3 bucket is a follow-up (sidecar container, FireLens, or scheduled upload); the ingest Lambda already accepts any object key once it lands in the bucket.
