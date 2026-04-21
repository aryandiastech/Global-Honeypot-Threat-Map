# Deployment and Operations

This document encapsulates the standard operating procedures to boot the infrastructure.

## Prerequisites
- AWS CLI configured locally (`aws configure`).
- AWS SAM CLI installed.
- Docker engine standing by.

## Step 1: Deploy Core Resources using AWS SAM
The DynamoDB tables, S3 Buckets, HTTP API, and all AWS Lambda scripts rely on the SAM `template.yaml`.
```bash
cd infra/sam
sam build --use-container
sam deploy --guided --parameter-overrides Stage=prod IpinfoToken="<YOUR_TOKEN>" AbuseIpdbKey="<YOUR_KEY>"
```
*Note the returned SAM Outputs (specifically the `RawLogBucketName` and `HttpApiUrl`).*

## Step 2: Build & Push the Cowrie Docker Image
Navigate to the Cowrie honeypot directory. The Dockerfile now incorporates `log_shipper.py`.
```bash
cd honeypots/cowrie
docker build -t ghtm-cowrie:latest .
# Push this image to AWS ECR manually following AWS login steps
```

## Step 3: Deploy AWS Fargate
Use the included CloudFormation template to spin up the actual decoy nodes.
```bash
cd infra/ecs
aws cloudformation deploy --template-file fargate-deploy.yaml --stack-name GHTM-Fargate-Prod --parameter-overrides ImageUrl="<YOUR_ECR_URI>" RawLogBucketName="<SAM_BUCKET_NAME>" Stage=prod
```

## Step 4: Launch React UI
```bash
cd frontend
# Populate .env with API URL and Mapbox token
npm install
npm run dev
```
