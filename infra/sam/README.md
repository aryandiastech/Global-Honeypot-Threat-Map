# SAM stack — S3 → Lambda → DynamoDB

Deploys:

- **S3** bucket for raw JSONL logs (ObjectCreated `*.jsonl` triggers Lambda).
- **Lambda** (`pipeline/ingest_lambda`) that reads each object and writes one DynamoDB item per non-empty JSON line.
- **DynamoDB** table with partition key `event_id` and GSI `src_ip-received_at` for map/API queries later.

## Prerequisites

- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html) installed. On Windows you can use: `winget install -e --id Amazon.SAM-CLI` (then open a new terminal).
- AWS credentials configured (`aws sts get-caller-identity` works).
- Choose a **Stage** parameter value (e.g. `dev`) — it is baked into bucket and table names.

## Deploy (guided)

From this directory:

```powershell
sam build
sam deploy --guided
```

Suggested answers:

- Stack name: `ghtm-ingestion-dev` (example)
- Region: `ap-south-1` or `us-east-1` (deploy one stack per region when you scale honeypots)
- Confirm changeset: `y`

After deploy, note **Outputs** for bucket name and table name.

## Test ingest

Upload a small file whose **lines** are JSON objects (Cowrie `*.json` / JSONL exports qualify). Example:

```powershell
aws s3 cp sample.jsonl s3://<RawLogBucketName>/test/sample.jsonl
```

Then query DynamoDB (AWS Console or CLI) for new items.

## Read API (HTTP API → Lambda → DynamoDB)

After deploy, the stack output **HttpApiUrl** is the base URL for:

```powershell
curl "$env:HTTP_API_URL/events?limit=10"
```

Point the dashboard at it via `frontend/.env`:

```text
VITE_API_URL=https://xxxxxxxx.execute-api.REGION.amazonaws.com
```

**Note:** items ingested **before** the `timeline-received_at` GSI existed will not appear until re-ingested (they lack `timeline_pk`).

## Next wiring steps (later milestones)

- Honeypot → S3: sidecar uploader, FireLens, or scheduled `aws s3 cp` from Fargate.
- Enrichment Lambda: **IP geolocation** + optional **threat intel** (create API accounts then; not required for this stack).
