# Deploying to AWS (and recovering the old account)

You do **not** need AWS to present the project (see [DEMO.md](DEMO.md)). This page is for running the real
cloud version on any AWS account in about 15 minutes, and for finding the account the project was originally built on.

---

## A. Finding the original AWS account

The repo never stored an account ID (the only one in git history is AWS's placeholder `123456789012`), and the
access key saved in `~/.aws/credentials` on the original laptop **no longer works** (`InvalidClientTokenId`): it has been
deactivated or deleted, or the account was closed. Ways to recover it:

1. **Decode the account ID from the old key.** On the original laptop, the key ID is still in `~/.aws/credentials`
   (`aws_access_key_id = AKIA…`). With credentials from *any* working AWS account, run:

   ```bash
   aws sts get-access-key-info --access-key-id AKIAxxxxxxxxxxxxxxxx
   ```

   It returns `{"Account": "123456789012"}` even if the key is inactive. Only the *key ID* is needed, never the secret.
2. **Search every inbox you might have used** for mail from `@signin.aws`, `@verify.signin.aws`, `aws-verification`,
   or "Welcome to Amazon Web Services" / "AWS Billing" around April 2026. That address is the root-user login.
3. **Saved browser passwords** for `signin.aws.amazon.com` / `console.aws.amazon.com`.
4. **Card statements**: an AWS charge (even ₹2 / $1 verification holds) shows which card, and therefore which email, was used.
5. Once you know the email, use **"Forgot password"** on the root sign-in page. If you've lost access to the email too,
   use AWS's account-recovery support form.

When you're back in, check **CloudFormation** in `ap-south-1` and `us-east-1` for `ghtm-*` stacks, and **Billing** for
leftover charges. Delete stacks you no longer need, since a running Fargate task or log group costs money.

## B. Fresh deploy on a new account (recommended for the friend)

### Costs

Accounts created after July 15, 2025 choose a **Free plan** (up to **$200 in credits**, ending after 6 months or when the
credits run out) or a Paid plan. Lambda (1M requests/month) and DynamoDB storage (25 GB) are **always free**. For this
project:

| Piece | Cost for a class demo |
|-------|-----------------------|
| S3, Lambda ×4, HTTP API, DynamoDB on-demand | cents per month at demo traffic |
| Fargate **Spot** honeypot, 0.25 vCPU / 0.5 GB, 24×7 | roughly $6–7 / month per region incl. the ~$3.60 public-IPv4 charge (credits cover it; set `DesiredCount=0` to pause) |
| CloudWatch logs (7-day retention) | cents |

Set an **AWS Budget** alert ($5) right after signup. Tear down with `sam delete` / `aws cloudformation delete-stack`
when done.

### Prerequisites

- AWS CLI v2, `aws configure` with an IAM user/role (not root). `aws sts get-caller-identity` must work.
- AWS SAM CLI (`winget install -e --id Amazon.SAM-CLI`), Docker Desktop running.

### 1. Data plane: S3 → Lambdas → DynamoDB → HTTP API

```bash
cd infra/sam
sam build
sam deploy --guided --stack-name ghtm-dev --region ap-south-1 \
  --parameter-overrides Stage=dev IpinfoToken="" AbuseIpdbKey="" --capabilities CAPABILITY_IAM
```

Note the outputs `RawLogBucketName` and `HttpApiUrl`. Geo arcs need an **IPinfo** token (free 50k lookups/month,
https://ipinfo.io/signup); reputation needs an **AbuseIPDB** key (free 1k checks/day, https://www.abuseipdb.com/register).
Pass them as `IpinfoToken=…` / `AbuseIpdbKey=…` on deploy. They are `NoEcho` parameters, so they never go in git.

Smoke test without a honeypot:

```bash
aws s3 cp pipeline/fixtures/sample_cowrie_lines.jsonl s3://<RawLogBucketName>/test/sample.jsonl
curl "<HttpApiUrl>/events?limit=5"
```

### 2. Honeypot: Cowrie on Fargate

```bash
ACCOUNT=$(aws sts get-caller-identity --query Account --output text); REGION=ap-south-1
aws ecr create-repository --repository-name ghtm-cowrie --region $REGION
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT.dkr.ecr.$REGION.amazonaws.com
docker build -t $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/ghtm-cowrie:latest honeypots/cowrie
docker push $ACCOUNT.dkr.ecr.$REGION.amazonaws.com/ghtm-cowrie:latest

VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text --region $REGION)
SUBNETS=$(aws ec2 describe-subnets --filters Name=vpc-id,Values=$VPC --query 'Subnets[].SubnetId' --output text --region $REGION | tr '\t' ',')
aws cloudformation deploy --region $REGION --stack-name ghtm-cowrie-dev \
  --template-file infra/ecs/fargate-deploy.yaml --capabilities CAPABILITY_IAM \
  --parameter-overrides Stage=dev ImageUrl=$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/ghtm-cowrie:latest \
    RawLogBucketName=<RawLogBucketName> VpcId=$VPC SubnetIds=$SUBNETS
```

The task's public IP (ECS console → task → Networking) accepts SSH on **2222**. New logs reach S3 every 60 s,
then DynamoDB, enrichment, and every 30 min the clustering job runs.

Repeat both steps with `--region us-east-1` for the second sensor.

### 3. Point the dashboard at AWS

```env
# frontend/.env
VITE_API_URL=https://xxxxxxxx.execute-api.ap-south-1.amazonaws.com
VITE_POLL_MS=15000
VITE_EVENTS_LIMIT=100
```

The badge switches to **AWS · live**. The AWS read API has no `/stats`, so the dashboard computes stats from the
latest 100 events.

## C. "AWS without AWS" options (researched)

| Option | Verdict |
|--------|---------|
| **This repo's local demo backend** (`demo/server.py`) | ✅ Recommended. Zero accounts, runs the same Lambda code paths, works offline. |
| **LocalStack** | ⚠️ Since the March 2026 release, LocalStack requires an account and auth token even for the free (non-commercial "Hobby") tier, and the old open-source community image is no longer the default. That's more setup than it's worth for a demo. |
| **`sam local start-api` + DynamoDB Local** | Possible for the read API only. Needs Docker plus a seeded local table, and still no S3 trigger or stream. More moving parts than the demo backend. |
| **A friend's/new AWS account** | ✅ Section B. The real thing, covered by new-account credits. |
