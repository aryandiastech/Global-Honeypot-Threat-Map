# Operational scripts

## `cowrie_log_to_s3.py`

Uploads a log file from disk to the **raw** S3 bucket so the **ingest Lambda** runs.

### Install (local or build host)

```powershell
python -m pip install -r scripts/requirements.txt
```

### Example (after `sam deploy`)

```powershell
python scripts/cowrie_log_to_s3.py --bucket ghtm-raw-logs-dev-123456789012 --file pipeline/fixtures/sample_cowrie_lines.jsonl
```

With an explicit key:

```powershell
python scripts/cowrie_log_to_s3.py --bucket YOUR_BUCKET --key manual/test.jsonl --file path/to/cowrie.json
```

### ECS Fargate

Attach an IAM **task role** that allows `s3:PutObject` on `arn:aws:s3:::YOUR_RAW_BUCKET/*` (see `infra/iam/`). Run this script on a schedule (`cron` in a sidecar, **EventBridge** + small task, or **ECS Exec** while debugging).

Cowrie’s default JSON log path inside the official image is typically under `/cowrie/cowrie-git/var/log/cowrie/` (exact filename may vary by image version).
