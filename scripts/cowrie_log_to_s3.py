#!/usr/bin/env python3
"""
Upload a Cowrie JSON log file (or any file) to the raw ingest S3 bucket.

Uses the default boto3 credential chain (ECS task role, env vars, ~/.aws, etc.).
Triggers the existing ingest Lambda on ObjectCreated.
"""

from __future__ import annotations

import argparse
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

import boto3


def _default_key(prefix: str, local_path: Path) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    host = socket.gethostname().split(".")[0]
    safe_base = local_path.name.replace("\\", "/")
    return f"{prefix.rstrip('/')}/{stamp}/{host}/{safe_base}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True, help="Raw log bucket name (SAM output RawLogBucketName).")
    parser.add_argument(
        "--key",
        help="Full S3 object key. If omitted, use --prefix with an auto-generated suffix.",
    )
    parser.add_argument(
        "--prefix",
        default="cowrie/",
        help="When --key is omitted, object key becomes prefix + date + host + filename (default: cowrie/).",
    )
    parser.add_argument(
        "--file",
        required=True,
        type=Path,
        help="Path to the local file to upload (e.g. cowrie.json or a rotated log).",
    )
    parser.add_argument("--region", default=None, help="AWS region (defaults to env / config chain).")
    args = parser.parse_args()

    local_path: Path = args.file
    if not local_path.is_file():
        raise SystemExit(f"File not found: {local_path}")

    key = args.key or _default_key(args.prefix, local_path)
    region = args.region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")

    session = boto3.session.Session(region_name=region) if region else boto3.session.Session()
    s3 = session.client("s3")

    extra = {
        "ServerSideEncryption": "AES256",
        "ContentType": "application/octet-stream",
    }

    s3.upload_file(
        str(local_path),
        args.bucket,
        key,
        ExtraArgs=extra,
    )
    print(f"Uploaded s3://{args.bucket}/{key} ({local_path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
