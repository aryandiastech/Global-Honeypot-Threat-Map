#!/usr/bin/env python3
"""
Lightweight Log Shipper to tail cowrie.json and upload batches to S3.
Designed to run in the background within the Cowrie container to stay within AWS Free Tier memory limits.
"""

import os
import time
import socket
from datetime import datetime, timezone
import boto3

FILE_PATH = os.environ.get("COWRIE_LOG_PATH", "/cowrie/cowrie-git/var/log/cowrie/cowrie.json")
BUCKET_NAME = os.environ.get("S3_RAW_LOG_BUCKET")
INTERVAL = int(os.environ.get("SHIPPER_INTERVAL_SEC", "60"))
REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "ap-south-1"))

def main():
    if not BUCKET_NAME:
        print("[Shipper] S3_RAW_LOG_BUCKET not set. Log shipping disabled.")
        # We don't exit to prevent crashing the container loop if misconfigured.
        while True:
            time.sleep(3600)

    print(f"[Shipper] Starting log tailer for {FILE_PATH}")
    print(f"[Shipper] Target bucket: {BUCKET_NAME}, Region: {REGION}, Interval: {INTERVAL}s")

    s3 = boto3.client('s3', region_name=REGION)
    position = 0
    prefix = "cowrie"
    host = socket.gethostname().split(".")[0]

    while True:
        try:
            time.sleep(INTERVAL)

            if not os.path.exists(FILE_PATH):
                continue
            
            with open(FILE_PATH, 'r', encoding='utf-8') as f:
                # If file is truncated (e.g. log rotation), reset position
                f.seek(0, 2)
                if f.tell() < position:
                    position = 0
                
                f.seek(position)
                lines = f.readlines()
                position = f.tell()

            if lines:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                stamp_path = datetime.now(timezone.utc).strftime("%Y/%m/%d")
                tmp_file = f"/tmp/log_batch_{timestamp}.jsonl"
                
                # Filter empty lines
                valid_lines = [ln for ln in lines if ln.strip()]
                if not valid_lines:
                    continue

                with open(tmp_file, 'w', encoding='utf-8') as tf:
                    tf.writelines(valid_lines)

                key = f"{prefix}/{stamp_path}/{host}/batch_{timestamp}.jsonl"
                
                extra = {
                    "ServerSideEncryption": "AES256",
                    "ContentType": "application/octet-stream",
                }

                s3.upload_file(tmp_file, BUCKET_NAME, key, ExtraArgs=extra)
                os.remove(tmp_file)
                print(f"[Shipper] Uploaded {len(valid_lines)} events to s3://{BUCKET_NAME}/{key}")

        except Exception as e:
            print(f"[Shipper] Error during upload cycle: {e}")

if __name__ == "__main__":
    main()
