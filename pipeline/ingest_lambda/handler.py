"""
S3 ObjectCreated -> parse JSONL (Cowrie-style) -> DynamoDB put_item.

No third-party APIs here; geo-IP and reputation are added by the enrich Lambda
(DynamoDB Stream consumer) after the row lands.

`normalize_cowrie_record` is a pure function so the local demo backend
(demo/server.py) can reuse the exact same event schema without AWS.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import urllib.parse
from datetime import datetime, timezone
from typing import Any

# AWS clients are created lazily so this module can be imported without boto3
# (the local demo backend only needs `normalize_cowrie_record`).
_s3 = None
_ddb = None


def _clients() -> tuple[Any, Any]:
    global _s3, _ddb
    if _s3 is None or _ddb is None:
        import boto3  # noqa: PLC0415

        _s3 = boto3.client("s3")
        _ddb = boto3.resource("dynamodb")
    return _s3, _ddb


def _sha256_id(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="replace"))
        h.update(b"\x1e")
    return h.hexdigest()


def _maybe_decompress(body: bytes, key: str, metadata: dict[str, str] | None) -> bytes:
    meta = {k.lower(): v for k, v in (metadata or {}).items()}
    if meta.get("content-encoding", "").lower() == "gzip" or key.endswith(".gz"):
        return gzip.decompress(body)
    return body


def _extract_src_ip(obj: dict[str, Any]) -> str | None:
    for k in ("src_ip", "srcIp", "peer_ip", "peerIP"):
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # Note: Cowrie's `session` is a session id, not an address — never use it as src_ip.
    return None


def _str_field(obj: dict[str, Any], key: str, max_len: int) -> str | None:
    v = obj.get(key)
    if isinstance(v, str) and v.strip():
        return v.strip()[:max_len]
    return None


def normalize_cowrie_record(
    data: dict[str, Any],
    *,
    bucket: str,
    key: str,
    line_index: int,
    received_at: str,
    aws_region: str | None,
) -> dict[str, Any]:
    """Map one Cowrie JSON log object to the DynamoDB event item schema."""
    item: dict[str, Any] = {
        "event_id": _sha256_id(bucket, key, str(line_index)),
        "received_at": received_at,
        # Timeline GSI partition for "recent events" API (read Lambda).
        "timeline_pk": "GLOBAL",
        "aws_region": (aws_region or "")[:32],
        "s3_bucket": bucket,
        "s3_key": key,
        "line_index": line_index,
    }

    optional = {
        "cowrie_eventid": _str_field(data, "eventid", 1024),
        "src_ip": _extract_src_ip(data),
        "sensor_timestamp": _str_field(data, "timestamp", 64),
        "session": _str_field(data, "session", 64),
        "sensor": _str_field(data, "sensor", 128),
        # Credentials and commands drive the botnet clustering features.
        "username": _str_field(data, "username", 256),
        "password": _str_field(data, "password", 256),
        "command": _str_field(data, "input", 1024),
        "client_version": _str_field(data, "version", 256),
    }
    for k, v in optional.items():
        if v is not None:
            item[k] = v[:64] if k == "src_ip" else v
    return item


def _process_object(*, bucket: str, key: str, aws_region: str | None) -> int:
    s3, ddb = _clients()
    table = ddb.Table(os.environ["EVENTS_TABLE_NAME"])
    head = s3.head_object(Bucket=bucket, Key=key)
    meta = head.get("Metadata") or {}

    obj_body = s3.get_object(Bucket=bucket, Key=key)
    raw = obj_body["Body"].read()
    raw = _maybe_decompress(raw, key=key, metadata=meta)
    text = raw.decode("utf-8", errors="replace")

    received_at = datetime.now(timezone.utc).isoformat()
    written = 0

    with table.batch_writer() as batch:
        for idx, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue

            batch.put_item(
                Item=normalize_cowrie_record(
                    data,
                    bucket=bucket,
                    key=key,
                    line_index=idx,
                    received_at=received_at,
                    aws_region=aws_region,
                )
            )
            written += 1

    return written


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    total = 0
    errors: list[str] = []

    for record in event.get("Records", []):
        if record.get("eventSource") != "aws:s3":
            continue
        try:
            bucket = record["s3"]["bucket"]["name"]
            key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
            aws_region = record.get("awsRegion")
        except (KeyError, TypeError) as exc:
            errors.append(f"bad_record:{exc!s}")
            continue

        try:
            total += _process_object(bucket=bucket, key=key, aws_region=aws_region if isinstance(aws_region, str) else None)
        except Exception as exc:  # noqa: BLE001 — log and continue per object
            errors.append(f"{bucket}/{key}:{exc!s}")

    return {"written_lines": total, "errors": errors[:10]}
