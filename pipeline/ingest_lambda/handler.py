"""
S3 ObjectCreated -> parse JSONL (Cowrie-style) -> DynamoDB put_item.

No third-party APIs here; Mapbox / geolocation / threat-intel are added later
when building the frontend and enrichment Lambdas.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import boto3

_s3 = boto3.client("s3")
_ddb = boto3.resource("dynamodb")
_TABLE_NAME = os.environ["EVENTS_TABLE_NAME"]


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
    session = obj.get("session")
    if isinstance(session, str) and session.strip():
        return session.strip()
    return None


def _process_object(*, bucket: str, key: str) -> int:
    table = _ddb.Table(_TABLE_NAME)
    head = _s3.head_object(Bucket=bucket, Key=key)
    meta = head.get("Metadata") or {}

    obj_body = _s3.get_object(Bucket=bucket, Key=key)
    raw = obj_body["Body"].read()
    raw = _maybe_decompress(raw, key=key, metadata=meta)
    text = raw.decode("utf-8", errors="replace")

    received_at = datetime.now(timezone.utc).isoformat()
    written = 0

    for idx, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            data: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue

        event_id = _sha256_id(bucket, key, str(idx))
        item: dict[str, Any] = {
            "event_id": event_id,
            "received_at": received_at,
            "s3_bucket": bucket,
            "s3_key": key,
            "line_index": idx,
        }

        cowrie_event = data.get("eventid")
        if isinstance(cowrie_event, str):
            item["cowrie_eventid"] = cowrie_event[:1024]

        src_ip = _extract_src_ip(data)
        if src_ip:
            item["src_ip"] = src_ip[:64]

        ts = data.get("timestamp")
        if isinstance(ts, str) and ts.strip():
            item["sensor_timestamp"] = ts.strip()[:64]

        table.put_item(Item=item)
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
        except (KeyError, TypeError) as exc:
            errors.append(f"bad_record:{exc!s}")
            continue

        try:
            total += _process_object(bucket=bucket, key=key)
        except Exception as exc:  # noqa: BLE001 — log and continue per object
            errors.append(f"{bucket}/{key}:{exc!s}")

    return {"written_lines": total, "errors": errors[:10]}
