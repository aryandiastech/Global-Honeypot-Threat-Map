"""
HTTP API: GET /events — recent honeypot events from DynamoDB (timeline GSI).
"""

from __future__ import annotations

import json
import os
from decimal import Decimal
from typing import Any

import boto3

_ddb = boto3.resource("dynamodb")
_TABLE_NAME = os.environ["EVENTS_TABLE_NAME"]


def _json_default(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
        },
        "body": json.dumps(body, default=_json_default),
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    params = event.get("queryStringParameters") or {}
    raw_limit = (params.get("limit") or "25").strip()
    try:
        limit = int(raw_limit)
    except ValueError:
        return _response(400, {"error": "limit must be an integer"})
    limit = max(1, min(limit, 100))

    table = _ddb.Table(_TABLE_NAME)
    try:
        resp = table.query(
            IndexName="timeline-received_at",
            KeyConditionExpression="timeline_pk = :pk",
            ExpressionAttributeValues={":pk": "GLOBAL"},
            ScanIndexForward=False,
            Limit=limit,
        )
    except Exception as exc:  # noqa: BLE001
        return _response(500, {"error": "query_failed", "detail": str(exc)})

    items = resp.get("Items", [])
    return _response(200, {"items": items, "count": len(items)})
