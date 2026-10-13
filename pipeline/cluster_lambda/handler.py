"""
Scheduled Lambda: read recent events from DynamoDB, group attacking IPs into
botnet clusters (see botnet_clustering.py) and write `cluster_id` back.

No third-party dependencies — the DBSCAN implementation is pure Python, so the
deployment package stays small (boto3 ships with the Lambda runtime).
"""

from __future__ import annotations

import os
from typing import Any

import boto3

from botnet_clustering import NOISE, cluster_records

_ddb = boto3.resource("dynamodb")

# Upper bound on events pulled per run (keeps the O(n^2) step and the scan cost bounded).
_MAX_EVENTS = int(os.environ.get("CLUSTER_MAX_EVENTS", "5000"))


def _recent_events(table: Any) -> list[dict[str, Any]]:
    """Newest events first via the timeline GSI (avoids a full-table scan)."""
    items: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {
        "IndexName": "timeline-received_at",
        "KeyConditionExpression": "timeline_pk = :pk",
        "ExpressionAttributeValues": {":pk": "GLOBAL"},
        "ScanIndexForward": False,
    }
    while len(items) < _MAX_EVENTS:
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last
    return items[:_MAX_EVENTS]


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    table_name = os.environ.get("EVENTS_TABLE_NAME")
    if not table_name:
        print("EVENTS_TABLE_NAME not set.")
        return {"status": "error", "reason": "EVENTS_TABLE_NAME not set"}

    table = _ddb.Table(table_name)
    items = _recent_events(table)
    if len(items) < 2:
        print("Not enough items to cluster.")
        return {"status": "skipped", "events": len(items)}

    result = cluster_records(items)

    updates = 0
    for item in items:
        ip = item.get("src_ip")
        cluster_id = result.ip_labels.get(ip, NOISE) if isinstance(ip, str) else NOISE
        current = item.get("cluster_id")
        # Skip unchanged rows (DynamoDB returns numbers as Decimal).
        if current is not None and int(current) == cluster_id:
            continue
        table.update_item(
            Key={"event_id": item["event_id"]},
            UpdateExpression="SET cluster_id = :val",
            ExpressionAttributeValues={":val": cluster_id},
        )
        updates += 1

    print(
        f"Clustered {len(items)} events from {len(result.ip_labels)} IPs into "
        f"{len(result.clusters)} botnets ({result.n_noise_ips} noise IPs) with {result.engine}; "
        f"{updates} rows updated."
    )
    return {"status": "success", "clusters": len(result.clusters), "updated": updates}
