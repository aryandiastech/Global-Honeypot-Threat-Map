"""
DynamoDB Streams -> enrich new events with:
- Geo-IP (IPinfo)
- Abuse score (AbuseIPDB)

Secrets are passed as Lambda env vars via SAM NoEcho parameters.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal
from typing import Any

# boto3 / table name are resolved lazily so the lookup helpers can be imported
# without AWS (the local demo backend reuses `_lookup` when API keys are set).
_ddb = None


def _table() -> Any:
    global _ddb
    if _ddb is None:
        import boto3  # noqa: PLC0415

        _ddb = boto3.resource("dynamodb")
    return _ddb.Table(os.environ["EVENTS_TABLE_NAME"])


_IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "").strip()
_ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "").strip()


def _get_src_ip(new_image: dict[str, Any]) -> str | None:
    v = new_image.get("src_ip")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return None


def _http_json(url: str, headers: dict[str, str] | None = None, timeout_s: int = 6) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = resp.read()
    return json.loads(body.decode("utf-8", errors="replace"))


def _ipinfo_lookup(ip: str) -> dict[str, Any] | None:
    if not _IPINFO_TOKEN:
        return None
    q = urllib.parse.urlencode({"token": _IPINFO_TOKEN})
    url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json?{q}"
    try:
        return _http_json(url)
    except (urllib.error.URLError, json.JSONDecodeError):
        return None


def _abuseipdb_check(ip: str) -> dict[str, Any] | None:
    if not _ABUSEIPDB_KEY:
        return None
    url = (
        "https://api.abuseipdb.com/api/v2/check?"
        + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"})
    )
    headers = {"Key": _ABUSEIPDB_KEY, "Accept": "application/json"}
    try:
        out = _http_json(url, headers=headers)
        data = out.get("data")
        return data if isinstance(data, dict) else None
    except (urllib.error.URLError, json.JSONDecodeError):
        return None


def _to_decimal(x: float) -> Decimal:
    # DynamoDB wants Decimal for non-integers.
    return Decimal(str(x))


def _update_item(event_id: str, *, geo: dict[str, Any] | None, abuse: dict[str, Any] | None) -> None:
    table = _table()

    exprs: list[str] = ["enriched_at = :t"]
    values: dict[str, Any] = {":t": int(time.time())}

    if geo:
        loc = geo.get("loc")  # "lat,lon"
        if isinstance(loc, str) and "," in loc:
            lat_s, lon_s = loc.split(",", 1)
            try:
                lat = float(lat_s)
                lon = float(lon_s)
                exprs += ["geo_lat = :lat", "geo_lon = :lon"]
                values[":lat"] = _to_decimal(lat)
                values[":lon"] = _to_decimal(lon)
            except ValueError:
                pass

        for k_src, k_dst in (
            ("country", "geo_country"),
            ("region", "geo_region"),
            ("city", "geo_city"),
            ("org", "geo_org"),
        ):
            v = geo.get(k_src)
            if isinstance(v, str) and v.strip():
                exprs.append(f"{k_dst} = :{k_dst}")
                values[f":{k_dst}"] = v.strip()[:256]

    if abuse:
        score = abuse.get("abuseConfidenceScore")
        if isinstance(score, int):
            exprs.append("abuse_score = :ascore")
            values[":ascore"] = score
        total = abuse.get("totalReports")
        if isinstance(total, int):
            exprs.append("abuse_total_reports = :atreports")
            values[":atreports"] = total

    table.update_item(
        Key={"event_id": event_id},
        UpdateExpression="SET " + ", ".join(exprs),
        ExpressionAttributeValues=values,
    )


# Warm-container cache: one honeypot session produces many events from the same IP,
# so look each address up once instead of burning API quota per event.
_LOOKUP_CACHE: dict[str, tuple[dict[str, Any] | None, dict[str, Any] | None]] = {}
_CACHE_MAX = 5000


def _lookup(ip: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    hit = _LOOKUP_CACHE.get(ip)
    if hit is not None:
        return hit
    result = (_ipinfo_lookup(ip), _abuseipdb_check(ip))
    if len(_LOOKUP_CACHE) >= _CACHE_MAX:
        _LOOKUP_CACHE.clear()
    _LOOKUP_CACHE[ip] = result
    return result


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    processed = 0
    enriched = 0

    for rec in event.get("Records", []):
        # INSERT only: our own update_item (and the cluster job's writes) emit MODIFY
        # records on the same stream; handling those would re-enrich forever.
        if rec.get("eventName") != "INSERT":
            continue
        ddb = rec.get("dynamodb") or {}
        new_img = ddb.get("NewImage") or {}
        # DynamoDB Streams uses typed JSON; we only need src_ip and event_id.
        # event_id is the PK and must exist.
        eid = new_img.get("event_id", {}).get("S")
        src_ip = new_img.get("src_ip", {}).get("S")
        if not (isinstance(eid, str) and eid and isinstance(src_ip, str) and src_ip):
            continue

        if "enriched_at" in new_img:
            continue

        processed += 1
        geo, abuse = _lookup(src_ip)
        if geo is None and abuse is None:
            # No API keys configured (or both lookups failed): nothing to write.
            continue
        _update_item(eid, geo=geo, abuse=abuse)
        enriched += 1

    return {"processed": processed, "enriched": enriched}

