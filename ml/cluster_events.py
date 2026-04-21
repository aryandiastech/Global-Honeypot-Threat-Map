#!/usr/bin/env python3
"""
Offline clustering stub for honeypot events.

Reads JSON from:
  - a file containing {"items":[...]} (read API export), or
  - JSONL where each line is one object (Dynamo-ish or Cowrie-ish).

Builds a tiny 2D numeric feature vector per row and runs DBSCAN.
This is intentionally simple for a first milestone; swap in richer features later.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.cluster import DBSCAN


def _load_records(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    # JSONL (multiple JSON objects, one per line) — includes Cowrie exports.
    if len(lines) > 1:
        return [json.loads(line) for line in lines]

    # Single blob: API export {"items":[...]} / array / one object.
    single = lines[0]
    data = json.loads(single)
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return [x for x in data["items"] if isinstance(x, dict)]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        return [data]
    raise ValueError("Unsupported JSON shape.")


def _src_ip(rec: dict[str, Any]) -> str:
    for k in ("src_ip", "srcIp", "peer_ip", "peerIP"):
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "unknown"


def _time_text(rec: dict[str, Any]) -> str | None:
    for k in ("received_at", "sensor_timestamp", "timestamp"):
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _hour_feature(isoish: str | None) -> float:
    if not isoish:
        return 0.0
    try:
        # Accept ISO8601-ish strings; fall back to 0 on parse failure.
        dt = datetime.fromisoformat(isoish.replace("Z", "+00:00"))
        return float(dt.hour) / 23.0
    except ValueError:
        return 0.0


def _ip_feature(ip: str) -> float:
    digest = hashlib.sha256(ip.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:4], "big", signed=False) / float(0xFFFFFFFF)


@dataclass(frozen=True)
class ClusterResult:
    labels: np.ndarray
    n_clusters: int
    n_noise: int


def run_dbscan(features: np.ndarray, *, eps: float, min_samples: int) -> ClusterResult:
    model = DBSCAN(eps=eps, min_samples=min_samples)
    labels = model.fit_predict(features)
    n_clusters = len({x for x in labels.tolist() if x != -1})
    n_noise = int((labels == -1).sum())
    return ClusterResult(labels=labels, n_clusters=n_clusters, n_noise=n_noise)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Path to JSON or JSONL input.")
    parser.add_argument("--output", type=Path, default=None, help="Write labeled JSONL here (stdout if omitted).")
    parser.add_argument("--eps", type=float, default=0.12, help="DBSCAN eps (feature space is roughly [0,1]^2).")
    parser.add_argument("--min-samples", type=int, default=2, help="DBSCAN min_samples.")
    args = parser.parse_args()

    records = _load_records(args.input)
    if len(records) < 2:
        print("Need at least 2 records to cluster meaningfully.", file=sys.stderr)
        return 2

    feats = np.array(
        [[_ip_feature(_src_ip(r)), _hour_feature(_time_text(r))] for r in records],
        dtype=np.float64,
    )
    result = run_dbscan(feats, eps=args.eps, min_samples=args.min_samples)

    out_lines: list[str] = []
    for rec, label in zip(records, result.labels.tolist(), strict=True):
        row = dict(rec)
        row["cluster_id"] = int(label)
        out_lines.append(json.dumps(row, ensure_ascii=False))

    payload = "\n".join(out_lines) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)

    meta = {
        "records": len(records),
        "clusters": result.n_clusters,
        "noise": result.n_noise,
        "eps": args.eps,
        "min_samples": args.min_samples,
    }
    print(json.dumps(meta, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
