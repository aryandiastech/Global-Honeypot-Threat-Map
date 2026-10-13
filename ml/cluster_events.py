#!/usr/bin/env python3
"""
Offline botnet clustering for honeypot events.

Reads JSON from:
  - a file containing {"items":[...]} (read API export), or
  - JSONL where each line is one object (Dynamo-ish or Cowrie-ish).

Groups events into one behavioural profile per attacking IP and runs DBSCAN
(see pipeline/cluster_lambda/botnet_clustering.py — the same code the
scheduled Lambda and the local demo backend use). Writes each record back
with a `cluster_id` (-1 = noise / not part of a botnet).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "pipeline" / "cluster_lambda"))

from botnet_clustering import (  # noqa: E402
    DEFAULT_EPS,
    DEFAULT_MIN_SAMPLES,
    cluster_records,
    label_records,
)


def _load_records(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    # JSONL (multiple JSON objects, one per line) — includes Cowrie exports.
    if len(lines) > 1:
        return [json.loads(line) for line in lines]

    # Single blob: API export {"items":[...]} / array / one object.
    data = json.loads(lines[0])
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return [x for x in data["items"] if isinstance(x, dict)]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        return [data]
    raise ValueError("Unsupported JSON shape.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True, help="Path to JSON or JSONL input.")
    parser.add_argument("--output", type=Path, default=None, help="Write labeled JSONL here (stdout if omitted).")
    parser.add_argument("--eps", type=float, default=DEFAULT_EPS, help="DBSCAN eps in weighted feature space.")
    parser.add_argument("--min-samples", type=int, default=DEFAULT_MIN_SAMPLES, help="DBSCAN min_samples (IPs).")
    args = parser.parse_args()

    records = _load_records(args.input)
    if len(records) < 2:
        print("Need at least 2 records to cluster meaningfully.", file=sys.stderr)
        return 2

    result = cluster_records(records, eps=args.eps, min_samples=args.min_samples)
    label_records(records, result)

    payload = "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)

    meta = {
        "records": len(records),
        "ips": len(result.ip_labels),
        "clusters": len(result.clusters),
        "noise_ips": result.n_noise_ips,
        "engine": result.engine,
        "eps": args.eps,
        "min_samples": args.min_samples,
        "botnets": result.clusters,
    }
    print(json.dumps(meta, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
