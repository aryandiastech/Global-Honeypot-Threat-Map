#!/usr/bin/env python3
"""
Local demo backend — runs the whole data plane on a laptop, no AWS account needed.

It mirrors the AWS pipeline step by step, reusing the same code:

  Cowrie JSON lines ──► normalize_cowrie_record  (pipeline/ingest_lambda)   ≈ S3 → ingest Lambda
                   ──► geo + reputation enrich   (offline table, or IPinfo/AbuseIPDB if keys set)
                   ──► botnet clustering         (pipeline/cluster_lambda)  ≈ scheduled Lambda
                   ──► GET /events               (same JSON contract as pipeline/read_api)

The store starts EMPTY by default — like honeypots that were just deployed — and fills
up as attacks arrive.

Event sources (combine freely):
  * --hours N          — pre-fill N hours of synthetic history (six botnets + lone scanners)
  * live simulation    — one new attack every 4–9 s on a random sensor, switched on/off from the
                         dashboard's Start button (or at launch with --live)
  * --cowrie-log PATH  — tail a real Cowrie cowrie.json (docker compose in honeypots/cowrie)

Endpoints (CORS open, like the AWS HTTP API):
  GET  /events?limit=N        newest first   {"items": [...], "count": N, "source": "local-demo", "simulation": {...}}
  GET  /stats                 aggregates over every event held in memory
  GET  /clusters              botnet summaries from the last clustering run
  GET  /attackers/<ip>        every stored event for one attacker + its botnet summary
  GET  /simulation            live simulation status
  POST /simulation/start      start generating attacks
  POST /simulation/stop       stop generating attacks
  GET  /health

Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
import random
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline" / "cluster_lambda"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from botnet_clustering import cluster_records, label_records  # noqa: E402
from simulator import SENSORS, AttackSimulator, botnet_names  # noqa: E402


def _load_lambda(name: str) -> Any:
    """Import pipeline/<name>/handler.py by path (every Lambda's file is called handler.py)."""
    spec = importlib.util.spec_from_file_location(f"{name}_handler", ROOT / "pipeline" / name / "handler.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


normalize_cowrie_record = _load_lambda("ingest_lambda").normalize_cowrie_record

MAX_EVENTS = 20_000
API_LIMIT_MAX = 500


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventStore:
    """In-memory stand-in for the DynamoDB events table."""

    def __init__(self, *, intel: dict[str, dict[str, Any]], lab_latlon: tuple[float, float],
                 sensor_region: str, use_live_intel: bool) -> None:
        self._lock = threading.Lock()
        self._events: list[dict[str, Any]] = []
        self._seq = 0
        self.intel = intel
        self.lab_latlon = lab_latlon
        self.sensor_region = sensor_region
        self.clusters: list[dict[str, Any]] = []
        self.cluster_engine = "none"
        self.last_clustered = None
        self.sources: set[str] = set()
        self._lookup = None
        if use_live_intel:
            self._lookup = _load_lambda("enrich_lambda")._lookup  # noqa: SLF001 — reuse the Lambda's cached lookups

    # ------------------------------------------------------------- enrichment
    def _enrich(self, item: dict[str, Any]) -> None:
        ip = item.get("src_ip")
        if not ip:
            return
        intel = self.intel.get(ip)
        if intel is None:
            intel = self._intel_for_unknown(ip)
            self.intel[ip] = intel
        item.update(intel)
        item["enriched_at"] = int(time.time())

    def _intel_for_unknown(self, ip: str) -> dict[str, Any]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {}
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            lat, lon = self.lab_latlon
            return {"geo_lat": lat, "geo_lon": lon, "geo_city": "Local lab", "geo_country": "LAN",
                    "geo_country_name": "Local network", "geo_org": "Demo laptop / Docker bridge"}
        if self._lookup is not None:
            geo, abuse = self._lookup(ip)
            out: dict[str, Any] = {}
            if geo and isinstance(geo.get("loc"), str) and "," in geo["loc"]:
                lat_s, lon_s = geo["loc"].split(",", 1)
                out.update(geo_lat=float(lat_s), geo_lon=float(lon_s))
            for src, dst in (("city", "geo_city"), ("region", "geo_region"), ("country", "geo_country"),
                             ("org", "geo_org")):
                if geo and isinstance(geo.get(src), str):
                    out[dst] = geo[src]
            if abuse:
                if isinstance(abuse.get("abuseConfidenceScore"), int):
                    out["abuse_score"] = abuse["abuseConfidenceScore"]
                if isinstance(abuse.get("totalReports"), int):
                    out["abuse_total_reports"] = abuse["totalReports"]
            return out
        return {}

    # ----------------------------------------------------------------- ingest
    def ingest(self, raw_lines: list[dict[str, Any]], *, source: str, use_event_time: bool) -> int:
        """Normalize (same code as the ingest Lambda), enrich, append. Returns rows written."""
        batch: list[dict[str, Any]] = []
        with self._lock:
            for data in raw_lines:
                region = data.pop("_sensor_region", None) or self.sensor_region
                self._seq += 1
                ts = data.get("timestamp")
                received_at = ts if use_event_time and isinstance(ts, str) else _now_iso()
                item = normalize_cowrie_record(
                    data,
                    bucket="ghtm-raw-logs-local-demo",
                    key=f"cowrie/{SENSORS.get(region, 'local')}/{source}.jsonl",
                    line_index=self._seq,
                    received_at=received_at,
                    aws_region=region,
                )
                self._enrich(item)
                batch.append(item)
            self._events.extend(batch)
            self._events.sort(key=lambda e: e["received_at"])
            if len(self._events) > MAX_EVENTS:
                del self._events[: len(self._events) - MAX_EVENTS]
            self.sources.add(source)
        return len(batch)

    def recluster(self) -> None:
        with self._lock:
            events = self._events
            result = cluster_records(events)
            label_records(events, result)
            self.clusters = result.clusters
            self.cluster_engine = result.engine
            self.last_clustered = _now_iso()

    # ------------------------------------------------------------------ reads
    def recent(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in reversed(self._events[-limit:])]

    def attacker(self, ip: str, limit: int = 300) -> dict[str, Any] | None:
        """Everything stored about one source IP (the dashboard's detail panel)."""
        with self._lock:
            rows = [dict(e) for e in reversed(self._events) if e.get("src_ip") == ip][:limit]
            clusters = list(self.clusters)
        if not rows:
            return None
        cid = rows[0].get("cluster_id")
        cluster = next((c for c in clusters if c.get("cluster_id") == cid), None)
        return {"ip": ip, "events": rows, "count": len(rows), "cluster": cluster}

    def stats(self) -> dict[str, Any]:
        with self._lock:
            events = list(self._events)
            clusters = list(self.clusters)
        by_ip: dict[str, dict[str, Any]] = {}
        countries: Counter = Counter()
        creds: Counter = Counter()
        commands: Counter = Counter()
        event_types: Counter = Counter()
        sensors: Counter = Counter()
        hourly: Counter = Counter()
        logins_ok = logins_failed = 0
        now = datetime.now(timezone.utc)
        for e in events:
            ip = e.get("src_ip")
            if ip and ip not in by_ip:
                by_ip[ip] = e
                countries[e.get("geo_country_name") or e.get("geo_country") or "Unknown"] += 1
            et = e.get("cowrie_eventid", "")
            event_types[et] += 1
            if et == "cowrie.login.success":
                logins_ok += 1
            elif et == "cowrie.login.failed":
                logins_failed += 1
            if et.startswith("cowrie.login.") and (e.get("username") or e.get("password")):
                creds[f"{e.get('username', '')}:{e.get('password', '')}"] += 1
            if e.get("command"):
                commands[e["command"]] += 1
            sensors[e.get("aws_region") or "unknown"] += 1
            try:
                age_h = int((now - datetime.fromisoformat(e["received_at"].replace("Z", "+00:00"))).total_seconds() // 3600)
                if 0 <= age_h < 24:
                    hourly[age_h] += 1
            except (KeyError, ValueError):
                pass
        names = botnet_names()
        return {
            "source": "local-demo",
            "total_events": len(events),
            "unique_attackers": len(by_ip),
            "countries": len(countries),
            "login_success": logins_ok,
            "login_failed": logins_failed,
            "botnets": len(clusters),
            "top_countries": countries.most_common(8),
            "top_credentials": creds.most_common(8),
            "top_commands": commands.most_common(6),
            "event_types": event_types.most_common(),
            "events_by_sensor": sensors.most_common(),
            # index 0 = the last hour, 23 = 23-24h ago
            "events_last_24h": [hourly.get(h, 0) for h in range(24)],
            "clusters": clusters,
            "cluster_engine": self.cluster_engine,
            "simulated_botnet_profiles": names,
        }


# ---------------------------------------------------------------- producers
class SimulationController:
    """Start/stop switch for the live attack simulator (driven by the dashboard's button).

    While running, one simulated attack session hits a random honeypot sensor every
    `min_interval`–`max_interval` seconds and goes through the same ingest → enrich →
    clustering path as real traffic.
    """

    def __init__(self, store: EventStore, sim: AttackSimulator, *, min_interval: float, max_interval: float) -> None:
        self._store = store
        self._sim = sim
        self.min_interval = min_interval
        self.max_interval = max(max_interval, min_interval)
        self._lock = threading.Lock()
        self._stop: threading.Event | None = None
        self._rng = random.Random()
        self.attacks = 0
        self.started_at: str | None = None
        self.next_attack_at: str | None = None
        self.last_attack: dict[str, Any] | None = None

    @property
    def running(self) -> bool:
        return self._stop is not None

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._stop is None:
                self._stop = threading.Event()
                self.attacks = 0
                self.started_at = _now_iso()
                threading.Thread(target=self._run, args=(self._stop,), name="attack-sim", daemon=True).start()
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            if self._stop is not None:
                self._stop.set()
                self._stop = None
                self.next_attack_at = None
        return self.status()

    def _run(self, stop: threading.Event) -> None:
        delay = 1.0  # first attack almost immediately so the button feels responsive
        while True:
            with self._lock:
                if self._stop is stop:
                    self.next_attack_at = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()
            if stop.wait(delay):
                return
            self.attack_once()
            delay = self._rng.uniform(self.min_interval, self.max_interval)

    def attack_once(self) -> dict[str, Any]:
        """Generate, ingest and cluster one attack session; returns its summary."""
        start = datetime.now(timezone.utc) - timedelta(seconds=5)
        session = self._sim.random_session(start)
        region = session[0].get("_sensor_region") if session else None
        self._store.ingest(session, source="live-sim", use_event_time=False)
        self._store.recluster()
        first = session[0] if session else {}
        intel = self._store.intel.get(first.get("src_ip", ""), {})
        summary = {
            "src_ip": first.get("src_ip"),
            "session": first.get("session"),
            "aws_region": region,
            "sensor": first.get("sensor"),
            "geo_city": intel.get("geo_city"),
            "geo_country": intel.get("geo_country"),
            "events": len(session),
            "at": _now_iso(),
        }
        with self._lock:
            self.attacks += 1
            self.last_attack = summary
        return summary

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "min_interval": self.min_interval,
            "max_interval": self.max_interval,
            "attacks": self.attacks,
            "started_at": self.started_at,
            "next_attack_at": self.next_attack_at,
            "last_attack": self.last_attack,
        }


def tail_cowrie(store: EventStore, path: Path, poll: float, stop: threading.Event) -> None:
    """Follow cowrie.json like the in-container log shipper does, but ingest locally."""
    position = 0
    print(f"[demo] tailing Cowrie log {path}", flush=True)
    while not stop.wait(poll):
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)
            if fh.tell() < position:  # rotated / truncated
                position = 0
            fh.seek(position)
            lines = fh.readlines()
            position = fh.tell()
        rows = []
        for line in lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
        if rows:
            n = store.ingest(rows, source="cowrie", use_event_time=False)
            store.recluster()
            print(f"[demo] ingested {n} real Cowrie events", flush=True)


# --------------------------------------------------------------------- HTTP
def make_handler(store: EventStore, mode: str,
                 simulation: SimulationController | None = None) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "GHTM-LocalDemo/1.0"

        def _send(self, status: int, body: dict[str, Any]) -> None:
            payload = json.dumps(body, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("access-control-allow-origin", "*")
            self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
            self.send_header("access-control-allow-headers", "*")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._send(204, {})

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            params = parse_qs(url.query)
            route = url.path.rstrip("/") or "/"
            if route == "/events":
                raw = (params.get("limit") or ["25"])[0].strip()
                try:
                    limit = int(raw)
                except ValueError:
                    self._send(400, {"error": "limit must be an integer"})
                    return
                limit = max(1, min(limit, API_LIMIT_MAX))
                items = store.recent(limit)
                body: dict[str, Any] = {"items": items, "count": len(items), "source": "local-demo", "mode": mode}
                if simulation is not None:
                    body["simulation"] = simulation.status()
                self._send(200, body)
            elif route == "/stats":
                self._send(200, store.stats())
            elif route == "/clusters":
                self._send(200, {"clusters": store.clusters, "engine": store.cluster_engine,
                                 "last_clustered": store.last_clustered})
            elif route.startswith("/attackers/"):
                ip = unquote(route[len("/attackers/"):])
                found = store.attacker(ip)
                if found:
                    self._send(200, found)
                else:
                    self._send(404, {"error": "unknown_attacker", "ip": ip})
            elif route == "/simulation":
                if simulation is None:
                    self._send(404, {"error": "simulation_unavailable"})
                else:
                    self._send(200, simulation.status())
            elif route in ("/", "/health"):
                self._send(200, {"ok": True, "service": "ghtm-local-demo", "mode": mode,
                                 "endpoints": ["/events?limit=100", "/stats", "/clusters", "/attackers/<ip>",
                                               "/simulation", "POST /simulation/start", "POST /simulation/stop",
                                               "/health"]})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length") or 0)
            if length:
                self.rfile.read(min(length, 65536))  # body is ignored
            route = urlparse(self.path).path.rstrip("/")
            if simulation is None:
                self._send(404, {"error": "simulation_unavailable"})
            elif route == "/simulation/start":
                self._send(200, simulation.start())
            elif route == "/simulation/stop":
                self._send(200, simulation.stop())
            else:
                self._send(404, {"error": "not_found"})

        def log_message(self, fmt: str, *args: Any) -> None:  # keep the console readable
            if os.environ.get("GHTM_DEMO_ACCESS_LOG"):
                super().log_message(fmt, *args)

    return Handler


def export_snapshot(store: EventStore, out: Path, limit: int) -> None:
    payload = {"items": store.recent(limit), "stats": store.stats(), "source": "static-snapshot",
               "generated_at": _now_iso()}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, default=str, separators=(",", ":")), encoding="utf-8")
    print(f"[demo] wrote snapshot with {len(payload['items'])} events to {out}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--hours", type=int, default=None,
                    help="Hours of simulated history to pre-fill. Default 0 (start empty, like freshly deployed "
                         "honeypots); --export-snapshot defaults to 24.")
    ap.add_argument("--seed", type=int, default=1337, help="Random seed for reproducible demo data.")
    ap.add_argument("--live", action="store_true",
                    help="Start the live attack simulation immediately (otherwise use the dashboard's Start button).")
    ap.add_argument("--min-interval", type=float, default=4.0, help="Minimum seconds between simulated attacks.")
    ap.add_argument("--max-interval", type=float, default=9.0, help="Maximum seconds between simulated attacks.")
    ap.add_argument("--cowrie-log", type=Path, default=None,
                    help="Tail a real Cowrie cowrie.json (e.g. honeypots/cowrie/logs/cowrie.json).")
    ap.add_argument("--sensor-region", default="ap-south-1", choices=sorted(SENSORS),
                    help="Which sensor node real Cowrie events are attributed to on the map.")
    ap.add_argument("--lab-latlon", default="28.6139,77.2090",
                    help="Map position for private/LAN attacker IPs (e.g. your own ssh test).")
    ap.add_argument("--export-snapshot", type=Path, default=None,
                    help="Write a static JSON snapshot (for the frontend's offline mode) and exit.")
    ap.add_argument("--snapshot-limit", type=int, default=500)
    args = ap.parse_args()
    if args.hours is None:
        args.hours = 24 if args.export_snapshot else 0

    lat_s, lon_s = args.lab_latlon.split(",", 1)
    sim = AttackSimulator(seed=args.seed)
    use_live_intel = bool(os.environ.get("IPINFO_TOKEN") or os.environ.get("ABUSEIPDB_KEY"))
    store = EventStore(intel=sim.intel, lab_latlon=(float(lat_s), float(lon_s)),
                       sensor_region=args.sensor_region, use_live_intel=use_live_intel)

    if args.hours > 0:
        n = store.ingest(sim.history(hours=args.hours), source="history-sim", use_event_time=True)
        print(f"[demo] backfilled {n} simulated events over {args.hours}h")
    else:
        print("[demo] starting with an empty database (freshly deployed honeypots)")
    store.recluster()
    if store.clusters:
        print(f"[demo] {len(store.clusters)} botnet clusters found ({store.cluster_engine} DBSCAN)")

    if args.export_snapshot:
        export_snapshot(store, args.export_snapshot, args.snapshot_limit)
        return 0

    stop = threading.Event()
    modes = ["history"] if args.hours > 0 else []
    simulation = SimulationController(store, sim, min_interval=args.min_interval, max_interval=args.max_interval)
    modes.append("live-sim")
    if args.live:
        simulation.start()
    if args.cowrie_log:
        threading.Thread(target=tail_cowrie, args=(store, args.cowrie_log, 2.0, stop), daemon=True).start()
        modes.append("cowrie")
    mode = "+".join(modes) or "empty"

    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(store, mode, simulation))
    print(f"[demo] serving on http://{args.host}:{args.port}  (mode: {mode})")
    print(f"[demo] live simulation {'RUNNING' if simulation.running else 'paused - press Start in the dashboard'}"
          f" (one attack every {args.min_interval:g}-{args.max_interval:g}s)")
    print(f"[demo] try http://{args.host}:{args.port}/events?limit=5   Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        simulation.stop()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
