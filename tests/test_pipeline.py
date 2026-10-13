"""
Stdlib-only tests (python -m unittest discover -s tests) for the pieces that
run both on AWS and in the local demo: ingest normalization, botnet
clustering, the enrich Lambda's stream filter, and the demo HTTP API.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline" / "cluster_lambda"))
sys.path.insert(0, str(ROOT / "demo"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


ingest = _load("ingest_handler", ROOT / "pipeline" / "ingest_lambda" / "handler.py")
enrich = _load("enrich_handler", ROOT / "pipeline" / "enrich_lambda" / "handler.py")
server = _load("demo_server", ROOT / "demo" / "server.py")

import botnet_clustering as bc  # noqa: E402
from simulator import AttackSimulator  # noqa: E402


class NormalizeTests(unittest.TestCase):
    def test_fixture_lines_map_to_schema(self) -> None:
        lines = (ROOT / "pipeline" / "fixtures" / "sample_cowrie_lines.jsonl").read_text(encoding="utf-8").splitlines()
        items = [
            ingest.normalize_cowrie_record(json.loads(l), bucket="b", key="k", line_index=i,
                                           received_at="2026-01-01T00:00:00+00:00", aws_region="ap-south-1")
            for i, l in enumerate(lines)
        ]
        self.assertEqual(items[1]["cowrie_eventid"], "cowrie.login.failed")
        self.assertEqual(items[1]["username"], "root")
        self.assertEqual(items[1]["src_ip"], "198.51.100.10")
        self.assertEqual(items[0]["timeline_pk"], "GLOBAL")
        self.assertNotEqual(items[0]["event_id"], items[1]["event_id"])

    def test_session_id_is_not_used_as_ip(self) -> None:
        item = ingest.normalize_cowrie_record({"eventid": "x", "session": "abc123"}, bucket="b", key="k",
                                              line_index=0, received_at="t", aws_region=None)
        self.assertNotIn("src_ip", item)
        self.assertEqual(item["session"], "abc123")


class ClusteringTests(unittest.TestCase):
    def _records(self):
        sim = AttackSimulator(seed=7)
        raw = sim.history(hours=12)
        recs = [ingest.normalize_cowrie_record(r, bucket="b", key="k", line_index=i, received_at=r["timestamp"],
                                               aws_region="x") for i, r in enumerate(raw)]
        truth = {ip: i for i, ips in enumerate(sim.bots) for ip in ips}
        truth.update({ip: -1 for ip in sim.noise_ips})
        return recs, truth

    def _check(self, result, truth) -> None:
        # Every predicted botnet must be pure (one true botnet), and every true botnet found.
        groups: dict[int, set[int]] = {}
        for ip, lbl in result.ip_labels.items():
            if lbl != bc.NOISE:
                groups.setdefault(lbl, set()).add(truth[ip])
        for lbl, members in groups.items():
            self.assertEqual(len(members), 1, f"cluster {lbl} mixes botnets {members}")
            self.assertNotIn(-1, members, f"cluster {lbl} is made of lone scanners")
        self.assertEqual(len(groups), len({v for v in truth.values() if v != -1}))

    def test_recovers_simulated_botnets(self) -> None:
        recs, truth = self._records()
        self._check(bc.cluster_records(recs), truth)

    def test_pure_python_matches(self) -> None:
        recs, truth = self._records()
        profiles = bc.build_profiles(recs)
        ips = sorted(profiles)
        labels = bc._dbscan_pure(bc.distance_matrix([profiles[i] for i in ips]), bc.DEFAULT_EPS, bc.DEFAULT_MIN_SAMPLES)
        self._check(bc.ClusterResult(dict(zip(ips, labels)), [], 0, "pure-python"), truth)


class EnrichStreamTests(unittest.TestCase):
    def test_modify_records_are_ignored(self) -> None:
        calls = []
        enrich._update_item = lambda *a, **k: calls.append(a)  # type: ignore[assignment]
        enrich._lookup = lambda ip: ({"loc": "1,2"}, None)  # type: ignore[assignment]
        img = {"event_id": {"S": "e1"}, "src_ip": {"S": "192.0.2.1"}}
        out = enrich.lambda_handler({"Records": [{"eventName": "MODIFY", "dynamodb": {"NewImage": img}}]}, None)
        self.assertEqual(out["processed"], 0)
        out = enrich.lambda_handler({"Records": [{"eventName": "INSERT", "dynamodb": {"NewImage": img}}]}, None)
        self.assertEqual(out["processed"], 1)
        self.assertEqual(len(calls), 1)


class DemoServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sim = AttackSimulator(seed=1)
        cls.store = server.EventStore(intel=sim.intel, lab_latlon=(0.0, 0.0), sensor_region="ap-south-1",
                                      use_live_intel=False)
        cls.store.ingest(sim.history(hours=6), source="test", use_event_time=True)
        cls.store.recluster()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(cls.store, "test"))
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _get(self, path: str):
        with urllib.request.urlopen(self.base + path) as r:
            return r.status, json.loads(r.read()), r.headers

    def test_events_contract(self) -> None:
        status, body, headers = self._get("/events?limit=10")
        self.assertEqual(status, 200)
        self.assertEqual(body["count"], 10)
        self.assertEqual(headers["access-control-allow-origin"], "*")
        first = body["items"][0]
        for key in ("event_id", "received_at", "src_ip", "geo_lat", "geo_lon", "cluster_id", "aws_region"):
            self.assertIn(key, first)
        times = [i["received_at"] for i in body["items"]]
        self.assertEqual(times, sorted(times, reverse=True))

    def test_stats(self) -> None:
        _, body, _ = self._get("/stats")
        self.assertGreater(body["total_events"], 0)
        self.assertGreater(body["botnets"], 0)
        self.assertEqual(len(body["events_last_24h"]), 24)

    def test_private_ip_gets_lab_location(self) -> None:
        self.store.ingest([{"eventid": "cowrie.login.failed", "src_ip": "172.17.0.1", "username": "root",
                            "password": "x", "timestamp": "2026-01-01T00:00:00Z"}], source="cowrie",
                          use_event_time=False)
        _, body, _ = self._get("/events?limit=1")
        self.assertEqual(body["items"][0]["geo_country"], "LAN")


if __name__ == "__main__":
    unittest.main()
