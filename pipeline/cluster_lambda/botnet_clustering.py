"""
Botnet grouping for honeypot events — shared by:

  - pipeline/cluster_lambda/handler.py  (scheduled Lambda, writes cluster_id to DynamoDB)
  - ml/cluster_events.py                (offline CLI over exported JSON / JSONL)
  - demo/server.py                      (local demo backend, no AWS)

Approach: events are grouped into one behavioural profile per attacking IP, a
pairwise distance is computed between profiles, and DBSCAN (precomputed
metric) clusters them; each event inherits its IP's cluster.

Bots from one botnet share a credential dictionary, a payload script and an
SSH client implementation even when their IPs are spread across countries, so
the distance is built from those (set overlap, Jaccard) plus a few behaviour
ratios. Geography is deliberately *not* a feature.

Pure Python (no numpy) so the Lambda deploys without a 200 MB scientific stack.
If scikit-learn is installed, its DBSCAN is used instead (same parameters).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

NOISE = -1

# Distance = weighted sum of components, each in [0, 1].
DISTANCE_WEIGHTS = {
    "credential_dictionary": 0.40,  # Jaccard on username:password pairs tried
    "payload_commands": 0.25,       # Jaccard on shell commands run after login
    "ssh_client": 0.15,             # Jaccard on SSH client version strings
    "behaviour": 0.20,              # mean |diff| of login / command / success ratios
}

DEFAULT_EPS = 0.25
DEFAULT_MIN_SAMPLES = 3


def _src_ip(rec: dict[str, Any]) -> str | None:
    for k in ("src_ip", "srcIp", "peer_ip", "peerIP"):
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _event_type(rec: dict[str, Any]) -> str:
    v = rec.get("cowrie_eventid") or rec.get("eventid") or ""
    return v if isinstance(v, str) else ""


def _text(rec: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _jaccard_distance(a: set[str], b: set[str], *, one_empty: float = 1.0) -> float:
    if not a and not b:
        return 0.0
    if not a or not b:
        return one_empty
    return 1.0 - len(a & b) / len(a | b)


@dataclass
class IpProfile:
    src_ip: str
    events: int = 0
    logins: int = 0
    login_success: int = 0
    commands: int = 0
    credentials: Counter = field(default_factory=Counter)
    command_lines: Counter = field(default_factory=Counter)
    clients: set[str] = field(default_factory=set)

    def add(self, rec: dict[str, Any]) -> None:
        self.events += 1
        et = _event_type(rec)
        if et.startswith("cowrie.login."):
            self.logins += 1
            if et == "cowrie.login.success":
                self.login_success += 1
            user = _text(rec, "username")
            pwd = _text(rec, "password")
            if user or pwd:
                self.credentials[f"{user or ''}:{pwd or ''}"] += 1
        cmd = _text(rec, "command", "input")
        if cmd:
            self.commands += 1
            self.command_lines[cmd] += 1
        client = _text(rec, "client_version") or (_text(rec, "version") if et == "cowrie.client.version" else None)
        if client:
            self.clients.add(client)

    def ratios(self) -> tuple[float, float, float]:
        n = max(1, self.events)
        return (self.logins / n, self.commands / n, self.login_success / max(1, self.logins))

    def distance(self, other: "IpProfile") -> float:
        w = DISTANCE_WEIGHTS
        d_cred = _jaccard_distance(set(self.credentials), set(other.credentials))
        # Many bots never get a shell (failed logins), so a missing command set is
        # "unknown" (0.5) rather than "different" (1.0).
        d_cmd = _jaccard_distance(set(self.command_lines), set(other.command_lines), one_empty=0.5)
        d_client = _jaccard_distance(self.clients, other.clients, one_empty=0.5)
        ra, rb = self.ratios(), other.ratios()
        d_beh = sum(abs(x - y) for x, y in zip(ra, rb)) / len(ra)
        return (w["credential_dictionary"] * d_cred + w["payload_commands"] * d_cmd
                + w["ssh_client"] * d_client + w["behaviour"] * d_beh)


def build_profiles(records: Iterable[dict[str, Any]]) -> dict[str, IpProfile]:
    profiles: dict[str, IpProfile] = {}
    for rec in records:
        ip = _src_ip(rec)
        if not ip:
            continue
        prof = profiles.get(ip)
        if prof is None:
            prof = profiles[ip] = IpProfile(src_ip=ip)
        prof.add(rec)
    return profiles


def distance_matrix(profiles: list[IpProfile]) -> list[list[float]]:
    n = len(profiles)
    dist = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            dist[i][j] = dist[j][i] = profiles[i].distance(profiles[j])
    return dist


def _dbscan_pure(dist: list[list[float]], eps: float, min_samples: int) -> list[int]:
    """Textbook DBSCAN over a precomputed distance matrix."""
    n = len(dist)
    neighbours = [[j for j in range(n) if dist[i][j] <= eps] for i in range(n)]
    labels: list[int | None] = [None] * n
    cluster = -1
    for i in range(n):
        if labels[i] is not None:
            continue
        if len(neighbours[i]) < min_samples:
            labels[i] = NOISE
            continue
        cluster += 1
        labels[i] = cluster
        queue = [j for j in neighbours[i] if j != i]
        while queue:
            j = queue.pop()
            if labels[j] == NOISE:
                labels[j] = cluster  # border point
            if labels[j] is not None:
                continue
            labels[j] = cluster
            if len(neighbours[j]) >= min_samples:
                queue.extend(neighbours[j])
    return [lbl if lbl is not None else NOISE for lbl in labels]


def dbscan(dist: list[list[float]], *, eps: float, min_samples: int) -> tuple[list[int], str]:
    """Returns (labels, engine). Uses scikit-learn when available."""
    if not dist:
        return [], "none"
    try:
        from sklearn.cluster import DBSCAN  # noqa: PLC0415

        labels = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed").fit_predict(dist)
        return [int(x) for x in labels], "scikit-learn"
    except ImportError:
        return _dbscan_pure(dist, eps, min_samples), "pure-python"


def _relabel_by_size(labels: list[int], weights: list[int]) -> list[int]:
    """Renumber clusters 0..k by descending event volume so ids (and UI colours) are stable."""
    totals: Counter = Counter()
    for lbl, w in zip(labels, weights):
        if lbl != NOISE:
            totals[lbl] += w
    order = {old: new for new, (old, _) in enumerate(sorted(totals.items(), key=lambda kv: (-kv[1], kv[0])))}
    return [order.get(lbl, NOISE) for lbl in labels]


@dataclass
class ClusterResult:
    ip_labels: dict[str, int]
    clusters: list[dict[str, Any]]
    n_noise_ips: int
    engine: str


def cluster_records(
    records: list[dict[str, Any]],
    *,
    eps: float = DEFAULT_EPS,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> ClusterResult:
    profiles = build_profiles(records)
    ips = sorted(profiles)
    ordered = [profiles[ip] for ip in ips]
    raw, engine = dbscan(distance_matrix(ordered), eps=eps, min_samples=min_samples)
    labels = _relabel_by_size(raw, [p.events for p in ordered])
    ip_labels = dict(zip(ips, labels))

    clusters: list[dict[str, Any]] = []
    for cid in sorted({lbl for lbl in labels if lbl != NOISE}):
        members = [p for p in ordered if ip_labels[p.src_ip] == cid]
        creds: Counter = Counter()
        cmds: Counter = Counter()
        clients: Counter = Counter()
        for m in members:
            creds.update(m.credentials)
            cmds.update(m.command_lines)
            clients.update(m.clients)
        clusters.append(
            {
                "cluster_id": cid,
                "ips": len(members),
                "events": sum(m.events for m in members),
                "top_credentials": [c for c, _ in creds.most_common(3)],
                "top_commands": [c for c, _ in cmds.most_common(2)],
                "ssh_clients": [c for c, _ in clients.most_common(2)],
            }
        )
    return ClusterResult(
        ip_labels=ip_labels,
        clusters=clusters,
        n_noise_ips=sum(1 for lbl in labels if lbl == NOISE),
        engine=engine,
    )


def label_records(records: list[dict[str, Any]], result: ClusterResult) -> None:
    """Write `cluster_id` onto each record in place (NOISE for unknown IPs)."""
    for rec in records:
        ip = _src_ip(rec)
        rec["cluster_id"] = result.ip_labels.get(ip, NOISE) if ip else NOISE
