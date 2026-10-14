# ML

Two complementary models:

| Module | Unit | Question | Method |
|--------|------|----------|--------|
| `attack_analysis.py` | attack session | *What kind of attack was it?* | Naive Bayes classifier → 7 types + MITRE ATT&CK; k-means (silhouette-picked k) + PCA |
| `../pipeline/cluster_lambda/botnet_clustering.py` (CLI: `cluster_events.py`) | attacker IP | *Who is coordinated?* | DBSCAN on shared password lists / commands / SSH client |

## Attack-type analysis

```powershell
curl "http://localhost:8000/attacks" -o ml/attacks.json
python ml/attack_analysis.py --input ml/attacks.json --output ml/analysis.json
```

The model card (classifier accuracy, k, silhouette, cluster/type agreement) prints to stderr. The demo backend runs
the same code on `POST /analysis/scan`.

# Botnet clustering (offline CLI)

`cluster_events.py` runs the same clustering as the scheduled Lambda and the local demo
(`pipeline/cluster_lambda/botnet_clustering.py`) on an exported file:

- one **behavioural profile per attacking IP** (credential dictionary, payload commands, SSH client, login/command/success ratios),
- a weighted **Jaccard + ratio distance** between profiles,
- **DBSCAN** on the precomputed distance matrix (`eps=0.25`, `min_samples=3`); `-1` = noise / lone scanner.

## Install (optional)

The code is pure Python. scikit-learn is used automatically if installed:

```powershell
python -m pip install -r ml/requirements.txt
```

## Run

```powershell
# fixture (2 lines -> 1 IP -> noise)
python ml/cluster_events.py --input pipeline/fixtures/sample_cowrie_lines.jsonl --output ml/out-labeled.jsonl

# realistic: export from the running demo backend (or the AWS read API) and cluster it
curl "http://localhost:8000/events?limit=500" -o ml/export.json
python ml/cluster_events.py --input ml/export.json --output ml/out-labeled.jsonl
```

Metadata (cluster sizes, top credentials and commands per botnet) prints to **stderr**, and labeled JSONL goes to `--output`.

## Evaluation

`tests/test_pipeline.py` clusters simulated traffic with known ground truth (6 botnets + 45 lone scanners)
and asserts every cluster is pure and every botnet is found, with both the scikit-learn and pure-Python engines.
