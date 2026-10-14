# Machine Learning Engine

This page documents the Unsupervised Learning component of the Global Honeypot Threat Map, which groups similar hacking events together.

## Objective
Detect coordinated distributed attacks ("botnets") versus random isolated noise.

## Model Chosen: DBSCAN (Density-Based Spatial Clustering of Applications with Noise)
Why DBSCAN over K-Means?
- We do not know how many "botnets" (clusters) to expect in advance.
- DBSCAN excels at finding dense clusters and heavily penalizes random single scanners, classifying them accurately as "noise". K-Means forces every point into a cluster.

## Feature Engineering: behavioural profiles
Events are grouped per attacking IP and compared with a weighted distance (each part in `[0, 1]`):

| Component | Weight | Rationale |
|-----------|--------|-----------|
| Credential dictionary (Jaccard on `user:password` pairs) | 0.40 | Bots in one botnet ship the same wordlist |
| Payload commands (Jaccard; one side empty = 0.5) | 0.25 | Same dropper / backdoor script after login |
| SSH client version (Jaccard) | 0.15 | Same SSH library compiled into the bot |
| Behaviour ratios (login, command, success) | 0.20 | How far each attacker gets |

Geography is deliberately excluded: botnets are spread worldwide, and the map shows that spread.
DBSCAN runs with `metric="precomputed"`, `eps=0.25`, `min_samples=3`. Clusters are renumbered by event volume so ids and colours stay stable.

*(The first milestone used a 2-D `[hash(src_ip), hour]` vector. Hashing a categorical value makes unrelated IPs land near each other by chance, so clusters were essentially random. The set-overlap distance fixed this.)*

## Evaluation
On simulated traffic with ground truth (6 botnets, 118 bot IPs, 45 lone scanners) the model recovers **6/6 botnets at 100% purity** and labels all 45 lone scanners as noise. The result is stable for `eps` 0.20–0.30. See `tests/test_pipeline.py`.

## AWS Deployment Architecture
1. **AWS Lambda (`ClusterFunction`)**: pure-Python DBSCAN (`pipeline/cluster_lambda/botnet_clustering.py`), so the package needs no numpy/scipy (well under the 250 MB limit, fast cold start). scikit-learn is used when available offline.
2. **Amazon EventBridge** triggers it every 30 minutes.
3. **Execution**: queries the newest events through the `timeline-received_at` GSI (up to `CLUSTER_MAX_EVENTS`, default 5000), clusters, and writes `cluster_id` back with `UpdateItem` (unchanged rows are skipped).
4. The dashboard reads `cluster_id` from `GET /events`, colours arcs per botnet, and tags each cluster's tactic (IoT worm, malware dropper, SSH-key backdoor, …) from its top commands.

## Attack-type analysis (per session)
Botnet clustering answers *who* is coordinated. `ml/attack_analysis.py` answers *what* each attack did:

1. **Feature extraction**: behaviour tokens (no login / 1-2 / 3+ attempts, success, commands, download) plus
   tokens from every command typed (`wget`, `chmod`, `busybox`, `authorized_keys`, `cpuinfo`, ...).
2. **Supervised classification**: multinomial Naive Bayes (Laplace smoothing) trained on 50 labelled examples
   of known honeypot behaviour, covering 7 classes mapped to MITRE ATT&CK:
   Reconnaissance scan (T1595), SSH brute force (T1110.001), Credential compromise (T1078),
   System discovery (T1082), Malware download & execution (T1105, T1059.004, T1496),
   Persistence backdoor (T1098.004, T1053.003), IoT botnet propagation (Mirai-like).
   Each verdict carries a posterior confidence and the features with the largest likelihood ratio over the
   runner-up class (explainability).
3. **Unsupervised clustering**: spherical k-means on L2-normalised TF-IDF vectors; k in 2..8 chosen by the
   best silhouette score; clusters named after their dominant supervised label.
4. **Projection**: PCA (power iteration) to 2-D for the dashboard scatter plot.

| Metric (demo data) | Value |
|---|---|
| Leave-one-out accuracy on the labelled corpus | 0.92 |
| Agreement with simulator ground truth | 1.00 |
| Silhouette (k = 8) | 0.94 |
| Cluster ↔ classifier agreement | 0.98 – 0.99 |
| Runtime for ~300 sessions (pure Python) | ~0.2 s |
