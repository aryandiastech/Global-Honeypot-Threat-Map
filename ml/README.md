# ML — clustering stub

`cluster_events.py` runs **DBSCAN** on a toy 2D feature space:

- `x`: stable hash of `src_ip` scaled to \([0,1]\)
- `y`: hour-of-day from `received_at` / `sensor_timestamp` / `timestamp` scaled to \([0,1]\)

## Install

```powershell
python -m pip install -r ml/requirements.txt
```

## Run (fixture)

```powershell
python ml/cluster_events.py --input pipeline/fixtures/sample_cowrie_lines.jsonl --output ml/out-labeled.jsonl
```

Metadata prints to **stderr**; labeled JSONL prints to **stdout** (or `--output`).

## Next steps for the full “botnet” story

- Engineer higher-signal features (ASN, user/password entropy, command sequences).
- Run on a scheduled basis (EventBridge + Fargate task or SageMaker Processing).
- Persist `cluster_id` back to DynamoDB or a side table for the dashboard.
