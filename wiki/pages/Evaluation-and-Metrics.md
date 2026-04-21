# Evaluation & Metrics

## What we measure

### Honeypot capture

- events/day per region
- unique attacker IPs/day
- top `cowrie_eventid` frequencies
- time-to-first-attack after deployment

### Pipeline reliability

- ingest Lambda success rate
- average ingest latency (S3 upload → DynamoDB item)
- DynamoDB throttles / hot partitions

### Dashboard usefulness

- time-to-load
- refresh latency / update frequency
- operator feedback: can a user identify a burst/campaign quickly?

### ML quality (unsupervised)

Because there are no labels, evaluation uses proxies:

- cluster stability over time
- silhouette score / Davies–Bouldin (when applicable)
- manual inspection of representative samples per cluster
- correlation with external intel (when enabled)

## Experimental protocol (recommended)

- Deploy in both regions for at least 7–14 days.
- Use a fixed retention period and stable config.
- Record versions (Cowrie image digest, Lambda code hash).

## Limitations

- attacker behavior changes rapidly
- NAT/proxies can blur IP identity
- unsupervised clusters require careful interpretation

