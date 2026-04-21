# Security, Ethics & Legal

## Ethical stance

This project is defensive research: a honeypot is designed to **observe** attacker behavior without attacking back.

## Controls and guardrails

- **No outbound attacks**: restrict egress; do not run malware.
- **Least privilege IAM**: ECS task roles only allow required S3 writes.
- **Data minimization**: store only needed fields for analysis/visualization.
- **Retention policy**: raw logs in S3 should have lifecycle policies.
- **Access control**: restrict write access to buckets/tables; avoid public data dumps.

## Privacy considerations

Captured IP addresses are personal data in many jurisdictions. Treat them as sensitive:

- avoid sharing raw IP lists publicly
- aggregate/anonymize in published results when possible
- document what is stored and for how long

## AWS-specific security

- Enable CloudTrail (account-wide)
- Consider GuardDuty for threat detection telemetry (optional)
- Use Secrets Manager / SSM for tokens (never commit)

