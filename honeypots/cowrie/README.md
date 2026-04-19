# Cowrie honeypot (SSH)

Medium-interaction SSH honeypot based on [Cowrie](https://github.com/cowrie/cowrie). Telnet is disabled in `etc/cowrie.local.cfg` so a single port (`2222`) matches a minimal Fargate service definition.

## Local run

From this directory, with Docker Desktop running:

```powershell
docker compose up --build
```

Test (expect honeypot banner / auth flow):

```powershell
ssh -p 2222 root@127.0.0.1
```

## Fargate notes

- Map container port **2222** (TCP) in the task definition.
- Prefer **awsvpc** networking; security group should allow **2222** from the internet only if you intend a public honeypot.
- Log shipping to S3 is handled in the data-pipeline workstream (sidecar, FireLens, or scheduled upload), not in this image’s first milestone.

## Pinning the base image

For production, pin `FROM cowrie/cowrie:<tag>` to a specific digest in CI and record it in your deploy docs.
