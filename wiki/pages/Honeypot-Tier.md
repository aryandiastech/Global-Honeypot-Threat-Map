# Honeypot Tier (Cowrie SSH)

## Why Cowrie

Cowrie is a widely used **medium-interaction** SSH/Telnet honeypot that records:

- connection attempts
- authentication failures/successes
- basic session activity (depending on config)

For the first deployment, we run **SSH only** (Telnet disabled) to keep the network surface minimal and align with a simple Fargate service.

## Containerization choices

- Base image: `cowrie/cowrie`
- Container port: **2222**
- Config path inside image: `/cowrie/cowrie-git/etc`

Our repo image wrapper is at `honeypots/cowrie/` and includes:

- `Dockerfile` (Fargate-friendly, avoids `chown`)
- `docker-compose.yml` for local testing
- `etc/cowrie.local.cfg` for overrides (Telnet disabled)

## Local test

```powershell
cd honeypots/cowrie
docker compose build
docker compose up
ssh -p 2222 root@127.0.0.1
```

## Notes on config mounting

Cowrie’s Docker docs note that mounting `/cowrie/cowrie-git/etc` hides files in the image, so you must ensure needed config files exist in the mounted directory.

Reference: Cowrie Docker repository docs `https://docs.cowrie.org/en/latest/docker/README.html`

