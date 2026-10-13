# Cowrie honeypot (SSH)

Medium-interaction SSH honeypot based on [Cowrie](https://github.com/cowrie/cowrie). Telnet is disabled in `etc/cowrie.local.cfg` so a single port (`2222`) matches a minimal Fargate service definition.

## Local run

From this directory, with Docker Desktop running:

```powershell
docker compose build
docker compose up
```

The compose file bind-mounts `etc/cowrie.local.cfg` into the container so your config is always applied (and editable without rebuilding). The Dockerfile still bakes a copy for Fargate-style runs without a bind mount.

If `docker compose build` errors on `COPY --chmod`, enable BuildKit (Docker Desktop does by default) or run: `set DOCKER_BUILDKIT=1` in classic cmd.

Test (expect honeypot banner / auth flow):

```powershell
ssh -p 2222 root@127.0.0.1
```

## Fargate notes

- Map container port **2222** (TCP) in the task definition.
- Prefer **awsvpc** networking; security group should allow **2222** from the internet only if you intend a public honeypot.
- Log shipping: set `S3_RAW_LOG_BUCKET` on the task and `entrypoint.py` starts `log_shipper.py`, which uploads new `cowrie.json` lines to S3 every `SHIPPER_INTERVAL_SEC` (default 60). The S3 upload triggers the ingest Lambda.

## How the entrypoint works

The upstream image is **distroless** (no `/bin/sh`), so the container starts `entrypoint.py` with Cowrie's own Python. It launches the log shipper thread (only when a bucket is configured), runs Cowrie as a child process and forwards `SIGTERM`. `boto3` is installed in a separate build stage and copied to `/opt/shipper-deps`.

## Live demo without AWS

`docker compose up` writes `cowrie.json` into `./logs/`. Run the local demo backend with `--cowrie-log` (see `DEMO.md` in the repo root) and every SSH attempt against port 2222 appears on the dashboard within seconds.

## Pinning the base image

For production, pin `FROM cowrie/cowrie:<tag>` to a specific digest in CI and record it in your deploy docs.
