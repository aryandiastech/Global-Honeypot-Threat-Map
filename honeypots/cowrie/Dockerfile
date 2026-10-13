# Cowrie SSH honeypot — Fargate-friendly (single port 2222).
# Base image: https://hub.docker.com/r/cowrie/cowrie
#
# The upstream runtime is distroless (no /bin/sh, no chown, no pip), so:
#   - files are baked with COPY --chmod (no ownership change needed),
#   - boto3 for the log shipper is installed in a separate build stage and copied in,
#   - the entrypoint is a Python launcher instead of a shell script.

# Pure-Python deps for the S3 log shipper (boto3 + botocore have no compiled parts).
FROM python:3.13-slim AS shipper-deps
RUN pip install --no-cache-dir --target /opt/shipper-deps "boto3>=1.34,<2"

FROM cowrie/cowrie:latest

COPY --from=shipper-deps /opt/shipper-deps /opt/shipper-deps

# World-readable config so the `cowrie` process can read it without chown.
COPY --chmod=0644 etc/cowrie.local.cfg /cowrie/cowrie-git/etc/cowrie.local.cfg
COPY --chmod=0755 log_shipper.py /cowrie/cowrie-git/log_shipper.py
COPY --chmod=0755 entrypoint.py /cowrie/cowrie-git/entrypoint.py

USER 999:999
WORKDIR /cowrie/cowrie-git

EXPOSE 2222

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD ["/cowrie/cowrie-env/bin/python3", "-c", "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',2222)); s.close()"]

ENTRYPOINT ["/cowrie/cowrie-env/bin/python3", "/cowrie/cowrie-git/entrypoint.py"]
# Same as upstream: log to stdout (CloudWatch on ECS) — the JSON event log is still
# written to var/log/cowrie/cowrie.json by Cowrie's jsonlog output plugin.
CMD ["/cowrie/cowrie-env/bin/twistd", "-n", "--umask=0022", "--pidfile=", "--logger", "cowrie.python.logfile.stdoutLogger", "cowrie"]
