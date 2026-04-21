# Cowrie SSH honeypot — Fargate-friendly (single port 2222).
# Base image: https://hub.docker.com/r/cowrie/cowrie
#
# Do not use `RUN chown` here: upstream uses a minimal runtime where chown/sh
# may be missing, and `/cowrie/cowrie-git/etc` is a declared VOLUME (bake files
# with COPY + permissions only; use --chmod so no ownership change is needed).
FROM cowrie/cowrie:latest

# BuildKit: world-readable config so the `cowrie` process can read it without chown.
COPY --chmod=0644 etc/cowrie.local.cfg /cowrie/cowrie-git/etc/cowrie.local.cfg

USER cowrie
WORKDIR /cowrie/cowrie-git

COPY --chmod=0755 log_shipper.py /cowrie/cowrie-git/log_shipper.py
COPY --chmod=0755 start.sh /cowrie/cowrie-git/start.sh

EXPOSE 2222

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD ["/cowrie/cowrie-env/bin/python3", "-c", "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',2222)); s.close()"]

ENTRYPOINT ["/cowrie/cowrie-git/start.sh"]
CMD ["/cowrie/cowrie-env/bin/twistd", "-n", "-l", "var/log/cowrie/cowrie.log", "cowrie"]
