# Cowrie SSH honeypot — sized for ECS Fargate (single primary port, non-root runtime).
# Base image: https://hub.docker.com/r/cowrie/cowrie
FROM cowrie/cowrie:latest

USER root

COPY etc/cowrie.local.cfg /cowrie/cowrie-git/etc/cowrie.local.cfg
RUN chown cowrie:cowrie /cowrie/cowrie-git/etc/cowrie.local.cfg

USER cowrie
WORKDIR /cowrie/cowrie-git

EXPOSE 2222

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',2222)); s.close()"
