#!/usr/bin/env python3
"""
Container entrypoint for the Cowrie honeypot.

The upstream cowrie/cowrie image runs on a distroless base (no /bin/sh), so a
shell wrapper cannot be used. This launcher:

  1. starts the S3 log shipper in a background thread (only if S3_RAW_LOG_BUCKET is set),
  2. runs Cowrie (the CMD arguments) as a child process,
  3. forwards SIGTERM/SIGINT so ECS / docker stop shut Cowrie down cleanly.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading

# boto3 is vendored into this directory at image build time (see Dockerfile).
SHIPPER_DEPS = "/opt/shipper-deps"


def _start_shipper() -> None:
    if not os.environ.get("S3_RAW_LOG_BUCKET"):
        print("[entrypoint] S3_RAW_LOG_BUCKET not set; log shipping disabled (local mode).", flush=True)
        return
    if os.path.isdir(SHIPPER_DEPS):
        sys.path.insert(0, SHIPPER_DEPS)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import log_shipper  # noqa: PLC0415 — imported lazily so boto3 is only needed when shipping

    threading.Thread(target=log_shipper.main, name="log-shipper", daemon=True).start()


def main() -> int:
    cmd = sys.argv[1:]
    if not cmd:
        print("[entrypoint] no command given", file=sys.stderr)
        return 2

    _start_shipper()

    print("[entrypoint] starting Cowrie:", " ".join(cmd), flush=True)
    child = subprocess.Popen(cmd)

    def _forward(signum: int, _frame: object) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)
    return child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
