"""The decision log: one JSON object per line, append-only.

Every entry is already redacted by the caller; this module never sees raw
secrets and never rewrites history. Step 3 adds reading and stats here.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.environ.get("JEV_GATE_STATE_DIR", Path.home() / ".local/state/jev-gate"))


def path(state_dir=None):
    return Path(state_dir or STATE_DIR) / "decisions.jsonl"


def append(entry, state_dir=None):
    target = path(state_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **entry}, sort_keys=True)
    # One write() call on an O_APPEND file keeps concurrent hooks from interleaving lines.
    fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (line + "\n").encode())
    finally:
        os.close(fd)
