"""The decision log: one JSON object per line, append-only.

Every entry is already redacted by the caller; this module never sees raw
secrets and never rewrites history.

    append(entry)                 # write one decision (gate.py's job)
    tail_lines(path, n)            # last n raw lines, cheaply
    follow(path)                   # yield new lines as they're appended, like `tail -f`
    format_entry(entry)             # one decision, human-readable

    python3 journal.py             # watch the log live in the terminal
"""

import argparse
import collections
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.environ.get("JEV_GATE_STATE_DIR", Path.home() / ".local/state/jev-gate"))
POLL_S = 0.3


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


# --- reading, live and otherwise -------------------------------------------

def tail_lines(target, n):
    """The last n non-blank lines, read in one pass so the file is never fully loaded."""
    if not target.exists():
        return []
    keep = collections.deque(maxlen=n)
    with target.open() as f:
        for line in f:
            line = line.strip()
            if line:
                keep.append(line)
    return list(keep)


def follow(target, poll_s=POLL_S):
    """Yield each new line appended to target, forever. Blocks between polls; Ctrl+C to stop.

    Skips content that predates the call: if target already exists, starts at its current end.
    If target doesn't exist yet, waits for it, then yields everything it's created with — that
    content didn't exist when follow() was called either, so it counts as new.

    If the file shrinks (rotated or cleared under us), re-opens from the start rather than
    blocking on a position that no longer exists.
    """
    resume_at_end = target.exists()
    while not target.exists():
        time.sleep(poll_s)
    f = target.open()
    if resume_at_end:
        f.seek(0, os.SEEK_END)
    try:
        while True:
            line = f.readline()
            if line:
                if line.strip():
                    yield line.strip()
                continue
            time.sleep(poll_s)
            try:
                if target.stat().st_size < f.tell():
                    f.close()
                    f = target.open()
            except FileNotFoundError:
                pass
    finally:
        f.close()


_DIM = "\033[2m"
_RESET = "\033[0m"
_TAGS = {"allow": ("ALLOW", "\033[1;32m"), "ask": ("ASK  ", "\033[1;33m")}


def format_entry(entry, color=True):
    """One decision as a two-line, human-readable block."""
    ts = (entry.get("ts") or "")[11:19] or "?"
    tag, bold = _TAGS.get(entry.get("decision"), (str(entry.get("decision", "?")).upper().ljust(5), "\033[1;31m"))
    command = entry.get("command") or ""
    if len(command) > 140:
        command = command[:140] + "…"

    bits = [entry.get("reason") or ""]
    if entry.get("latency_ms") is not None:
        bits.append(f"{entry['latency_ms']:.0f} ms")
    if entry.get("cost_usd"):
        bits.append(f"${entry['cost_usd']:.6f}")
    if entry.get("observed"):
        bits.append("background: didn't change what you saw")
    detail = " · ".join(b for b in bits if b)

    if color:
        return f"{_DIM}{ts}{_RESET}  {bold}{tag}{_RESET}  {command}\n         {_DIM}{detail}{_RESET}"
    return f"{ts}  {tag}  {command}\n         {detail}"


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Watch jev-gate's decisions on this machine, live and human-readable.")
    parser.add_argument("-n", "--lines", type=int, default=20, help="how many recent decisions to show first (default 20)")
    parser.add_argument("--no-follow", action="store_true", help="print recent decisions and exit; don't wait for new ones")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    target = path()
    color = sys.stdout.isatty() and not args.no_color

    def show(raw_line):
        try:
            print(format_entry(json.loads(raw_line), color))
        except (ValueError, KeyError):
            pass  # a malformed line is a log bug, not a reason to crash the viewer

    for raw_line in tail_lines(target, args.lines):
        show(raw_line)
    if args.no_follow:
        return 0

    print(f"\n{_DIM if color else ''}--- watching {target} — Ctrl+C to stop ---{_RESET if color else ''}\n", file=sys.stderr)
    try:
        for raw_line in follow(target):
            show(raw_line)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
