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
import shutil
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


def count_and_last(target):
    """One pass over the log: (total non-blank lines, last non-blank line or None)."""
    if not target.exists():
        return 0, None
    count, last = 0, None
    with target.open() as f:
        for line in f:
            line = line.strip()
            if line:
                count += 1
                last = line
    return count, last


def relative_time(iso_ts):
    """'3m ago'-style rendering of one of our own timestamps. 'unknown' for anything else."""
    try:
        ts = datetime.fromisoformat(iso_ts)
    except (ValueError, TypeError):
        return "unknown"
    seconds = (datetime.now(timezone.utc) - ts).total_seconds()
    for cutoff, unit, size in ((60, "s", 1), (3600, "m", 60), (86400, "h", 3600), (float("inf"), "d", 86400)):
        if seconds < cutoff:
            return f"{max(0, int(seconds / size))}{unit} ago"


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
_BOLD = "\033[1m"
_META = "\033[36m"
_TAGS = {"allow": ("ALLOW", "✓", "\033[1;32m"), "ask": ("ASK  ", "?", "\033[1;33m")}
_UNKNOWN_COLOR = "\033[1;31m"


def format_entry(entry, color=True, width=None):
    """One decision as a small card: accent bar + icon/tag + bold command with the timestamp
    right-aligned, then one detail line — the reason dimmed, latency/cost picked out in a
    distinct accent so the eye can scan for cost and speed without reading the whole reason.

    `width` overrides the detected terminal width — mainly so tests don't depend on the
    real terminal they happen to run in.
    """
    width = width if width is not None else shutil.get_terminal_size(fallback=(100, 24)).columns
    ts = (entry.get("ts") or "")[11:19] or "?"
    tag, icon, accent = _TAGS.get(entry.get("decision"), (str(entry.get("decision", "?")).upper().ljust(5), "!", _UNKNOWN_COLOR))
    command = entry.get("command") or ""
    if len(command) > 120:
        command = command[:120] + "…"

    reason = entry.get("reason") or ""
    meta_bits = []
    if entry.get("latency_ms") is not None:
        meta_bits.append(f"{entry['latency_ms']:.0f} ms")
    if entry.get("cost_usd"):
        meta_bits.append(f"${entry['cost_usd']:.6f}")
    if entry.get("observed"):
        meta_bits.append("background — didn't change what you saw")

    plain_head = f"▎ {icon} {tag}  {command}"
    pad = " " * max(1, width - len(plain_head) - len(ts) - 1)
    if color:
        head = f"{accent}▎{_RESET} {accent}{icon} {tag}{_RESET}  {_BOLD}{command}{_RESET}{pad}{_DIM}{ts}{_RESET}"
        segments = ([(_DIM, reason)] if reason else []) + [(_META, b) for b in meta_bits]
        detail = f"{_DIM} · {_RESET}".join(f"{c}{text}{_RESET}" for c, text in segments)
    else:
        head = f"{plain_head}{pad}{ts}"
        detail = " · ".join([reason] + meta_bits if reason else meta_bits)
    return "\n".join([head, f"  {detail}"] if detail else [head])


# --- the watch loop, shared by this module's own CLI and jev-gate's --------

def watch(n=20, follow_after=True, color=True, target=None, on_start=None):
    """Run on_start (if given), then print the last n decisions, then (if follow_after) keep
    printing new ones until Ctrl+C. Everything log-shaped comes after the banner, never before it.

    Prints a one-line allow/ask summary for what it saw while following.
    """
    target = target or path()

    def show(raw_line):
        try:
            entry = json.loads(raw_line)
        except ValueError:
            return None
        print(format_entry(entry, color))
        print()
        return entry.get("decision")

    if follow_after and on_start:
        on_start()  # a one-shot dump (follow_after=False) skips the banner: there's nothing to watch
    for raw_line in tail_lines(target, n):
        show(raw_line)
    if not follow_after:
        return

    seen = collections.Counter()
    try:
        for raw_line in follow(target):
            decision = show(raw_line)
            if decision:
                seen[decision] += 1
    except KeyboardInterrupt:
        pass
    if seen:
        line = f"--- {seen.get('allow', 0)} allowed, {seen.get('ask', 0)} asked while watching ---"
        print(f"\n{_DIM}{line}{_RESET}" if color else f"\n{line}")


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Watch jev-gate's decisions on this machine, live and human-readable.")
    parser.add_argument("-n", "--lines", type=int, default=20, help="how many recent decisions to show first (default 20)")
    parser.add_argument("--no-follow", action="store_true", help="print recent decisions and exit; don't wait for new ones")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)
    color = sys.stdout.isatty() and not args.no_color

    def on_start():
        print(f"\n{_DIM}--- watching {path()} — Ctrl+C to stop ---{_RESET}\n" if color
              else f"\n--- watching {path()} — Ctrl+C to stop ---\n", file=sys.stderr)

    watch(n=args.lines, follow_after=not args.no_follow, color=color, on_start=on_start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
