#!/usr/bin/env python3
"""jev-gate: a PreToolUse hook that auto-allows Bash calls Jev is confident are harmless.

Reads the hook event on stdin and prints at most one JSON object. The only
decision it ever emits is "allow"; everything else is silence (plus, in some
modes, a one-line systemMessage), so Claude Code's normal permission flow runs.
Any error anywhere means silence. The gate can remove prompts, never add them.

    run(event, config, judge) -> dict | None     # the whole policy, pure enough to test
    main()                                        # stdin/stdout wrapper, never raises
"""

import fnmatch
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from judge import DEFAULT_MODEL, Judge, JudgeError  # noqa: E402

CONFIG_DIR = Path(os.environ.get("JEV_GATE_CONFIG_DIR", Path.home() / ".config/jev-gate"))
MODES = ("shadow", "explain", "auto")
PROMPTING_PERMISSION_MODES = ("default", "acceptEdits")
MANAGED_SETTINGS = Path("/Library/Application Support/ClaudeCode")


# --- config ----------------------------------------------------------------

@dataclass
class Config:
    mode: str = "shadow"
    model: str = DEFAULT_MODEL
    budget_s: float = 1.5
    read_only: float = 0.85         # P(read_only)
    writes_workspace: float = 0.95  # P(read_only) + P(writes_workspace)
    network_none: float = 0.95
    injection_clean: float = 0.99
    config_dir: Path = field(default=CONFIG_DIR)

    @classmethod
    def load(cls, config_dir=CONFIG_DIR):
        """Missing file means defaults; a malformed one raises, which fails to the prompt."""
        config = cls(config_dir=Path(config_dir))
        path = Path(config_dir) / "config.json"
        raw = json.loads(path.read_text()) if path.exists() else {}
        thresholds = raw.pop("thresholds", {})
        for name, value in {**raw, **thresholds}.items():
            if name not in ("mode", "model", "budget_s", "read_only", "writes_workspace", "network_none", "injection_clean"):
                raise ValueError(f"unknown config key {name}")
            setattr(config, name, value)
        if os.environ.get("JEV_GATE_MODE"):
            config.mode = os.environ["JEV_GATE_MODE"]
        if config.mode not in MODES:
            raise ValueError(f"unknown mode {config.mode}")
        for name in ("read_only", "writes_workspace", "network_none", "injection_clean"):
            value = getattr(config, name)
            if not isinstance(value, (int, float)) or not 0.5 <= value <= 1:
                raise ValueError(f"threshold {name} must be in [0.5, 1]")
        return config


# --- the user's own permission rules ---------------------------------------

def _settings_files(project_dir):
    files = [Path.home() / ".claude/settings.json",
             project_dir / ".claude/settings.json",
             project_dir / ".claude/settings.local.json",
             MANAGED_SETTINGS / "managed-settings.json"]
    managed_d = MANAGED_SETTINGS / "managed-settings.d"
    if managed_d.is_dir():
        files += sorted(managed_d.glob("*.json"))
    return files


def load_rules(project_dir):
    """Bash rule patterns per kind. An unreadable settings file raises: we can't prove there's no ask/deny rule."""
    rules = {"allow": [], "ask": [], "deny": []}
    for path in _settings_files(project_dir):
        try:
            text = path.read_text()
        except FileNotFoundError:
            continue
        permissions = json.loads(text).get("permissions") or {}
        for kind in rules:
            for rule in permissions.get(kind) or []:
                if rule == "Bash":
                    rules[kind].append("*")
                elif isinstance(rule, str) and rule.startswith("Bash(") and rule.endswith(")"):
                    rules[kind].append(rule[5:-1])
    return rules


def split_commands(command):
    """Split on && || ; | and newlines outside quotes. Approximate, which is fine: see rule_verdict."""
    parts, current, quote, i = [], [], None, 0
    while i < len(command):
        c = command[i]
        if quote:
            current.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(command):
                current.append(command[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"":
            quote = c
            current.append(c)
        elif c == "\\" and i + 1 < len(command):
            current += [c, command[i + 1]]
            i += 1
        elif c in ";|&\n":
            parts.append("".join(current))
            current = []
            while i + 1 < len(command) and command[i + 1] in "|&":
                i += 1
        else:
            current.append(c)
        i += 1
    parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _matches(pattern, command):
    if pattern.endswith(":*"):
        prefix = pattern[:-2]
        return command == prefix or command.startswith(prefix + " ")
    if "*" in pattern:
        return fnmatch.fnmatchcase(command, pattern)
    return command == pattern


def rule_verdict(command, rules):
    """'deny'/'ask' if any rule could apply, 'allow' if every part is already allowed, else None.

    Errs toward 'ask' (the gate stays out) and away from 'allow' (the gate just runs):
    a mismatch in either direction costs at most a wasted Jev call, never a wrong allow.
    """
    parts = split_commands(command) or [command]
    for kind in ("deny", "ask"):
        if any(_matches(p, c) for p in rules[kind] for c in parts + [command]):
            return kind
    if all(any(_matches(p, c) for p in rules["allow"]) for c in parts):
        return "allow"
    return None


# --- hard deny-list --------------------------------------------------------

_SENSITIVE = r"(?:\.claude\b|\.ssh\b|\.aws\b|\.gnupg\b|\.config/jev-gate|\.(?:zsh|bash)rc\b|\.(?:bash_|z)?profile\b|\.zshenv\b|\.gitconfig\b|Library/LaunchAgents)"
DENY_LIST = [
    (re.compile(r"\brm\s+(?:-[a-zA-Z]*[rR]|--recursive)"), "recursive delete"),
    (re.compile(r"\|\s*(?:sudo\s+)?(?:env\s+)?(?:/\S*/)?(?:ba|z|da|k|fi)?sh\b|\|\s*(?:sudo\s+)?(?:/\S*/)?(?:python[\d.]*|node|perl|ruby|php|osascript)\b"),
     "pipes into an interpreter"),
    (re.compile(r"(?:^|[\s;&|(`])(?:sudo|doas|su)\s"), "runs as root"),
    (re.compile(r"(?:^|[\s;&|(`])eval\b"), "uses eval"),
    (re.compile(_SENSITIVE), "touches credentials or agent/shell config"),
    (re.compile(r"\b(?:chmod|chown)\s+-[a-zA-Z]*R"), "recursive permission change"),
    (re.compile(r"\b(?:mkfs|diskutil\s+erase|dd\s+[^|]*of=)"), "writes disks"),
]


def deny_reason(command):
    for pattern, reason in DENY_LIST:
        if pattern.search(command):
            return reason
    return None


# --- workspace -------------------------------------------------------------

def _git_root(path):
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def workspace_dirs(cwd, project_dir):
    """The narrower of the cwd's git root and the project dir, plus temp dirs."""
    git_root = _git_root(cwd)
    candidates = [d for d in (git_root, project_dir) if d is not None and (cwd == d or d in cwd.parents)]
    root = max(candidates, key=lambda d: len(d.parts)) if candidates else cwd
    temps = {Path("/tmp").resolve(), Path(tempfile.gettempdir()).resolve()}
    return [str(root)] + sorted(str(t) for t in temps)


# --- policy ----------------------------------------------------------------

@dataclass
class Verdict:
    allow: bool
    reason: str
    consulted_jev: bool = False


def judge_verdict(a, config):
    ro = a.p("effect", "read_only")
    safe = a.p("effect", "read_only", "writes_workspace")
    net = a.p("network", "none")
    clean = a.p("injection", "clean")
    summary = f"read-only {ro:.2f}, workspace-safe {safe:.2f}, no-network {net:.2f}, clean {clean:.2f}"
    if clean < config.injection_clean:
        return Verdict(False, f"possible injection ({summary})", True)
    if net < config.network_none:
        return Verdict(False, f"may use the network ({summary})", True)
    if ro >= config.read_only:
        return Verdict(True, f"read-only ({summary})", True)
    if safe >= config.writes_workspace:
        return Verdict(True, f"writes only the workspace ({summary})", True)
    return Verdict(False, f"not confident it's harmless ({summary})", True)


def evaluate(event, config, judge, deadline):
    """The policy. Returns a Verdict, or None when the gate should stay out entirely."""
    if event.get("hook_event_name", "PreToolUse") != "PreToolUse" or event.get("tool_name") != "Bash":
        return None
    if event.get("permission_mode") not in PROMPTING_PERMISSION_MODES:
        return None
    command = (event.get("tool_input") or {}).get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    cwd = Path(event.get("cwd") or os.getcwd()).resolve()
    project_dir = Path(os.environ["CLAUDE_PROJECT_DIR"]).resolve() if os.environ.get("CLAUDE_PROJECT_DIR") else None

    rules = rule_verdict(command, load_rules(project_dir or _git_root(cwd) or cwd))
    if rules == "allow":
        return None  # Claude Code will allow it anyway; don't spend a call.
    if rules in ("ask", "deny"):
        return Verdict(False, f"matches your {rules} rules")
    reason = deny_reason(command)
    if reason:
        return Verdict(False, f"deny-list: {reason}")
    try:
        assessment = judge.assess(command, str(cwd), workspace_dirs(cwd, project_dir), deadline)
    except JudgeError as e:
        return Verdict(False, f"no verdict ({e})")
    return judge_verdict(assessment, config)


def render(verdict, mode):
    """Turn a verdict into hook output. Only auto mode ever emits a decision, and only 'allow'."""
    if verdict is None or mode == "shadow":
        return None
    if mode == "explain":
        label = "would allow" if verdict.allow else "would ask"
        return {"systemMessage": f"jev-gate: {label}: {verdict.reason}"}
    if verdict.allow:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                       "permissionDecisionReason": f"jev-gate: {verdict.reason}"}}
    return {"systemMessage": f"jev-gate: asking: {verdict.reason}"}


def run(event, config=None, judge=None, started=None):
    started = time.monotonic() if started is None else started
    config = config or Config.load()
    judge = judge or Judge.from_config(config.config_dir, config.model)
    verdict = evaluate(event, config, judge, started + config.budget_s)
    return render(verdict, config.mode)


def main():
    started = time.monotonic()
    try:
        event = json.loads(sys.stdin.read())
        output = run(event, started=started) if isinstance(event, dict) else None
        if output is not None:
            sys.stdout.write(json.dumps(output))
    except Exception:
        pass  # Fail to the prompt: no output, exit 0.
    return 0


if __name__ == "__main__":
    sys.exit(main())
