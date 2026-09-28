#!/usr/bin/env python3
"""jev-gate: a PreToolUse hook that auto-allows Bash calls Jev is confident are harmless.

Reads the hook event on stdin and prints at most one JSON object. The only
decision it ever emits is "allow"; everything else is silence (plus, in some
modes, a one-line systemMessage), so Claude Code's normal permission flow runs.
Any error anywhere means silence. The gate can remove prompts, never add them.

    run(event, config, judge) -> dict | None     # the whole policy, pure enough to test
    main()                                        # stdin/stdout wrapper, never raises

Watch-only mode and already-allowed commands can't change the output, so they are
judged by a detached child (`gate.py --observe`) and Claude Code never waits on Jev.
"""

import fnmatch
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import journal  # noqa: E402
from judge import DEFAULT_MODEL, Judge, JudgeError, redact  # noqa: E402

CONFIG_DIR = Path(os.environ.get("JEV_GATE_CONFIG_DIR", Path.home() / ".config/jev-gate"))
MODES = ("shadow", "explain", "auto")
PROMPTING_PERMISSION_MODES = ("default", "acceptEdits")
MANAGED_SETTINGS = Path("/Library/Application Support/ClaudeCode")


# --- config ----------------------------------------------------------------

class Config:
    def __init__(self, mode="shadow", model=DEFAULT_MODEL, budget_s=1.5, observe_allowed=True,
                 read_only=0.85, writes_workspace=0.95, network_none=0.95, injection_clean=0.99,
                 config_dir=None):
        self.mode = mode
        self.model = model
        self.budget_s = budget_s
        self.observe_allowed = observe_allowed    # judge already-allowed commands in the background, for the log
        self.read_only = read_only                # P(read_only)
        self.writes_workspace = writes_workspace  # P(read_only) + P(writes_workspace)
        self.network_none = network_none
        self.injection_clean = injection_clean
        # Resolved at call time, not bound as a default: so tests can redirect CONFIG_DIR after import.
        self.config_dir = Path(config_dir) if config_dir is not None else CONFIG_DIR

    @classmethod
    def load(cls, config_dir=None):
        """Missing file means defaults; a malformed one raises, which fails to the prompt."""
        config = cls(config_dir=config_dir)
        path = config.config_dir / "config.json"
        raw = json.loads(path.read_text()) if path.exists() else {}
        thresholds = raw.pop("thresholds", {})
        for name, value in {**raw, **thresholds}.items():
            if name not in ("mode", "model", "budget_s", "observe_allowed", "read_only", "writes_workspace", "network_none", "injection_clean"):
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


def set_mode(mode, config_dir=None):
    """Persist mode to config.json, preserving whatever else is already in it (thresholds, etc.)."""
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; choose from {', '.join(MODES)}")
    config_dir = Path(config_dir) if config_dir is not None else CONFIG_DIR
    path = config_dir / "config.json"
    raw = json.loads(path.read_text()) if path.exists() else {}
    raw["mode"] = mode
    config_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw, indent=2) + "\n")


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


def _global_settings_path(settings_path=None):
    return Path(settings_path) if settings_path is not None else Path.home() / ".claude/settings.json"


def hook_installed(settings_path=None):
    """Whether settings.json actually registers this gate.py as a PreToolUse Bash hook."""
    this_script = str(Path(__file__).resolve())
    try:
        hooks = json.loads(_global_settings_path(settings_path).read_text()).get("hooks") or {}
    except (FileNotFoundError, ValueError):
        return False
    for group in hooks.get("PreToolUse") or []:
        if group.get("matcher") != "Bash":
            continue
        if any(this_script in (h.get("command") or "") for h in group.get("hooks") or []):
            return True
    return False


def register_hook(settings_path=None):
    """Add gate.py as a PreToolUse Bash hook. Idempotent: does nothing if already registered.

    Merges into whatever's already there rather than overwriting it — other hooks, permission
    rules, anything else in the file are left exactly as they were.
    """
    path = _global_settings_path(settings_path)
    if hook_installed(path):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.loads(path.read_text()) if path.exists() else {}
    entry = {"type": "command", "command": f"{sys.executable} {Path(__file__).resolve()}", "timeout": 5}
    pre = raw.setdefault("hooks", {}).setdefault("PreToolUse", [])
    for group in pre:
        if group.get("matcher") == "Bash":
            group.setdefault("hooks", []).append(entry)
            break
    else:
        pre.append({"matcher": "Bash", "hooks": [entry]})
    path.write_text(json.dumps(raw, indent=2) + "\n")
    return True


def unregister_hook(settings_path=None):
    """Remove gate.py's own PreToolUse hook entry, if present. Leaves everything else untouched."""
    path = _global_settings_path(settings_path)
    if not hook_installed(path):
        return False
    raw = json.loads(path.read_text())
    this_script = str(Path(__file__).resolve())
    for group in raw["hooks"]["PreToolUse"]:
        if group.get("matcher") == "Bash":
            group["hooks"] = [h for h in group.get("hooks") or [] if this_script not in (h.get("command") or "")]
    raw["hooks"]["PreToolUse"] = [g for g in raw["hooks"]["PreToolUse"] if g.get("hooks")]
    if not raw["hooks"]["PreToolUse"]:
        del raw["hooks"]["PreToolUse"]
    if not raw["hooks"]:
        del raw["hooks"]
    path.write_text(json.dumps(raw, indent=2) + "\n")
    return True


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

_SENSITIVE = (
    r"(?:~|\$HOME)/\.[^\s/]+"  # any hidden dotfile/dir directly under home: credential stores aren't a fixed list
    r"|\.(?:zsh|bash)rc\b|\.(?:bash_|z)?profile\b|\.zshenv\b|\.gitconfig\b"  # rc/profile files even without ~/
    r"|Library/LaunchAgents"
)
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
    import tempfile  # ~28 ms; only needed on the Jev path
    temps = {Path("/tmp").resolve(), Path(tempfile.gettempdir()).resolve()}
    return [str(root)] + sorted(str(t) for t in temps)


# --- policy ----------------------------------------------------------------

class Verdict:
    def __init__(self, allow, reason, rules=None, assessment=None, background=False):
        self.allow = allow
        self.reason = reason
        self.rules = rules              # what the user's own rules say: allow / ask / deny / None
        self.assessment = assessment    # judge.Assessment when Jev was consulted
        self.background = background    # the verdict can't change the output: judge it off the hot path


def judge_verdict(a, config, rules=None):
    ro = a.p("effect", "read_only")
    safe = a.p("effect", "read_only", "writes_workspace")
    net = a.p("network", "none")
    clean = a.p("injection", "clean")
    summary = f"read-only {ro:.2f}, workspace-safe {safe:.2f}, no-network {net:.2f}, clean {clean:.2f}"
    if clean < config.injection_clean:
        return Verdict(False, f"possible injection ({summary})", rules, a)
    if net < config.network_none:
        return Verdict(False, f"may use the network ({summary})", rules, a)
    if ro >= config.read_only:
        return Verdict(True, f"read-only ({summary})", rules, a)
    if safe >= config.writes_workspace:
        return Verdict(True, f"writes only the workspace ({summary})", rules, a)
    return Verdict(False, f"not confident it's harmless ({summary})", rules, a)


def evaluate(event, config, judge, deadline, observing=False):
    """The policy. Returns a Verdict, or None when the gate should stay out entirely.

    `observing` is the background pass: it ignores the user's allow rules, so we learn
    what the gate would have done for commands that never reach a prompt today.
    """
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
    if not observing and (config.mode == "shadow" or rules == "allow"):
        if rules == "allow" and not config.observe_allowed:
            return None
        return Verdict(False, "judged in the background", rules, background=True)
    if rules in ("ask", "deny"):
        return Verdict(False, f"matches your {rules} rules", rules)
    reason = deny_reason(command)
    if reason:
        return Verdict(False, f"deny-list: {reason}", rules)
    try:
        assessment = judge.assess(command, str(cwd), workspace_dirs(cwd, project_dir), deadline)
    except JudgeError as e:
        return Verdict(False, f"no verdict ({e})", rules)
    return judge_verdict(assessment, config, rules)


def render(verdict, mode):
    """Turn a verdict into hook output. Only auto mode ever emits a decision, and only 'allow'."""
    if verdict is None or verdict.background or mode == "shadow":
        return None
    if mode == "explain":
        label = "would allow" if verdict.allow else "would ask"
        return {"systemMessage": f"jev-gate: {label}: {verdict.reason}"}
    if verdict.allow:
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                       "permissionDecisionReason": f"jev-gate: {verdict.reason}"}}
    return {"systemMessage": f"jev-gate: asking: {verdict.reason}"}


def record(event, verdict, config, judge, observed):
    """Log one decision. Logging must never change a decision, so errors are swallowed."""
    try:
        command = event["tool_input"]["command"]
        terms = getattr(judge, "terms", ())
        a = verdict.assessment
        journal.append({
            "session_id": event.get("session_id"),
            "tool_use_id": event.get("tool_use_id"),
            "permission_mode": event.get("permission_mode"),
            "mode": config.mode,
            "observed": observed,
            "rules": verdict.rules,
            "decision": "allow" if verdict.allow else "ask",
            "reason": verdict.reason,
            "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
            "command": redact(command, terms),
            "cwd": redact(str(event.get("cwd") or ""), terms),
            "model": a.model if a else None,
            "probabilities": a.probabilities if a else None,
            "latency_ms": round(a.latency_ms, 1) if a else None,
            "tokens": [a.input_tokens, a.output_tokens] if a else None,
            "cost_usd": a.cost_usd if a else None,
        })
    except Exception:
        pass


def spawn_observer(event):
    """Hand the event to a detached copy of this script and return at once."""
    import subprocess
    child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--observe"],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    child.stdin.write(json.dumps(event).encode())
    child.stdin.close()


def run(event, config=None, judge=None, started=None):
    started = time.monotonic() if started is None else started
    config = config or Config.load()
    judge = judge or Judge.from_config(config.config_dir, config.model)
    verdict = evaluate(event, config, judge, started + config.budget_s)
    if verdict is None:
        return None
    if verdict.background:
        spawn_observer(event)
        return None
    record(event, verdict, config, judge, observed=False)
    return render(verdict, config.mode)


def observe(event, config=None, judge=None, started=None):
    """The background pass: judge with the same budget, log, print nothing."""
    started = time.monotonic() if started is None else started
    config = config or Config.load()
    judge = judge or Judge.from_config(config.config_dir, config.model)
    verdict = evaluate(event, config, judge, started + config.budget_s, observing=True)
    if verdict is not None:
        record(event, verdict, config, judge, observed=True)


def main(argv=None):
    started = time.monotonic()
    observing = (sys.argv[1:] if argv is None else argv) == ["--observe"]
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            return 0
        if observing:
            observe(event, started=started)
            return 0
        output = run(event, started=started)
        if output is not None:
            sys.stdout.write(json.dumps(output))
    except Exception:
        pass  # Fail to the prompt: no output, exit 0.
    return 0


if __name__ == "__main__":
    sys.exit(main())
