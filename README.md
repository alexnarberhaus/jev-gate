# jev-gate

A Claude Code permission gate. A `PreToolUse` hook sends each pending Bash call to Jev (TypeSafe System One) as typed questions. Jev returns calibrated probabilities, and **code — never Jev — owns the decision**: auto-allow when Jev is confidently sure the call is harmless, otherwise the call falls through to Claude Code's normal prompt, with a one-line reason attached.

It can only remove prompts, never add or block them. New installs start in `shadow` mode, watching and logging without changing anything, until you decide otherwise.

## Install

One line, no separate clone step to think about:
```
git clone https://github.com/alexnarberhaus/jev-gate.git ~/repos/jev-gate && python3 ~/repos/jev-gate/jev-gate install
```

This will:
- ask for your TypeSafe API key (input hidden) and write it to `~/.config/jev-gate/.env`, readable only by you — skip it and add the key later if you don't have one yet; without it, the gate just fails safely to the normal prompt
- symlink `jev-gate` into `~/.local/bin` so it works as a bare command (add that to your `PATH` if the installer says it isn't already)
- register the `PreToolUse` hook in `~/.claude/settings.json`, merging into whatever's already there — your existing hooks and permission rules are left untouched
- default to `shadow` mode

Check it worked:
```
jev-gate status
```

**Requirements:** macOS or Linux, Python 3 (standard library only — nothing to `pip install`), and a writable `~/.claude/settings.json`.

**On a managed Mac behind a TLS-inspecting proxy**, `git clone https://...` may fail with `SSL certificate problem: unable to get local issuer certificate`. Point git at the proxy's CA bundle for just this command:
```
GIT_SSL_CAINFO=~/.claude/claude-installer/cacerts.pem git clone https://github.com/alexnarberhaus/jev-gate.git ~/repos/jev-gate && python3 ~/repos/jev-gate/jev-gate install
```
(adjust the path if your proxy's CA bundle lives elsewhere).

## Watching it live

```
jev-gate
```
Shows the last few decisions, then streams new ones as they happen — command, decision, and Jev's reasoning. While it's running, one keypress (no Enter) changes the mode:

- `s` — **shadow**: log only, change nothing
- `e` — **explain**: annotate prompts with Jev's read, never auto-approve
- `a` — **auto**: auto-approve calls Jev is confident are harmless
- `q` or Ctrl+C — quit

## Other commands

```
jev-gate status              # is the hook installed, which mode, is the log moving
jev-gate mode                # show the current mode
jev-gate mode auto           # change it without opening the live view
jev-gate watch -n 50         # show more history before following
jev-gate watch --no-follow   # one-shot dump, no live tail
jev-gate uninstall           # remove the hook and the PATH symlink; keeps your config and log
```

## How it decides

For each Bash call, in order:
1. **Hard deny-list.** Recursive deletes, `sudo`/`eval`, piping into an interpreter, disk-writing commands, and anything touching a hidden dotfile directly under your home directory (`~/.ssh`, `~/.aws`, `~/.codex`, `~/.npmrc`, shell rc files, etc.) always fall through to the normal prompt. This never asks Jev, and it never blocks you outright — it just doesn't skip the prompt.
2. **Jev, on three questions:** whether the command's effect is read-only, workspace-only, or wider; whether it touches the network at all; whether the command text itself is clean or looks aimed at the reviewer (an injection attempt). The command text is treated strictly as data to judge, never as instructions.
3. **Tiered thresholds** (in `~/.config/jev-gate/config.json`, tunable): a read-only call needs `P(read_only) ≥ 0.85`; a call that only writes inside the project or a temp directory needs `P(read_only)+P(writes_workspace) ≥ 0.95`. Either way, `P(network=none) ≥ 0.95` and `P(injection=clean) ≥ 0.99` are also required. Anything short of that falls through to the normal prompt.

Only `allow` is ever emitted as an actual decision — the gate can lower the number of prompts you see, never raise it. In `shadow` mode, and for any command your own settings already allow, the judging happens in a detached background process so Claude Code never waits on it.

## Redacting private terms

Every command sent to Jev is redacted first: known secret/token/key/email shapes are stripped automatically. Client or company names aren't — add them yourself, one per line, in:
```
~/.config/jev-gate/redact.txt
```
They're matched on word boundaries (so `ING` won't also redact "settings").

## Data leaving your machine

Each judged command, its cwd, and its workspace paths are sent to TypeSafe's API, after redaction. Nothing else about your session is sent. If that's not acceptable for a given machine or repo, don't install the hook there.

## Measuring it against real commands

`eval.py` applies the exact same policy to a hand-labelled set of real and adversarial commands (`eval/commands.jsonl`) and reports allow precision, prompts-saved rate, latency, and cost:
```
python3 eval.py            # report at the configured thresholds
python3 eval.py --sweep    # search for looser thresholds that still hit 100% precision
```
Jev's assessments are cached (`eval/cache.json`), so re-running costs nothing until you add new cases or change the model.

## Development

```
python3 -m unittest discover -s tests -q
```
Pure stdlib, no test dependencies. See `CLAUDE.md` for the full design brief and milestones.

## Uninstall

```
jev-gate uninstall
```
Removes the `PreToolUse` hook and the `~/.local/bin` symlink. Leaves `~/.config/jev-gate` (key, redact list, thresholds) and `~/.local/state/jev-gate` (the decision log) in place in case you reinstall — delete them yourself if you want them gone for good.
