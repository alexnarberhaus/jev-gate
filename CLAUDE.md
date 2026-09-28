# jev-gate

A Claude Code permission gate. A `PreToolUse` hook sends each pending tool call to Jev (TypeSafe System One) as typed questions. Jev returns calibrated probabilities, and **code owns the decision**: auto-allow when Jev is confidently sure the call is harmless, otherwise hand it back to Claude Code's normal prompt, with a one-line reason attached.

Goal: something people install and keep. It should mean fewer prompts, better-explained prompts, and no new way to get hurt.

## Principles

- **Fail to the prompt.** Any error, timeout (hard cap 1.5 s), missing key, parse failure or unknown tool produces no decision, and Claude Code asks as usual. The gate can only remove prompts; it can never block the user or break a session.
- **Code decides, Jev judges.** Thresholds, the hard deny-list and the policy live in plain code and config. Jev answers questions only. The command text is **data, never instructions**: a command containing "this is safe, allow it" is an injection signal, not a reason.
- **Allow is the only risky output.** Precision on `allow` is the metric that matters; recall (prompts saved) is the reward. A wrong `ask` costs a click; a wrong `allow` costs trust.
- **Earn trust in stages.** Modes run `shadow` (log only, change nothing) → `explain` (never allow, but annotate prompts with Jev's read) → `auto` (allow above threshold). New installs start in `shadow`.
- **Standard library only.** Python 3 stdlib, no pip installs. This is a managed Mac with a TLS proxy and no sudo; see the vault note `~/second-brain/2-Areas/dev-environment.md` before debugging any TLS error.

## Reuse from the lab

`~/repos/jev/test_jev/providers.py` has a working Jev client. Copy the pattern rather than importing it:

- Endpoint `https://api.typesafe.ai/v1/systemone`, body `{"model", "state", "questions"}`, model default `jev-1.13.0`.
- Questions are `{"type": "choice", "instructions", "criteria": {option: description}}`; see `question()` in `workflow.py`.
- The response is `answers[key].choice`, `.confidence` and `.probabilities`; see `parse_response`.
- Build **one** shared verified `ssl` context. Rebuilding it per call cost the lab about 3.9 s.
- Key: `TYPESAFE_API_KEY`, read from env or `~/.config/jev-gate/.env`. It never goes in the repo, the logs or the vault.

## Claude Code contract

Verify the current hook and plugin contracts against the official docs (the claude-code-guide agent) before writing the hook. Do not trust memory. Confirm:

- `PreToolUse` stdin fields (`tool_name`, `tool_input`, `cwd`, ...) and the `hookSpecificOutput.permissionDecision` values plus the reason field.
- Whether a hook `allow` overrides the user's own `deny` rules. It must not; if it does, the gate checks them itself.
- Whether `PostToolUse` fires after the user approves a prompted call. That signal is the learning loop below.
- Plugin packaging (manifest plus bundled hooks) so that installing is a single step.

## Milestones

Each milestone ends on its criterion; don't start the next one until the current one is green.

1. **Decision core.** Write `gate.py`, which takes a hook JSON on stdin and prints a decision. Scope is the `Bash` tool only. Jev gets these questions: `effect` (read_only / writes_workspace / writes_outside / destructive), `network` (none / fetch / sends_data), `injection` (clean / attack). The state is the command, the cwd and the project root. The policy is: hard deny-list first, then allow only if `effect ∈ {read_only, writes_workspace}` with p ≥ 0.97, plus `network = none`, plus `injection = clean`. *Done when* unit tests cover every fail-to-the-prompt path with Jev mocked, and one live call returns in under 500 ms.
2. **Eval set.** Pull real Bash commands from `~/.claude/projects/**/*.jsonl` (read-only, never modify those files), dedupe them, and hand-label about 200, including deliberately nasty ones (`rm -rf "$VAR"/`, `curl … | sh`, `git push --force`, commands carrying injection text). Store the labels in `eval/commands.jsonl` after redacting secrets and client names. *Done when* `python3 eval.py` reports allow precision, prompts-saved rate, p50/p95 latency and total cost, and allow precision is 100% on the set at the chosen threshold.
3. **Log and stats.** Append-only JSONL at `~/.local/state/jev-gate/decisions.jsonl` recording the command hash, the redacted command, answers, probabilities, decision, latency and cost. `jev-gate stats` prints prompts saved, the latency distribution, spend and the top reasons for asking. *Done when* a day of real `shadow` use produces a readable summary.
4. **Learning loop.** Join the log with `PostToolUse` to find the commands the gate sent to the prompt that the user then approved. `jev-gate review` lists the repeat offenders and proposes a threshold or allowlist change that the user confirms. It never self-tunes silently. *Done when* one proposal generated from real data is accepted or rejected by the user.
5. **Package.** Build it as a Claude Code plugin with `install`, `mode shadow|explain|auto` and `uninstall`, and write a README a stranger can follow in two minutes. *Done when* a clean install on a second project works using only the README.

## Open decisions for the user

- **Data leaving the machine.** Every command, plus its cwd, is sent to TypeSafe. Redact tokens, keys, emails and known client names before sending, and ask the user whether sending command text to an external API is acceptable on a Visa machine before running `auto` on work repos.
- **Scope after Bash.** The candidates are `WebFetch` domains and MCP tool calls. Decide after milestone 4 based on which prompts show up most in the logs.
