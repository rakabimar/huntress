# Agent specs (specialist stances)

Canonical, runtime-agnostic specialist definitions live in `agent-specs/*.md`.
`harness sync` renders them into each runtime's native agent format:

| Runtime | Output |
|---|---|
| Claude Code | `.claude/agents/<name>.md` |
| Codex | `.codex/agents/<name>.md` |
| OpenCode | `.opencode/agent/<name>.md` |

## The eight specialists

| Spec | Stance | Owns |
|---|---|---|
| `recon-observer` | Recon/Observer | What surface exists? |
| `hypothesis-architect` | Hypothesis | Falsifiable cause→effect claims |
| `attacker` | Attacker | Where would I break it? |
| `defender` | Defender | How would I fix/defend it? |
| `triager` | Triager | Would a platform pay for this? |
| `validator` | Validator | Can I disprove this candidate? |
| `reporter` | Reporter | Is this writable as a creditable report? |
| `researcher` | Orchestrator | Runs the loop end-to-end |

## Anatomy

```markdown
---
name: attacker
description: Break the in-scope surface using the skill library; record hypotheses.
---

# Attacker

## Prime directives
…inline reminder of scope/policy/isolation rules…

## Process
…

## Outputs
…

## Stop conditions
…
```

Agent specs intentionally omit `tools:`/`model:` in frontmatter so the generated
agent inherits full tool access and the session model. Each spec re-states the
prime directives and stop conditions inline, so a dispatched specialist never
loses the guardrails even when its parent context is thin.