# Playwright MCP

The harness pins Microsoft's official `@playwright/mcp` package. Install it
with `npm install`; headed mode is the default so browser work remains visible.
Doctor also starts the MCP server and renders a localhost fixture in headless
mode as a safe health test.

At session start the harness creates:

```text
<program>/browser/<account>/profile
<program>/browser/<account>/artifacts
<program>/browser/mcp.json
```

Each enabled account receives a separate persistent profile. When the Burp
proxy is reachable, generated browser traffic uses it. Scope-derived allowed
origins are defense in depth only; the Harness Scope Engine remains
authoritative, and PreToolUse classifies navigation and consequential UI
actions.

Import the Burp CA into these dedicated research profiles. After verifying
HTTPS interception, create `<program>/browser/BURP_CA_TRUSTED`; until then deep
doctor reports a warning.
## Policy-mediated capabilities

Browser observation and mutation are separate capabilities. `browser_observe`
supports navigation followed by snapshot or screenshot. Any click, fill,
selection, key action, upload, or dialog interaction must use `browser_action`
with an enabled test account, target URL, stable element reference, declared
effect semantics, and expected effect.

The semantic classes map deterministically to policy: reversible own-test-
account mutation is R2 and may be AUTO when ROE allows state changes; third-
party communication, financial operations, credential changes, and role
changes are R3/ASK; irreversible, persistent, destructive, or non-test-account
actions are R4/DENY. UI label text is not the classifier.

Autonomous runtime MCP configuration does not register raw Playwright servers.
It exposes only the two Harness tools. Manual/debug configuration may retain
isolated raw Playwright contexts, with the lifecycle hook as defense in depth.

