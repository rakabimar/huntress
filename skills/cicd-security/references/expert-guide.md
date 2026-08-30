# Expert guide

## Mental model
Model event actor/input → workflow trigger/context → permissions/secrets/OIDC → checkout/artifact/cache → shell/action execution → environment/release. Pull requests, pull_request_target, workflow_run, reusable workflows, and deployment events have different trust.

## Attack surface
Review untrusted interpolation into shell, privileged trigger plus attacker checkout, write permissions, secret inheritance, artifact replacement, cache restore/save, release upload, environment approvals, OIDC subject/audience trust, unpinned third-party actions, and self-hosted runner exposure.

## Methodology and decision tree
Pin workflow commit; identify trigger and attacker influence; compute token/secret/environment privileges; trace untrusted fields to shell/action/checkout/artifact/cache; prove capability statically with exact YAML and platform semantics. Create a Lead, never run a workflow.
