#!/usr/bin/env bash
# One-shot environment bootstrap (spec §100).
#
#   ./scripts/bootstrap.sh
#
# Creates a local venv, installs the harness + dependencies, and runs the
# readiness check.  Safe to re-run (idempotent).  No external network testing
# is performed — only package installation and local self-checks.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

PY="${PYTHON:-python3}"

echo "==> Python: $("$PY" --version 2>&1)"

if [ ! -d ".venv" ]; then
  echo "==> Creating venv"
  "$PY" -m venv .venv
fi

VENV_PY="$HERE/.venv/bin/python"
echo "==> Installing dependencies (editable, full extras)"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install -e '.[full]'

if command -v npm >/dev/null 2>&1; then
  echo "==> Installing pinned official Playwright MCP package"
  npm install --ignore-scripts
else
  echo "==> npm not found; Playwright MCP will remain unavailable"
fi

echo "==> Generating runtime configuration"
"$HERE/harness" init
"$HERE/harness" sync

echo "==> Verifying runtime binaries"
for bin in claude codex opencode burpsuite; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf "  - %-10s %s\n" "$bin" "$(command -v "$bin")"
  else
    printf "  - %-10s %s\n" "$bin" "(not found — optional)"
  fi
done

echo "==> Running doctor (global environment/core readiness)"
"$HERE/harness" doctor

echo
echo "Bootstrap complete. Next steps:"
echo "  1. ./harness program create <slug> --name '<display name>' [--platform hackerone]"
echo "  2. edit ~/.bughunt/programs/<slug>/{scope,roe}.yaml and set an authorized target"
echo "  3. ./harness engagement validate -p <slug>"
echo "  4. ./harness start claude -p <slug>   # or codex / opencode"
