#!/usr/bin/env bash
set -euo pipefail

# Produce a reproducible source archive from tracked and intentional untracked
# source files while honoring .gitignore. Runtime state is never copied.
repo_root="$(git rev-parse --show-toplevel)"
output="${1:-$repo_root/dist/bughunt-harness-source.tar.gz}"
mkdir -p "$(dirname "$output")"

file_list="$(mktemp)"
trap 'rm -f "$file_list"' EXIT
git -C "$repo_root" ls-files --cached --others --exclude-standard -z \
  | sort -z > "$file_list"

tar -czf "$output" --directory="$repo_root" \
  --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
  --exclude='.git' --exclude='node_modules' --exclude='__pycache__' \
  --exclude='.pytest_cache' --exclude='*.egg-info' \
  --exclude='.claude' --exclude='.codex' --exclude='.opencode' \
  --exclude='.mcp.json' --exclude='opencode.json' \
  --exclude='AGENTS.md' --exclude='CLAUDE.md' \
  --exclude='.claude/settings.local.json' --exclude='*.db' \
  --exclude='browser' --exclude='burp' --exclude='evidence' --exclude='reports' \
  --null --files-from="$file_list"

printf '%s\n' "$output"
