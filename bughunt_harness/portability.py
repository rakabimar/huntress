"""Canonical-source personal-path guard used by doctor and release tests."""

from __future__ import annotations

import re
import os
from pathlib import Path

PERSONAL_PATH_PATTERNS = (
    re.compile(r"/home/(?!<user>|\$\{|~)[A-Za-z0-9._-]+/"),
    re.compile(r"/mnt/c/Users/[^/]+/", re.I),
    re.compile(r"(?:C:\\Users\\|C:/Users/)[^/\\]+[/\\]", re.I),
    re.compile(r"/Users/(?!<user>|\$\{)[^/]+/"),
)
ALLOWLIST = {
    "tests/test_source_sandbox.py",  # deliberate hostile-repository fixture
    "bughunt_harness/source_sandbox.py",  # fixed in-container sandbox identity
    "bughunt_harness/portability.py",  # the guard patterns themselves
    ".claude/settings.local.json",  # locally generated active-program binding
}
RELEVANT_SUFFIXES = {".py", ".md", ".toml", ".yaml", ".yml", ".json", ".sh"}


def personal_path_matches(project_root: Path) -> list[dict]:
    root = Path(project_root).resolve(); matches = []
    ignored = {".git", ".venv", "node_modules", "build", "dist", ".pytest_cache", "__pycache__"}
    paths = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in ignored and not (Path(current) / name).is_symlink()]
        paths.extend(Path(current) / name for name in files)
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in RELEVANT_SUFFIXES:
            continue
        rel = path.relative_to(root).as_posix()
        if rel in ALLOWLIST:
            continue
        try: text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError): continue
        for number, line in enumerate(text.splitlines(), 1):
            if any(pattern.search(line) for pattern in PERSONAL_PATH_PATTERNS):
                matches.append({"file": rel, "line": number})
    return matches


__all__ = ["personal_path_matches", "PERSONAL_PATH_PATTERNS"]
