from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from bughunt_harness.portability import personal_path_matches


def test_no_personal_paths_in_canonical_source():
    root = Path(__file__).resolve().parents[1]
    assert personal_path_matches(root) == []


def test_random_path_with_spaces_init_sync_doctor(tmp_path):
    source = Path(__file__).resolve().parents[1]
    destination = tmp_path / "bughunt portability random path"
    shutil.copytree(
        source, destination,
        ignore=shutil.ignore_patterns(".git", ".venv", "node_modules", "build", "dist", ".pytest_cache", "*.pyc", "__pycache__"),
    )
    env = dict(os.environ)
    env["BUGHUNT_HOME"] = str(tmp_path / "alternate bughunt home")
    env["BUGHUNT_BURP_PROXY"] = "disabled"
    env.pop("BUGHUNT_PROJECT_ROOT", None)
    for args in (["init"], ["sync"], ["doctor"]):
        result = subprocess.run([str(destination / "harness"), *args], cwd=destination, env=env, text=True, capture_output=True, timeout=90)
        assert result.returncode == 0, result.stderr + result.stdout
    for relative in (".mcp.json", ".codex/config.toml", ".claude/settings.json", "opencode.json"):
        text = (destination / relative).read_text(encoding="utf-8")
        assert str(source) not in text
        assert "/home/rakabimar" not in text
    assert (tmp_path / "alternate bughunt home" / "registry.db").is_file()
