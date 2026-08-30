from __future__ import annotations

import os
from types import SimpleNamespace

from bughunt_harness.recon import detect_recon_tools


def _fake_binary(directory, name):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_python_httpx_is_rejected_then_projectdiscovery_candidate_selected(tmp_path, monkeypatch):
    python_bin = tmp_path / "python-bin"
    projectdiscovery_bin = tmp_path / "projectdiscovery-bin"
    python_httpx = _fake_binary(python_bin, "httpx")
    projectdiscovery_httpx = _fake_binary(projectdiscovery_bin, "httpx")
    monkeypatch.setenv("PATH", os.pathsep.join((str(python_bin), str(projectdiscovery_bin))))
    monkeypatch.setenv("HOME", str(tmp_path / "isolated-home"))

    def fake_run(argv, **kwargs):
        if argv[0] == str(python_httpx.resolve()):
            return SimpleNamespace(returncode=0, stdout="Usage: httpx [OPTIONS] URL\n", stderr="")
        if argv[0] == str(projectdiscovery_httpx.resolve()):
            return SimpleNamespace(
                returncode=0,
                stdout="[INF] Current Version: v1.7.0 (ProjectDiscovery)\n",
                stderr="",
            )
        raise AssertionError(f"unexpected host executable probe: {argv}")

    monkeypatch.setattr("bughunt_harness.recon.subprocess.run", fake_run)
    detected = detect_recon_tools()

    assert detected["httpx"]["installed"] is True
    assert detected["httpx"]["available"] is True
    assert detected["httpx"]["path"] == str(projectdiscovery_httpx.resolve())
    assert detected["httpx"]["candidates"][0]["path"] == str(python_httpx.resolve())
    assert detected["httpx"]["candidates"][0]["selected"] is False
    assert "rejected" in detected["httpx"]["candidates"][0]["reason"]
    assert detected["httpx"]["candidates"][1]["selected"] is True
    assert detected["subfinder"]["available"] is False


def test_projectdiscovery_httpx_is_recognized_from_isolated_path(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bin"
    httpx = _fake_binary(fake_bin, "httpx")
    monkeypatch.setenv("PATH", str(fake_bin))
    monkeypatch.setenv("HOME", str(tmp_path / "isolated-home"))
    monkeypatch.setattr(
        "bughunt_harness.recon.subprocess.run",
        lambda argv, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="[INF] Current Version: v1.7.0 (ProjectDiscovery)\n",
            stderr="",
        ),
    )

    detected = detect_recon_tools()
    assert detected["httpx"]["available"] is True
    assert detected["httpx"]["path"] == str(httpx.resolve())
    assert detected["httpx"]["note"] == ""
