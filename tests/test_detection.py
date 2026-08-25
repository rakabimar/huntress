"""Runtime tooling detection tests (P1): Burp + browser/Playwright.

Detection must be *genuine* — driven by PATH/env/importability, never a
hardcoded "detected".  These tests inject fake ``which`` / env / spec results so
they never depend on the real machine.
"""

from bughunt_harness.detection import detect_browser, detect_burp


def test_burp_detected_via_binary():
    which = lambda name: "/opt/burpsuite" if name == "burpsuite" else None
    r = detect_burp(env={}, which=which)
    assert r["detected"] is True
    assert r["binary"] == "/opt/burpsuite"
    assert r["proxy_env_set"] is False


def test_burp_detected_via_proxy_env():
    r = detect_burp(env={"BUGHUNT_BURP_PROXY": "http://127.0.0.1:8080"}, which=lambda n: None)
    assert r["detected"] is True
    assert r["proxy_env_set"] is True
    assert r["binary"] is None


def test_burp_not_detected_when_absent():
    r = detect_burp(env={}, which=lambda n: None)
    assert r["detected"] is False
    assert r["binary"] is None
    assert r["proxy_env_set"] is False


def test_browser_not_detected_when_nothing_present(monkeypatch):
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    r = detect_browser(which=lambda n: None)
    assert r["detected"] is False
    assert r["python_module"] is False


def test_browser_detected_via_node_npx():
    def which(name):
        return "/usr/bin/node" if name == "node" else ("/usr/bin/npx" if name == "npx" else None)

    r = detect_browser(which=which)
    assert r["detected"] is True
    assert r["node"] is True and r["npx"] is True


def test_browser_detected_via_python_module(monkeypatch):
    monkeypatch.setattr("importlib.util.find_spec", lambda name: object() if name == "playwright" else None)
    r = detect_browser(which=lambda n: None)
    assert r["detected"] is True
    assert r["python_module"] is True