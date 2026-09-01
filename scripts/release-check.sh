#!/usr/bin/env bash
set -euo pipefail

release_root="$(git rev-parse --show-toplevel)"
cd "$release_root"

if [ -n "$(git status --porcelain)" ]; then
  echo "release check requires a clean Git checkout" >&2
  exit 2
fi

python_bin="${PYTHON:-python3}"
package_version="$($python_bin -c 'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')"
runtime_version="$($python_bin -c 'import bughunt_harness; print(bughunt_harness.__version__)')"
node_version="$($python_bin -c 'import json; print(json.load(open("package.json"))["version"])')"
lock_version="$($python_bin -c 'import json; print(json.load(open("package-lock.json"))["version"])')"
mcp_version="$($python_bin -c 'from bughunt_harness.mcp.server import _make_mcp; print(_make_mcp()._mcp_server.version)')"
"$python_bin" -c 'from pathlib import Path; from bughunt_harness.portability import personal_path_matches; matches=personal_path_matches(Path.cwd()); assert not matches, matches'
if [ "$package_version" != "$runtime_version" ] || [ "$package_version" != "$node_version" ] || [ "$package_version" != "$lock_version" ] || [ "$package_version" != "$mcp_version" ]; then
  echo "version mismatch: package=$package_version runtime=$runtime_version node=$node_version lock=$lock_version mcp=$mcp_version" >&2
  exit 2
fi

release_tmp="$(mktemp -d)"
trap 'rm -rf "$release_tmp"' EXIT
"$python_bin" -m venv "$release_tmp/venv"
release_python="$release_tmp/venv/bin/python"
"$release_python" -m pip install --upgrade pip
"$release_python" -m pip install '.[full]'
"$release_python" -m pytest -m 'unit or integration_local' -ra
"$release_python" -m build --sdist --outdir "$release_tmp/dist"

artifact="$release_tmp/dist/bughunt_harness-$package_version.tar.gz"
test -f "$artifact"
sha256sum "$artifact" | tee "$release_tmp/dist/SHA256SUMS"
tar -tzf "$artifact" | grep -Eq '(^|/)bughunt_harness/'
if tar -tzf "$artifact" | grep -Eq '^[^/]+/(\.git|node_modules|browser|burp|state|evidence|reports|\.pytest_cache)(/|$)|\.(db|sqlite3?)$'; then
  echo "source distribution contains a forbidden runtime artifact" >&2
  exit 2
fi

mkdir "$release_tmp/extracted"
tar -xzf "$artifact" -C "$release_tmp/extracted"
"$python_bin" -m venv "$release_tmp/reinstall"
reinstall_python="$release_tmp/reinstall/bin/python"
"$reinstall_python" -m pip install "$artifact[full]"
(
  cd "$release_tmp"
  BUGHUNT_EXPECTED_RELEASE_VERSION="$package_version" "$reinstall_python" -c 'import os,bughunt_harness; assert bughunt_harness.__version__ == os.environ["BUGHUNT_EXPECTED_RELEASE_VERSION"]'
  "$release_tmp/reinstall/bin/harness" --version
)
(
  cd "$release_tmp/extracted/bughunt_harness-$package_version"
  "$reinstall_python" -m pytest -m 'unit or integration_local' -ra
)

mkdir -p "$release_root/dist"
cp "$artifact" "$release_root/dist/"
cp "$release_tmp/dist/SHA256SUMS" "$release_root/dist/"
echo "release $package_version verified: dist/$(basename "$artifact")"
