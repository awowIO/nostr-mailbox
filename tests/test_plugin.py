"""The plugin package: what is generated matches plugin.json, and Claude Code's own validator
accepts the plugin and its marketplace."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_manifests_and_skill_links_are_generated_from_plugin_json():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts/sync_plugin.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(
    shutil.which("claude") is None, reason="Claude Code CLI not installed; cannot run its validator"
)
@pytest.mark.parametrize("target", [".", ".claude-plugin/marketplace.json"])
def test_claude_code_validator_accepts_the_package(target):
    proc = subprocess.run(
        ["claude", "plugin", "validate", target], cwd=ROOT, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed; cannot build the package")
def test_the_wheel_built_from_the_sdist_carries_the_package(tmp_path):
    """`uv build` makes the wheel from the sdist, as an index installer does. Both must
    carry the package, and the wheel nothing but it. The wheel installs the CLI under
    both of its names, `nostr-mailbox` and crosswire.sh's `crosswire`."""
    subprocess.run(["uv", "build", "-q", "-o", str(tmp_path)], cwd=ROOT, check=True)
    with tarfile.open(next(tmp_path.glob("*.tar.gz"))) as archive:
        sdist = archive.getnames()
    with zipfile.ZipFile(next(tmp_path.glob("*.whl"))) as archive:
        wheel = archive.namelist()
        scripts = archive.read("nostr_mailbox-0.1.0.dist-info/entry_points.txt").decode()
    console = dict(line.split(" = ") for line in
                   scripts.split("[console_scripts]\n", 1)[1].strip().splitlines())
    assert console == {"nostr-mailbox": "nostr_mailbox.cli:main",
                       "crosswire": "nostr_mailbox.cli:main"}
    package = ROOT / "skills/nostr-mailbox/nostr_mailbox"
    # the modules, and the console page `ui.py` serves (web/index.html)
    modules = sorted(p.name for pattern in ("*.py", "web/*") for p in package.glob(pattern))
    assert sorted(n.split("/")[-1] for n in sdist
                  if "/skills/nostr-mailbox/nostr_mailbox/" in n) == modules
    assert sorted(n.split("/")[-1] for n in wheel if n.startswith("nostr_mailbox/")) == modules
    assert {n.split("/")[0] for n in wheel} == {"nostr_mailbox", "nostr_mailbox-0.1.0.dist-info"}
