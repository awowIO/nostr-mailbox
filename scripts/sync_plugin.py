#!/usr/bin/env python3
"""Generate the per-harness plugin manifests from plugin.json, check them, or install locally.

    python3 scripts/sync_plugin.py --check      # fail if anything generated is stale
    python3 scripts/sync_plugin.py --write      # regenerate it from plugin.json
    python3 scripts/sync_plugin.py --install    # install into Claude Code, Codex and Antigravity
    python3 scripts/sync_plugin.py --install --harness codex --dry-run

plugin.json is the single source of truth. Generated:
  .claude-plugin/plugin.json        Claude Code plugin manifest
  .claude-plugin/marketplace.json   Claude Code marketplace (this repo is a one-plugin marketplace)
  .codex-plugin/plugin.json         Codex plugin manifest (adds the `interface` block)
  .agents/plugins/marketplace.json  Codex marketplace
  .agents/skills/<skill>            relative symlinks to skills/<skill>: repo-root skill discovery
Antigravity (and Gemini CLI) load the package from ~/.gemini/config/plugins/<name>.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = (
    "plugin.json",
    ".claude-plugin",
    ".codex-plugin",
    ".agents/plugins",
    "skills",
    "README.md",
    "LICENSE",
)
PACKAGE_INIT = "skills/nostr-mailbox/nostr_mailbox/__init__.py"
SKILL_BODY_LIMIT = 24_000  # Gemini/Antigravity truncate SKILL.md bodies above this many bytes
MARKET = "org.nostr-mailbox.marketplace"


def canonical() -> dict:
    return json.loads((ROOT / "plugin.json").read_text())


def render(meta: dict) -> dict[str, dict]:
    base = {
        k: meta[k]
        for k in ("name", "version", "description", "author", "license", "keywords", "skills")
    }
    market = meta["extensions"][MARKET]
    return {
        ".claude-plugin/plugin.json": base,
        ".codex-plugin/plugin.json": {
            **base,
            "interface": meta["extensions"]["com.openai"]["interface"],
        },
        ".claude-plugin/marketplace.json": {
            "name": meta["name"],
            "owner": market["owner"],
            "description": market["description"],
            "plugins": [
                {
                    "name": meta["name"],
                    "source": "./",
                    "description": meta["description"],
                    "version": meta["version"],
                }
            ],
        },
        ".agents/plugins/marketplace.json": {
            "name": meta["name"],
            "interface": {
                "displayName": meta["extensions"]["com.openai"]["interface"]["displayName"]
            },
            "plugins": [
                {
                    "name": meta["name"],
                    "source": {"source": "local", "path": "./"},
                    "policy": market["policy"],
                    "category": market["category"],
                }
            ],
        },
    }


def skill_links() -> dict[Path, str]:
    """Each skill's `.agents/skills/<name>` link and the relative target it must have."""
    return {
        ROOT / ".agents/skills" / skill.parent.name: f"../../skills/{skill.parent.name}"
        for skill in sorted((ROOT / "skills").glob("*/SKILL.md"))
    }


def dumps(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def validate(meta: dict) -> list[str]:
    problems = []
    if not re.fullmatch(r"\d+\.\d+\.\d+", meta["version"]):
        problems.append(f"plugin.json version {meta['version']!r} is not semver")
    if f'__version__ = "{meta["version"]}"' not in (ROOT / PACKAGE_INIT).read_text():
        problems.append("nostr_mailbox.__version__ differs from plugin.json version")
    if f'version = "{meta["version"]}"' not in (ROOT / "pyproject.toml").read_text():
        problems.append("pyproject.toml version differs from plugin.json version")
    for skill in sorted((ROOT / "skills").glob("*/SKILL.md")):
        text = skill.read_text()
        if (
            not text.startswith("---\n")
            or "\nname:" not in text.split("---", 2)[1]
            or "\ndescription:" not in text.split("---", 2)[1]
        ):
            problems.append(f"{skill} needs YAML frontmatter with name and description")
        if len(text.encode().split(b"---\n", 2)[-1]) > SKILL_BODY_LIMIT:
            problems.append(f"{skill} body exceeds {SKILL_BODY_LIMIT} bytes")
    return problems


def check(meta: dict) -> list[str]:
    problems = validate(meta)
    for rel, data in render(meta).items():
        path = ROOT / rel
        if not path.exists():
            problems.append(f"{rel} is missing; run scripts/sync_plugin.py --write")
        elif path.read_text() != dumps(data):
            problems.append(f"{rel} is stale; run scripts/sync_plugin.py --write")
    for link, target in skill_links().items():
        if not link.is_symlink() or os.readlink(link) != target:
            problems.append(
                f"{link.relative_to(ROOT)} must be a symlink to {target}; "
                "run scripts/sync_plugin.py --write"
            )
    return problems


def write(meta: dict) -> None:
    for rel, data in render(meta).items():
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != dumps(data):
            path.write_text(dumps(data))
            print(f"wrote {rel}")
    for link, target in skill_links().items():
        if link.is_symlink() and os.readlink(link) == target:
            continue
        if link.exists() or link.is_symlink():
            raise SystemExit(f"{link} exists and is not the symlink {target}; move it aside first")
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
        print(f"linked {link.relative_to(ROOT)} -> {target}")


# -- local installation ---------------------------------------------------------------------------


def run(command: list[str], dry_run: bool) -> None:
    print(shlex.join(command), flush=True)
    if not dry_run:
        subprocess.run(command, check=True)


def package_files() -> list[Path]:
    files = []
    for rel in PAYLOAD:
        path = ROOT / rel
        for candidate in path.rglob("*") if path.is_dir() else [path]:
            if candidate.is_symlink():
                raise SystemExit(f"refusing to package a symlink: {candidate}")
            if (
                candidate.is_file()
                and "__pycache__" not in candidate.parts
                and candidate.suffix != ".pyc"
            ):
                files.append(candidate)
    return sorted(files)


def copy_package(target: Path, dry_run: bool) -> None:
    if target.is_symlink():
        raise SystemExit(f"refusing to write through symlinked plugin directory {target}")
    for source in package_files():
        destination = target / source.relative_to(ROOT)
        if any(
            part.is_symlink()
            for part in [destination, *destination.parents]
            if part.is_relative_to(target)
        ):
            raise SystemExit(f"refusing to copy through a symlink under {target}")
        if destination.is_file() and destination.read_bytes() == source.read_bytes():
            continue
        print(f"copy {source.relative_to(ROOT)} -> {destination}", flush=True)
        if dry_run:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
            stream.write(source.read_bytes())
        os.chmod(stream.name, source.stat().st_mode & 0o777)
        os.replace(stream.name, destination)


GITHUB_REPO = "awowIO/nostr-mailbox"


def install_claude(name: str, dry_run: bool) -> None:
    config = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
    known_file = config / "plugins/known_marketplaces.json"
    known = json.loads(known_file.read_text()) if known_file.exists() else {}
    if name in known:
        run(["claude", "plugin", "marketplace", "update", name], dry_run)
    else:
        run(["claude", "plugin", "marketplace", "add", GITHUB_REPO], dry_run)
    installed_file = config / "plugins/installed_plugins.json"
    installed = (
        json.loads(installed_file.read_text()).get("plugins", {}) if installed_file.exists() else {}
    )
    action = "update" if installed.get(f"{name}@{name}") else "install"
    run(["claude", "plugin", action, f"{name}@{name}", "--scope", "user"], dry_run)


def install_codex(name: str, dry_run: bool) -> None:
    run(["codex", "plugin", "marketplace", "add", str(ROOT)], dry_run)
    run(["codex", "plugin", "add", f"{name}@{name}"], dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 if anything generated is stale")
    mode.add_argument("--write", action="store_true", help="regenerate manifests and skill links")
    mode.add_argument("--install", action="store_true", help="install into local harnesses")
    parser.add_argument(
        "--harness",
        action="append",
        choices=["claude", "codex", "antigravity"],
        help="repeat to pick harnesses (default: detected harnesses)",
    )
    parser.add_argument(
        "--antigravity-dir",
        type=Path,
        default=Path.home() / ".gemini/config/plugins",
        help="Antigravity / Gemini plugin directory",
    )
    parser.add_argument("--dry-run", action="store_true", help="print what --install would do")
    args = parser.parse_args()
    meta = canonical()
    if args.check:
        problems = check(meta)
        for problem in problems:
            print(f"sync_plugin: {problem}", file=sys.stderr)
        if not problems:
            print(f"{meta['name']} {meta['version']}: manifests in sync")
        return 1 if problems else 0
    if args.write:
        problems = validate(meta)
        if problems:
            raise SystemExit("\n".join(problems))
        write(meta)
        return 0
    problems = check(meta)
    if problems:
        raise SystemExit("\n".join(problems))
    harnesses = args.harness or [h for h in ("claude", "codex") if shutil.which(h)]
    if not args.harness and (shutil.which("agy") or (Path.home() / ".gemini").is_dir()):
        harnesses.append("antigravity")
    if not harnesses:
        raise SystemExit(
            "No harness detected. Choose --harness antigravity or run the standalone CLI."
        )
    for harness in harnesses:
        if not args.dry_run and harness != "antigravity" and shutil.which(harness) is None:
            raise SystemExit(
                f"{harness} CLI not found on PATH; pick installed harnesses with --harness"
            )
    for harness in harnesses:
        if harness == "claude":
            install_claude(meta["name"], args.dry_run)
        elif harness == "codex":
            install_codex(meta["name"], args.dry_run)
        else:
            copy_package(args.antigravity_dir / meta["name"], args.dry_run)
    bin_dir = Path.home() / ".local/bin"
    bin_target = bin_dir / "nostr-mailbox"
    script_src = ROOT / "skills/nostr-mailbox/scripts/nostr_mailbox.py"
    if args.dry_run:
        print(f"ln -sf {script_src} {bin_target}")
    else:
        bin_dir.mkdir(parents=True, exist_ok=True)
        script_src.chmod(0o755)
        if bin_target.is_symlink() or bin_target.exists():
            bin_target.unlink()
        bin_target.symlink_to(script_src)
    print(
        "Install planned (dry run)."
        if args.dry_run
        else "Installed plugin and ~/.local/bin/nostr-mailbox. Restart sessions to load the skill."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
