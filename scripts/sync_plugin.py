#!/usr/bin/env python3
"""Generate the per-harness plugin manifests from plugin.json, check them, or install locally.

    python3 scripts/sync_plugin.py --check      # fail if anything generated is stale
    python3 scripts/sync_plugin.py --write      # regenerate it from plugin.json
    python3 scripts/sync_plugin.py --install    # install into Claude Code, Codex and Antigravity
    python3 scripts/sync_plugin.py --install --harness codex --dry-run
    python3 scripts/sync_plugin.py --install --harness claude-desktop

plugin.json is the single source of truth. Generated:
  .claude-plugin/plugin.json        Claude Code plugin manifest
  .claude-plugin/marketplace.json   Claude Code marketplace (this repo is a one-plugin marketplace)
  .codex-plugin/plugin.json         Codex plugin manifest (adds the `interface` block)
  .agents/plugins/marketplace.json  Codex marketplace
  .agents/skills/<skill>            relative symlinks to skills/<skill>: repo-root skill discovery
Antigravity (and Gemini CLI) load the package from ~/.gemini/config/plugins/<name>.
Claude Desktop launches the MCP server named in its claude_desktop_config.json: --install
merges `nostr-mailbox` into its `mcpServers`, run as this machine's default persona, the
one the terminal CLI and every other local harness act as.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shlex
import shutil
import stat
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
    "docs",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
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


def copy_files(target: Path, base: Path, sources: list[Path], dry_run: bool) -> None:
    """Copy `sources` into `target`, each at its path relative to `base`. Nothing is
    written through a symlink: not `target`, not a directory between it and the file,
    not the file's own name."""
    if target.is_symlink():
        raise SystemExit(f"refusing to write through symlinked directory {target}")
    for source in sources:
        destination = target / source.relative_to(base)
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


def copy_package(target: Path, dry_run: bool) -> None:
    copy_files(target, ROOT, package_files(), dry_run)


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


def copy_skill_dir(target: Path, dry_run: bool) -> None:
    """Copy skills/<skill> into a harness skill directory (Pi, Copilot, Cursor, OpenCode),
    under the same rules as `copy_package`."""
    skill_root = ROOT / "skills/nostr-mailbox"
    files = [path for path in package_files() if path.is_relative_to(skill_root)]
    copy_files(target, skill_root, files, dry_run)


def pi_agent_dir() -> Path:
    """Pi's agent directory: PI_CODING_AGENT_DIR when set, else its default."""
    return Path(os.environ.get("PI_CODING_AGENT_DIR") or Path.home() / ".pi/agent").expanduser()


def skill_harness_dirs() -> dict[str, Path]:
    """Where each skill-directory harness looks for skills, read when asked."""
    return {
        "pi": pi_agent_dir() / "skills",
        "copilot": Path.home() / ".copilot/skills",
        "cursor": Path.home() / ".cursor/skills",
        "opencode": Path.home() / ".config/opencode/skills",
    }


DESKTOP_SERVER = "nostr-mailbox"
# What makes the CLI in this shell act as it does: its home, its persona, its default org.
# Claude Desktop starts its server with none of this shell's environment, so the entry
# carries whichever of these are set here, and the server acts as this terminal does.
# NOSTR_MAILBOX_SEAT is left out: a seat is one agent's queue of unsettled messages.
PROFILE_ENV = ("NOSTR_MAILBOX_HOME", "NOSTR_MAILBOX_IDENTITY", "NOSTR_MAILBOX_TRUST")
# What an MCP stdio client (Claude Desktop among them) passes a server by default, beside
# the `env` of its entry: nothing else of the installing shell reaches the server.
STDIO_ENV = (("APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PROCESSOR_ARCHITECTURE",
              "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "USERNAME", "USERPROFILE", "PROGRAMFILES")
             if os.name == "nt" else ("HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER"))


def claude_desktop_config() -> Path:
    """Where Claude Desktop reads its MCP servers on this platform."""
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
    if os.name == "nt":
        return Path(os.environ["APPDATA"]) / "Claude/claude_desktop_config.json"
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return config / "Claude/claude_desktop_config.json"


def desktop_entry(binary: Path) -> dict:
    """The `mcpServers` entry: the installed binary over stdio, as this machine's
    default persona with its keyrings, the very ones the terminal CLI, Claude Code,
    Codex, Antigravity and Cursor use here, so a channel joined once is open to all of
    them. No `--persona`: one named here would start with no keyring and be invited
    afresh. A call that should act as another persona names it in `persona`.

    A desktop app starts the server with a bare PATH, under which the binary's
    `/usr/bin/env python3` finds no Python 3.12 (macOS ships 3.9), so the entry carries
    the PATH this installer runs with (the python3, and the kubectl or docker an admin
    command reaches the relay with), and the profile variables set here (PROFILE_ENV)."""
    env = {"PATH": os.environ["PATH"],
           **{name: os.environ[name] for name in PROFILE_ENV if os.environ.get(name)}}
    return {"command": str(binary), "args": ["mcp"], "env": env}


def launch_once(entry: dict) -> None:
    """Start `entry` as an MCP stdio client does (its command and args, the default
    environment and its `env`) and require it to answer `initialize`; stdin then ends,
    so it exits. A server that cannot start is never written into a config."""
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "sync_plugin", "version": "0"}}}
    env = {**{k: os.environ[k] for k in STDIO_ENV if k in os.environ}, **entry["env"]}
    command = [entry["command"], *entry["args"]]
    done = subprocess.run(command, input=json.dumps(request) + "\n", capture_output=True,
                          text=True, env=env, check=False)
    lines = done.stdout.splitlines()
    try:
        name = json.loads(lines[0])["result"]["serverInfo"]["name"] if lines else None
    except (json.JSONDecodeError, KeyError, TypeError):
        name = None
    if done.returncode != 0 or name != "nostr-mailbox":
        raise SystemExit(f"{shlex.join(command)} did not answer an MCP initialize (exit "
                         f"{done.returncode}); nothing was written. stdout: {done.stdout!r} "
                         f"stderr: {done.stderr!r}")


def install_claude_desktop(config: Path, binary: Path, dry_run: bool) -> None:
    """Merge `desktop_entry(binary)` into Claude Desktop's config as mcpServers.nostr-mailbox.
    Every other key and server is kept. The file is replaced whole (a sibling temp file,
    then os.replace), keeps its mode (0600 when new), and is never written through a
    symlink; the entry is launched once first (`launch_once`)."""
    if config.is_symlink():
        raise SystemExit(f"refusing to write through the symlink {config}; edit its target, "
                         "or replace the link with a file")
    current: dict = {}
    if config.exists():
        text = config.read_text()
        try:
            current = json.loads(text) if text.strip() else {}
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{config} is not JSON ({exc}); it is left as it is: fix it, "
                             "or move it aside") from exc
        if not isinstance(current, dict):
            raise SystemExit(f"{config} holds a {type(current).__name__}, not a JSON object")
    servers = current.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise SystemExit(f"{config}: mcpServers is a {type(servers).__name__}, not an object")
    entry = desktop_entry(binary)
    launched = shlex.join([entry["command"], *entry["args"]])
    if servers.get(DESKTOP_SERVER) == entry:
        print(f"unchanged {config}: mcpServers.{DESKTOP_SERVER} runs {launched}", flush=True)
        return
    print(f"merge mcpServers.{DESKTOP_SERVER} into {config}: {launched}", flush=True)
    if dry_run:
        return
    launch_once(entry)
    merged = {**current, "mcpServers": {**servers, DESKTOP_SERVER: entry}}
    mode = stat.S_IMODE(config.stat().st_mode) if config.exists() else 0o600
    config.parent.mkdir(parents=True, exist_ok=True)
    fd, staged = tempfile.mkstemp(dir=config.parent, prefix=f".{config.name}.", suffix=".part")
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(merged, indent=2, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staged, mode)
        os.replace(staged, config)
    finally:
        with contextlib.suppress(FileNotFoundError):    # replaced: nothing left to clean
            os.unlink(staged)
    print("Restart Claude Desktop to load it.", flush=True)


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
        choices=["claude", "codex", "antigravity", "pi", "copilot", "cursor", "opencode",
                 "claude-desktop"],
        help="repeat to pick harnesses (default: detected harnesses)",
    )
    parser.add_argument(
        "--claude-desktop-config",
        type=Path,
        help="Claude Desktop's claude_desktop_config.json (default: this platform's)",
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
    harnesses = list(args.harness or [])
    if not harnesses:
        for h in ("claude", "codex"):
            if shutil.which(h):
                harnesses.append(h)
        if shutil.which("agy") or (Path.home() / ".gemini").is_dir():
            harnesses.append("antigravity")
        if shutil.which("pi") or pi_agent_dir().is_dir() or (Path.home() / ".pi").is_dir():
            harnesses.append("pi")
        if shutil.which("opencode") or (Path.home() / ".config/opencode").is_dir():
            harnesses.append("opencode")
        if (Path.home() / ".cursor").is_dir():
            harnesses.append("cursor")
        if (Path.home() / ".copilot").is_dir():
            harnesses.append("copilot")
        if (args.claude_desktop_config or claude_desktop_config()).parent.is_dir():
            harnesses.append("claude-desktop")
    if not harnesses:
        raise SystemExit(
            "No harness detected. Choose --harness antigravity/pi/copilot/cursor/opencode/"
            "claude-desktop or run the standalone CLI."
        )
    for harness in harnesses:
        if (
            not args.dry_run
            and harness in ("claude", "codex")
            and shutil.which(harness) is None
        ):
            raise SystemExit(
                f"{harness} CLI not found on PATH; pick installed harnesses with --harness"
            )
    for harness in harnesses:
        if harness == "claude":
            install_claude(meta["name"], args.dry_run)
        elif harness == "codex":
            install_codex(meta["name"], args.dry_run)
        elif harness == "antigravity":
            copy_package(args.antigravity_dir / meta["name"], args.dry_run)
        elif harness != "claude-desktop":   # after the binary it launches is linked, below
            copy_skill_dir(skill_harness_dirs()[harness] / meta["name"], args.dry_run)
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
    if "claude-desktop" in harnesses:
        install_claude_desktop(args.claude_desktop_config or claude_desktop_config(), bin_target,
                               args.dry_run)
    print(
        "Install planned (dry run)."
        if args.dry_run
        else "Installed plugin and ~/.local/bin/nostr-mailbox. Restart sessions to load the skill."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
