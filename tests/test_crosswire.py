"""Witnesses for crosswire.sh, the public community switchboard: `setup` declares it when
no relay is named, and the CLI answers to `crosswire` as well as `nostr-mailbox`.

Nothing is mocked and nothing reaches the network: `setup` with no admin reach writes
the declaration and contacts no relay. The installer runs as a real process under a
HOME of its own, and the commands it links run as real processes, as a person's shell
runs them."""
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from nostr_mailbox import Trust, cli

REPO = Path(__file__).resolve().parents[1]
SYNC = REPO / "scripts/sync_plugin.py"
LAUNCHER = REPO / "skills/nostr-mailbox/scripts/nostr_mailbox.py"
NAMES = ("nostr-mailbox", "crosswire")
ENV = (cli.TRUST_ENV, cli.IDENTITY_ENV, cli.SEAT_ENV, "NOSTR_MAILBOX_HOME")
PUBLIC = ("wss://crosswire.sh", "crosswire")


@pytest.fixture(autouse=True)
def _no_ambient_profile(monkeypatch):
    """Each witness names its home; nothing comes from the caller's shell."""
    for name in ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def run(capsys):
    """The CLI in this process on the machine at `home`. Returns what it printed,
    parsed; with `code=1`, what it said on stderr."""
    def invoke(home: Path, *argv, code: int = 0):
        status = cli.main(["--home", str(home), *map(str, argv)])
        out, err = capsys.readouterr()
        assert status == code, err or out
        return json.loads(out) if status == 0 else err
    return invoke


def _declared(made: dict) -> tuple[str, str]:
    trust = Trust.load(Path(made["trust_file"]))
    return trust.relay, trust.campaign


def test_setup_declares_the_public_switchboard_unless_a_relay_is_named(run, tmp_path):
    """`setup` alone declares wss://crosswire.sh, campaign `crosswire`, encrypted, in the
    declaration and the org registry alike. A named relay or campaign is kept exactly
    as given, and either one left out takes its own default. An admin reach with no
    relay named is refused before anything is written: it runs one relay's own admin
    CLI, and the public switchboard is no local relay."""
    assert (cli.DEFAULT_PUBLIC_RELAY, cli.DEFAULT_PUBLIC_CAMPAIGN) == PUBLIC
    public = run(tmp_path / "public", "setup")
    assert (public["relay"], public["campaign"]) == PUBLIC == _declared(public)
    assert public["encrypted_nip44_v2"] and Trust.load(Path(public["trust_file"])).campaign_key
    org = tomllib.loads(Path(public["org_file"]).read_text())
    assert (org["relay"], org["campaign"]) == PUBLIC

    for argv, wanted in (
            (("--relay", "wss://relays.awow.io", "--campaign", "team"),
             ("wss://relays.awow.io", "team")),
            (("--relay", "wss://relays.awow.io"), ("wss://relays.awow.io", "crosswire")),
            (("--campaign", "team"), ("wss://crosswire.sh", "team"))):
        made = run(tmp_path / "-".join(wanted).replace("/", "_"), "setup", *argv)
        assert (made["relay"], made["campaign"]) == wanted == _declared(made), argv

    reach = tmp_path / "reach"
    refused = run(reach, "setup", "--exec", "ncli-somewhere", code=1)
    assert "name that relay with --relay" in refused and "Nothing was written" in refused
    assert not reach.exists(), "no key, no declaration, no admin reach"


def test_the_installer_links_both_names_and_crosswire_runs_the_cli(tmp_path):
    """`sync_plugin.py --install` links `~/.local/bin/nostr-mailbox` and
    `~/.local/bin/crosswire` to the skill's launcher, replacing whatever was at either
    name; a dry run plans both and writes neither. Each link runs the CLI under its own
    name, and `crosswire setup`, with no relay named, declares the public switchboard."""
    home, agent, mailbox = tmp_path / "home", tmp_path / "pi-agent", tmp_path / "mailbox"
    env = {**{k: v for k, v in os.environ.items() if k not in ENV}, "HOME": str(home),
           "PI_CODING_AGENT_DIR": str(agent)}
    bin_dir = home / ".local/bin"

    def install(*extra):
        done = subprocess.run([sys.executable, str(SYNC), "--install", "--harness", "pi",
                               *extra], capture_output=True, text=True, env=env, check=False)
        assert done.returncode == 0, done.stderr
        return done.stdout

    planned = install("--dry-run")
    for name in NAMES:
        assert f"ln -sf {LAUNCHER} {bin_dir / name}" in planned
    assert not home.exists(), "a dry run writes nothing"

    assert "~/.local/bin/nostr-mailbox and ~/.local/bin/crosswire" in install()
    (bin_dir / "crosswire").unlink()
    (bin_dir / "crosswire").write_text("a stale file at the name\n")
    install()
    assert sorted(p.name for p in bin_dir.iterdir()) == sorted(NAMES)
    for name in NAMES:
        link = bin_dir / name
        assert link.is_symlink() and link.resolve() == LAUNCHER.resolve(), name
        helped = subprocess.run([str(link), "--help"], capture_output=True, text=True,
                                env=env, check=False)
        assert helped.returncode == 0, helped.stderr
        assert helped.stdout.startswith(f"usage: {name} "), helped.stdout[:80]

    made = subprocess.run([str(bin_dir / "crosswire"), "--home", str(mailbox), "setup"],
                          capture_output=True, text=True, env=env, check=False)
    assert made.returncode == 0, made.stderr
    out = json.loads(made.stdout)
    assert (out["relay"], out["campaign"]) == PUBLIC == _declared(out)
    assert Path(out["trust_file"]).parent == mailbox
