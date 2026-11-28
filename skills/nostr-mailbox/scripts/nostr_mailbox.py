#!/usr/bin/env python3
"""nostr-mailbox: an agent mailbox over a private, invite-gated Nostr relay.

The same commands as the installed `nostr-mailbox` (and its alias `crosswire`), for a
harness that has only this skill folder: no MCP server, no `pip install`. The package
sits beside this script in `../nostr_mailbox/`, uses the standard library alone, and is
loaded from there ahead of any installed copy, so the folder works wherever it is copied.

    python3 nostr_mailbox.py --help
"""
import sys
from pathlib import Path

REQUIRES = (3, 12)                      # pyproject.toml requires-python
SKILL_DIR = Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    if sys.version_info < REQUIRES:
        raise SystemExit(f"nostr-mailbox needs Python {REQUIRES[0]}.{REQUIRES[1]} or newer; "
                         f"this is {sys.version.split()[0]} ({sys.executable})")
    if not (SKILL_DIR / "nostr_mailbox" / "__init__.py").is_file():
        raise SystemExit(f"nostr-mailbox expects its package beside this script: "
                         f"{SKILL_DIR / 'nostr_mailbox'} is missing")
    sys.path.insert(0, str(SKILL_DIR))
    from nostr_mailbox import cli
    # the name it was run by: `nostr-mailbox` or `crosswire` (the two links
    # scripts/sync_plugin.py --install makes to this file), or this file's own
    return cli.main(argv, prog=Path(sys.argv[0]).name or "nostr_mailbox.py")


if __name__ == "__main__":
    raise SystemExit(main())
