"""Where a signed event leaves the relay as a file a harness reads.

Everything else in this package moves signed events. These two functions are the only
places one becomes something a seat is fed, and both write plain files, so any harness
consumes them without this package importing it:

- `adopt_directive` appends ONE verified operator directive to an `OPERATOR.md` as a
  dated `in force` entry. The entry's first line names the signed event
  (`Source: nostr:<id> seq=<n> operator=<npub>`), and those lines are this machine's
  own record of what it has adopted. An optional verify command is shown the file as
  it would read with the entry, before anything is written, and can refuse it.
- `deliver_handoff` replaces one file, whole, with a rendered four-field packet.

Both can append one wake line to a file a harness monitor tails: `DIRECTIVE <stamp> …`
for an adoption, `DISPATCH <stamp> inbox: <file> — …` for a packet. Each is one line,
a word and a UTC stamp first, so one pattern (`^(DIRECTIVE|DISPATCH) `) hears both."""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import bech32
from .backend import CampaignSession
from .event import NostrError
from .profile import DirectiveLedger

SOURCE = "Source: "
SOURCE_SCHEME = "nostr:"
# The OPERATOR.md format: appended only, each entry dated, verbatim, and either `in force`
# or `retired <date> by <entry or reason>`. A reader renders in-force entries whole and
# nothing before the first entry, so the preamble is housekeeping, never the operator's word.
PREAMBLE = ("# The operator's standing word: appended only; the one edit is a dated "
            "`retired <date> by <entry or reason>` mark on an entry's header\n")
ENTRY = re.compile(
    r"^## (?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?Z) — "
    r"(?P<status>in force|retired \d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2})?Z)? by .+)$")
# The DISPATCH line keeps the excerpt cut its harnesses already parse: the packet's first
# line, at most 120 characters. A monitor shows one short line; the packet is in the file.
WAKE_EXCERPT = 120


class BridgeError(NostrError):
    """The file a harness reads would not take what was offered."""


def _stamp(now: datetime | None) -> str:
    return (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry(stamp: str, body: str) -> str:
    """A new in-force OPERATOR.md entry, the body verbatim."""
    return f"\n## {stamp} — in force\n\n{body}\n"


def write_whole(path: str | Path, text: str) -> None:
    """Replace `path` with `text`, whole or not at all."""
    path = Path(path)
    fd, staged = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(staged, path)
    finally:
        Path(staged).unlink(missing_ok=True)


def append_line(path: str | Path, line: str) -> None:
    """Append one line in one write, in append mode: no read-modify-write race."""
    with open(path, "a") as fh:
        fh.write(line + "\n")


# ------------------------------------------------------------------- directive adoption
def adopted_ids(operator_file: str | Path) -> list[str]:
    """Event ids of the directives adopted into `operator_file`, in file order."""
    path = Path(operator_file)
    if not path.is_file():
        return []
    ids = []
    for line in path.read_text().splitlines():
        if line.startswith(SOURCE):
            source = line[len(SOURCE):].strip()
            if source.startswith(SOURCE_SCHEME):
                ids.append(source.split()[0][len(SOURCE_SCHEME):])
    return ids


def adoption_state(ledger: DirectiveLedger, adopted: list[str]) -> dict:
    """How the relay's chain and this machine's own record line up. `rollback` names an
    adopted directive the relay's chain no longer contains: the relay is withholding
    or has lost history, and nothing more is adopted from that answer."""
    chain = {d.event_id for d in ledger.in_force}
    return {"adopted": [i for i in adopted if i in chain],
            "rollback": [i for i in adopted if i not in chain],
            "next": next((d.event_id for d in ledger.in_force
                          if d.campaign_wide and d.event_id not in adopted), None)}


def _verify(command: str, staged_name: str, candidate: str, text: str, *,
            timeout_s: float, short: str, target: Path) -> None:
    """Run the harness's own check on the file as it would read. The command gets the
    candidate file's path as its last argument and the directive's words on stdin;
    exit 0 lets the adoption go ahead, anything else refuses it, unwritten."""
    argv = shlex.split(command)
    if not argv:
        raise BridgeError("--verify-cmd is empty")
    with tempfile.TemporaryDirectory(prefix="nostr-mailbox-") as scratch:
        staged = Path(scratch) / staged_name
        staged.write_text(candidate)
        try:
            done = subprocess.run([*argv, str(staged)], input=text, capture_output=True,
                                  text=True, timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise BridgeError(
                f"verify command {argv[0]!r} gave no answer in {timeout_s}s (--timeout-seconds); "
                f"directive {short} was not adopted and nothing was written to {target}") from exc
        except OSError as exc:
            raise BridgeError(f"verify command {argv[0]!r} could not run: {exc}; directive "
                              f"{short} was not adopted") from exc
    if done.returncode != 0:
        said = (done.stderr.strip() or done.stdout.strip()).splitlines()
        raise BridgeError(      # its last line only: a harness's output can be long
            f"verify command {argv[0]!r} refused directive {short} (exit {done.returncode})"
            f"{': ' + said[-1] if said else ''}; nothing was written to {target}")


def adopt_directive(session: CampaignSession, event_id: str, *, operator_file: str | Path,
                    graph_digest: str | None = None, verify_cmd: str | None = None,
                    wake_file: str | Path | None = None, now: datetime | None = None) -> dict:
    """Adopt one signed operator directive into `operator_file` on this machine.

    Refused, with nothing written, unless every one of these holds: the directive is in
    the verified chain in force (roster, campaign and ancestry are what put it there; a
    held or rejected directive is not); it addresses every seat (an OPERATOR.md entry
    reaches every seat, and widening an audience is not this command's call); if it
    names a graph digest, the caller supplied the same one; every directive this file
    records as adopted is still in the relay's chain; every earlier campaign-wide
    directive is already adopted; no line of it would read as an entry header; and the
    verify command, when given, accepts the file as it would read. Adopting the same
    event again appends nothing and posts the wake line again, which is how a retry
    finishes an adoption interrupted before its wake."""
    path = Path(operator_file)
    ledger = session.directives()
    chain = {d.event_id: d for d in ledger.in_force}
    short = f"{event_id[:12]}…"
    if event_id not in chain:
        why = next((reason for d, reason in ledger.held if d.event_id == event_id), None)
        why = why or next((reason for ident, reason in ledger.rejected if ident == event_id),
                          "the relay returned no such directive for this campaign")
        raise BridgeError(f"directive {short} is not in force and was not adopted: {why}")
    directive = chain[event_id]
    if not directive.campaign_wide:
        raise BridgeError(
            f"directive {short} addresses {list(directive.audience)}, and an OPERATOR.md "
            "entry reaches every seat. It was not adopted: widening an operator's audience "
            "is the operator's decision")
    if directive.graph_digest and directive.graph_digest != graph_digest:
        raise BridgeError(
            f"directive {short} was issued for graph {directive.graph_digest[:12]}… "
            f"and this adoption names {graph_digest[:12] + '…' if graph_digest else 'none'}; "
            "it was not adopted")
    adopted = adopted_ids(path)
    state = adoption_state(ledger, adopted)
    if state["rollback"]:
        raise BridgeError(
            f"{path} records directive {state['rollback'][0][:12]}… as adopted, and the "
            "relay's chain no longer contains it. The relay is withholding or has lost "
            "history; nothing was adopted from this answer")
    earlier = [d for d in ledger.in_force
               if d.seq < directive.seq and d.campaign_wide and d.event_id not in adopted]
    if earlier:
        raise BridgeError(
            f"directive {earlier[0].event_id[:12]}… (sequence {earlier[0].seq}) comes "
            f"first and is not adopted yet; adopt it before sequence {directive.seq}")
    npub = bech32.encode(bech32.NPUB, bytes.fromhex(directive.operator))
    source = f"{SOURCE_SCHEME}{event_id} seq={directive.seq} operator={npub}"
    stamp, already = _stamp(now), event_id in adopted
    verify = "not run: already adopted" if already else None
    if not already:
        text = directive.text.strip()
        body = f"{SOURCE}{source}\n\n{text}"
        for line in body.splitlines():          # checked BEFORE the append-only write
            if line.startswith("## ") or ENTRY.fullmatch(line):
                raise BridgeError(
                    f"directive {short} carries a line that would read as an entry header "
                    f"in {path.name}: {line!r}. It was not adopted; appended, it would "
                    "break every reader of the file until it were hand-edited")
        held = path.read_text() if path.is_file() else ""
        addition = ("" if held else PREAMBLE) + entry(stamp, body)
        if verify_cmd:
            _verify(verify_cmd, path.name, held + addition, text,
                    timeout_s=session.timeout_s, short=short, target=path)
            verify = "passed"
        with open(path, "a") as fh:
            fh.write(addition)
    wake = None
    if wake_file:
        wake = (f"DIRECTIVE {stamp} operator directive {directive.seq} adopted "
                f"({SOURCE_SCHEME}{short}) — re-read {path} in full")
        append_line(wake_file, wake)
    return {"adopted": event_id, "seq": directive.seq, "operator": npub,
            "already_adopted": already, "source": source, "operator_file": str(path),
            "verify": verify, "wake": wake}


# ------------------------------------------------------------------- handoff delivery
def deliver_handoff(text: str, first_line: str, *, out: str | Path,
                    wake_file: str | Path | None = None, now: datetime | None = None) -> dict:
    """Replace `out`, whole, with a rendered handoff packet, and post one DISPATCH line
    naming it to `wake_file` when one is given."""
    path = Path(out)
    write_whole(path, text)
    wake = None
    if wake_file:
        wake = (f"DISPATCH {_stamp(now)} inbox: {path.name} — "
                f"{first_line.strip()[:WAKE_EXCERPT]}")
        append_line(wake_file, wake)
    return {"written": str(path), "wake": wake}
