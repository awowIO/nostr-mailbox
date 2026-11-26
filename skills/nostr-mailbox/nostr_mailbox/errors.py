"""The one root every error this package raises on purpose descends from, so a caller
(the CLI first of all) can tell "the mailbox said no" from a bug."""
from __future__ import annotations


class NostrError(Exception):
    """Root of every error this package raises on purpose."""
