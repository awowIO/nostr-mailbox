"""Private files: a key, a keyring, a trust declaration, a ledger. Each is written whole
or not at all, mode 0600 in a 0700 directory.

The bytes go to a sibling `mkstemp` made in the target's own directory (a name nobody
can predict, opened `O_EXCL`, so a symlink planted at a fixed `.tmp` name is never
followed), are forced to 0600 and to disk, and only then take the real name: by
`os.replace` (atomic, the old file or the new one, never half of either), or with
`exclusive` by a hard link, which fails when the name is already taken."""
from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

PRIVATE, PRIVATE_DIR = 0o600, 0o700


def write_private(path: str | Path, text: str, *, exclusive: bool = False) -> None:
    """Put `text` at `path`, 0600. `FileExistsError` under `exclusive` if it exists."""
    path = Path(path)
    path.parent.mkdir(mode=PRIVATE_DIR, parents=True, exist_ok=True)
    fd, staged = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".part")
    try:
        with os.fdopen(fd, "w") as fh:
            os.fchmod(fh.fileno(), PRIVATE)
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if exclusive:
            os.link(staged, path)
        else:
            os.replace(staged, path)
    finally:
        with contextlib.suppress(FileNotFoundError):    # replaced: nothing left to clean
            os.unlink(staged)
