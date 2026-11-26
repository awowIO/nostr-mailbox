"""`python -m nostr_mailbox …`: the same commands as `nostr-mailbox …`."""
from .cli import main

raise SystemExit(main(prog="python -m nostr_mailbox"))
