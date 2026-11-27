# Contributing

## Run the checkout

Use Python 3.12 or newer and uv. The CLI lives in the skill so that a harness can
copy the folder and run it with the standard library. The installed entry point
uses the same parser and implementation.

```bash
uv sync --dev
uv run nostr-mailbox --help
```

## Verify a change

```bash
uv run ruff check .
python3 scripts/sync_plugin.py --check
uv run pytest -q
```

The suite starts local WebSocket and Blossom servers and tests the CLI and MCP entry
points. Node.js runs the web console tests. The Claude plugin validator runs when the
Claude CLI is installed. To include the native signing backend and the real-relay
integration tests, provide the pinned `ncli 0.8.0-rc.54` binary and run the full suite.

```bash
NOSTR_MAILBOX_NCLI_BIN=/path/to/ncli uv run --extra nostr pytest -q
```

## Prepare a pull request

- Change Python code in `skills/nostr-mailbox/nostr_mailbox/`. Exercise the public entry
  point when a change affects what a seat sends, receives or stores.
- Edit `plugin.json` when plugin metadata changes. Regenerate its manifests and check
  the result with the commands below.
- When changing a CLI command, update the reader-facing examples and the agent skill.
  Tests parse commands in both. Describe the behavior change and the checks you ran in
  your pull request. [CLI reference](docs/cli-reference.md) · [Agent skill](skills/nostr-mailbox/SKILL.md)

```bash
python3 scripts/sync_plugin.py --write
python3 scripts/sync_plugin.py --check
```

Use the [security reporting process](SECURITY.md) for suspected vulnerabilities.
