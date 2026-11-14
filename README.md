# MCP-Sentry

A local security gateway for MCP tool traffic. See what your AI calls, apply policies before forwarding requests, and keep a metadata-only audit trail.

**v0.1.0 · Experimental MVP · Python 3.11+ · macOS / Linux · No runtime dependencies.** This version supports local stdio servers and the MCP tools interface. It is not a sandbox or a guarantee that a server is safe.

```text
Claude / Cursor / another MCP client
                 |
           MCP-Sentry
       policies + audit trail
                 |
       local stdio MCP servers
```

## Try it

From the repository root:

```sh
python3 -m mcpsentry demo
```

The demo launches two inert MCP servers as real subprocesses. It reads a fictional database record, allows an ordinary message, and blocks a fake secret, a copied customer reference, an unapproved recipient, and a simulated destructive tool. Nothing is sent over the network.

```text
ALLOW  Authorized database read
ALLOW  Ordinary message to approved recipient
BLOCK  Fake-secret transfer · secret_in_arguments
BLOCK  Copied customer reference · sensitive_data_transfer
BLOCK  Unapproved recipient · recipient_not_allowed
BLOCK  Destructive tool · tool_denied
```

Inspect the resulting audit trail:

```sh
python3 -m mcpsentry events --state-dir .mcpsentry/demo
```

Optional installation into a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/mcpsentry --help
```

## Connect your MCP client

Generate a demo configuration containing absolute Python and fixture paths:

```sh
python3 -m mcpsentry init --output mcpsentry.json
```

Add this server entry to your client's MCP configuration, replacing the example paths:

```json
{
  "mcpServers": {
    "MCP-Sentry": {
      "command": "/absolute/path/to/python3",
      "args": ["-m", "mcpsentry", "run", "--config", "/absolute/path/to/mcpsentry.json", "--allow-exec", "--state-dir", "/absolute/path/to/private-state"],
      "cwd": "/absolute/path/to/MCP-Sentry"
    }
  }
}
```

For clients without `cwd` support, use the installed environment's absolute `mcpsentry` executable as `command` and remove `-m`, `mcpsentry`, and `cwd`. Route the protected servers through this entry; leaving direct entries gives the client a way around the gateway.

The client sees namespaced tools such as `db__read_customer` and `mail__send`. Gateway stdout contains only JSON-RPC. Startup messages go to stderr. Follow activity in a separate terminal:

```sh
python3 -m mcpsentry events --state-dir /absolute/path/to/private-state --follow
```

## Configure real servers and policies

`init` writes a runnable config. Replace its server definitions with commands you have reviewed. Paths in `cwd` resolve relative to the configuration file. Commands are executed without a shell. Only PATH, SYSTEMROOT, locale, and TMPDIR environment variables are inherited; pass other required environment variables explicitly in `env` and keep that file private.

```json
{
  "servers": {
    "database": {
      "command": "/absolute/path/to/python",
      "args": ["/absolute/path/to/server.py"],
      "cwd": "/absolute/path/to/project"
    }
  },
  "timeout_seconds": 10,
  "policy": {
    "default": "deny",
    "allow": ["database__read_*"],
    "deny": ["*__delete*"],
    "sensitive_sources": ["database__*"],
    "sensitive_destinations": [],
    "recipient_allowlists": {},
    "block_secrets": true,
    "block_tool_changes": true,
    "block_poisoning": true
  }
}
```

Policy order: explicit deny overrides allow; default is deny. Patterns use case-sensitive shell-style globs on the full namespaced tool name. Tools not allowed remain visible in discovery but cannot be executed in enforce mode. `recipient_allowlists` maps a tool pattern to top-level argument fields and exact allowed values, for example `{"mail__send":{"to":["team@example.com"]}}`. Missing or unapproved values are blocked. Configure every relevant recipient field; this is not a universal email parser.

`sensitive_sources` marks returned strings of 12 or more characters as sensitive. Strings inside structured JSON and JSON text blocks are tracked individually. Subsequent arguments containing those exact strings are blocked unless their destination matches `sensitive_destinations`. Recognized secret formats are separately blocked in arguments by default, even for trusted destinations. Matching is case-sensitive; encoding, paraphrasing, fragments, short values, binary content, and semantic transformations can evade it. Values stay in bounded session memory and are not persisted. If tracking capacity is exceeded, untrusted destinations are blocked for the remainder of the session.

Enforce mode is the default. Monitor mode records `would_block` and **forwards policy-violating calls**:

```sh
python3 -m mcpsentry run --config mcpsentry.json --allow-exec --mode monitor
```

Malformed backend traffic and unsupported non-text tool content fail closed in both modes. Recognizable instruction patterns in descriptions and textual results can be blocked, but this small rule set will miss attacks and can flag benign text. Blocking a response happens after the underlying tool ran; side effects cannot be undone.

## Scan and approve a baseline

These commands start the configured servers, so all require explicit execution authorization:

```sh
python3 -m mcpsentry scan --config mcpsentry.json --allow-exec
python3 -m mcpsentry baseline --config mcpsentry.json --allow-exec --output approved.json
python3 -m mcpsentry scan --config mcpsentry.json --allow-exec --baseline approved.json
python3 -m mcpsentry run --config mcpsentry.json --allow-exec --baseline approved.json
```

Baselines contain hashes of the config and exposed tool definitions, not the descriptions or credentials themselves. They are approval artifacts: review findings before creating one, protect it from modification, and create a new file deliberately when approving changes. The command refuses to overwrite an existing baseline. Config hashes are not encryption; low-entropy values may be guessable. In enforce mode, changed or flagged tool definitions are withheld from discovery as well as blocked on invocation.

Without `--baseline`, the first discovery is pinned only for the current process. Every call re-lists the tools and compares the target's definition before forwarding. With a persisted baseline, configuration changes and unapproved target definitions are blocked. Scans also report removed tools. This does not detect executable replacement at the same path, undisclosed behavioral changes, or a dishonest server that switches behavior after inspection.

Exit codes: `0` completed, `2` scan findings, `3` configuration/operational failure, `130` interrupted. A clean scan means only that these metadata rules found no known pattern.

## Privacy and limits

- No telemetry, hosted analysis, or model API. Configured servers can independently access the network.
- SQLite events contain timestamps, session IDs, tool aliases, decisions, reason codes, and duration. Arguments, results, raw errors, and matched sensitive values are not logged. Tool names themselves may reveal information.
- Audit files are created with owner-only permissions. Use a private state directory. The audit is local and editable, not tamper-evident; retention and rotation are not implemented.
- Local server commands run with your OS user's rights. Minimal environment inheritance is not isolation. Use a separate VM/container for untrusted servers.
- Only traffic routed through this process is visible. Remote internals, server-side file/network access, and the client's built-in tools are outside coverage.
- Supported: newline JSON-RPC stdio, initialization/ping, paginated upstream tool listing, text/structured tool results, sequential calls. Protocol versions: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25.
- Not implemented: HTTP/SSE, resources, prompts, sampling, elicitation, task APIs, client cancellation, interactive approvals, multi-client shared tracking, schema validation of call arguments, or OS sandboxing. Server-initiated requests are rejected; upstream notifications are not forwarded. Text results are size bounded but no binary inspection is provided.
- A timeout after dispatch means the operation may already have happened. MCP-Sentry does not retry it. Calls are serialized and the timeout is per upstream request; refreshing several catalogs adds latency.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m mcpsentry demo
```

Architecture: `config.py` validates configuration; `transport.py` handles bounded subprocess RPC; `security.py` makes decisions; `gateway.py` serves the client and dispatches calls; `audit.py` persists metadata; `cli.py` exposes commands.

Next milestones: official SDK interoperability checks, Streamable HTTP, argument-bound approvals, isolated local runners, and policy replay against metadata-safe fixtures. Features above are scoped to this experimental MVP, not a production security certification.

## License

MIT. See [LICENSE](LICENSE).
