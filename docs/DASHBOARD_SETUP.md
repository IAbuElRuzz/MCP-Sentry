# Dashboard and client setup

MCP-Sentry 0.7 includes a local read-only audit dashboard and a terminal setup wizard. Both use the standard-library core; no frontend build or hosted service is required.

## Security dashboard

```sh
python3 -m mcpsentry dashboard --state-dir .mcpsentry --port 8765
```

Open the private URL printed by the command. Its token is in the URL fragment, which is removed from browser history after opening and retained in that tab's session storage. Keep this URL private. The server binds only to `127.0.0.1`, rejects foreign Host/Origin headers, requires the token for audit API access, and sends no CORS permission. Stop it with Ctrl+C. Port 0 chooses an available port.

Use the **same state directory** as your gateway. To explore a demo audit:

```sh
python3 -m mcpsentry demo --features --state-dir .mcpsentry/demo
python3 -m mcpsentry dashboard --state-dir .mcpsentry/demo
```

The dashboard shows forwarded/blocked/redacted calls, withheld responses, findings, catalog changes and cross-call detections. Filter by session or decision, search the latest 200 matching events, refresh manually or every five seconds, and export the selected metadata snapshot as JSON. Totals and finding counts cover all decisions for the selected session; the decision filter applies to the timeline. Up to 100 recent sessions are listed. Search is within the displayed 200 events, not the complete database.

The audit SQLite connection is read-only; the dashboard cannot execute tools, grant approvals, modify policies or configure clients. It never fetches argument/response payloads because the audit trail does not store them. Tool aliases, session identifiers and activity timing are still private metadata. Browser exports contain this metadata. No remote assets or telemetry are loaded. The local HTTP server is intended for a single user; do not proxy it onto a public network. A missing audit database shows an empty state without creating one.

## Client setup wizard

Interactive setup:

```sh
python3 -m mcpsentry setup --interactive
```

Choose `claude-desktop` or `cursor`, then provide an existing MCP-Sentry configuration file. Review the commands/URLs in that file before authorizing future launches/connections. The wizard shows a plan and asks whether to apply it. It never starts the client or upstream servers during setup.

Preview with explicit arguments:

```sh
python3 -m mcpsentry setup --client cursor \
  --config /absolute/path/mcpsentry.json --allow-exec
```

Add `--apply` to write the configuration and create a private backup. For remote servers use `--allow-network`; mixed gateway configurations require both flags. Defaults target:

| Client | Configuration |
| --- | --- |
| Cursor | `~/.cursor/mcp.json` |
| Claude Desktop on macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop on Linux | `~/.config/Claude/claude_desktop_config.json` |
| Claude Desktop on Windows | `%APPDATA%/Claude/claude_desktop_config.json` |

Use `--target /path/to/client.json` for another location, including a project-specific Cursor configuration. Use `--state-dir` to choose the gateway audit directory and optional `--baseline` to pin an approved catalog. The generated entry uses the current Python interpreter and an absolute packaged launcher, config path and state path so desktop working directories do not matter. Keep that interpreter and MCP-Sentry installation/checkout available. Upstream executable discovery still depends on the client's environment; use absolute upstream commands where needed.

The wizard merges one `MCP-Sentry` stdio entry into `mcpServers` and preserves unrelated settings. Existing direct MCP entries are listed in the preview: **those entries bypass the gateway**. Move their upstream definitions into your MCP-Sentry config yourself, then explicitly remove the direct entries with repeated `--remove-server NAME` flags. Removal names must already exist. No server is silently migrated or removed. Other client scopes or marketplace integrations can also expose direct servers and are outside this file's setup.

Existing different `MCP-Sentry` entries, malformed/duplicate-key JSON, symlink target files and configurations that changed since preview are rejected. JSONC comments/trailing commas are not supported. Preview output contains only the new launcher and entry names, not existing commands, environment credentials or config bodies. Existing client JSON and its backup may contain credentials: apply writes both with private file permissions. Local application changes are checked before replacement; close the client's config editor during setup to avoid concurrent edits.

The default file formats/paths follow the official [Cursor MCP documentation](https://prod.cursor.com/docs/mcp) and [MCP local-server guide for Claude Desktop](https://modelcontextprotocol.io/docs/develop/connect-local-servers). Restart Claude Desktop after applying; reload/restart Cursor as needed. Verify the MCP-Sentry server appears in the client's MCP settings. Configuration generation is tested; an authenticated live desktop handshake is a separate verification step.

## Roll back

Applying prints the backup path. Restore with:

```sh
python3 -m mcpsentry setup --rollback /path/to/client.json.mcpsentry-backup-ID.json
```

Rollback restores the exact original bytes, or removes the file if setup created it. It requires the installed configuration to remain byte-for-byte unchanged; subsequent edits cause refusal so they cannot be silently lost. A backup remains available for manual recovery. Only use backups you trust, because each records its restore target and original content. Restart the client after restoring.
