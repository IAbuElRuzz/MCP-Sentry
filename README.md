# MCP-Sentry

A local security gateway for MCP tool traffic. See what your AI calls, apply policies before forwarding requests, and keep a metadata-only audit trail.

**v0.5.0 · Experimental · Python 3.11+ · macOS / Linux · Standard-library core, optional PDF/SDK extras.** Inspect outbound MCP arguments, redact eligible sensitive content, and detect fragments spread across calls. Local stdio and remote Streamable HTTP upstreams share one client-facing stdio gateway.

Try the new features with `python3 -m mcpsentry demo --features`. They need no container installation. See [redaction and cross-call detection](docs/DATA_PROTECTION.md) for configuration, approval interaction and coverage limits.

See [runtime controls and verification](docs/CONTROLS.md) for setup, exact boundaries and checks that could not run in this environment.

```text
Claude / Cursor / another MCP client
                 |
           MCP-Sentry
       policies + audit trail
                 |
   local stdio + remote HTTP MCP servers
```

## Additional runtime controls

| Control | Use it |
| :--- | :--- |
| Sensitive-data redaction | Explicit content-field rules preserve safe text where possible, remove encoded/secret fields when needed, and recheck policy before forwarding. Client-visible notices and metadata-only audit records show that a rewrite happened. |
| Cross-call leak detection | Correlate dispatched fragments across tools/servers, including tracked values and recognizable PII/secret formats. Block the completing call; earlier fragments cannot be recalled. |
| Local server isolation | Fixed Docker profile: no network, read-only filesystem/files, non-root user, dropped capabilities and resource limits. Enable `require_sandbox`; unavailable Docker never falls back to host execution. |
| Exact-action approvals | Require review for selected tools or eligible findings. A grant is bound to the arguments/recipient, session, config and tool definition, expires, and can be consumed once. |
| Document inspection | Extract text from inline DOCX/XLSX/PPTX and, with the optional parser, PDF. Incomplete, encrypted or image-containing documents remain blocked. |
| Context and local models | Built-in context cues plus an opt-in local classifier/Ollama adapter. Model output can add findings but cannot clear deterministic ones. |

```sh
python3 -m mcpsentry doctor
python3 -m mcpsentry sandbox-plan --config examples/sandbox.json
python3 -m mcpsentry approvals list --state-dir .mcpsentry
```

These features need explicit setup. Docker is not started automatically, approvals are disabled until configured, PDF requires `pip install -e '.[documents]'` (or `.[documents-pdfminer]`), and a real model must already be available locally. Local verification covers approvals, Office extraction, pdfminer-backed PDF inspection and official SDK client/server interoperability. Docker/model/GUI client checks retain the blockers recorded in the [verification matrix](docs/CONTROLS.md#local-verification-status-for-this-implementation).

## Try it

From the repository root:

```sh
python3 -m mcpsentry demo
python3 -m mcpsentry demo --dlp
python3 -m mcpsentry demo --features
```

The demo launches two inert MCP servers as real subprocesses. It reads a fictional database record, allows an ordinary message, and blocks a fake secret, a copied customer reference, an unapproved recipient, and a simulated destructive tool. Nothing is sent over the network.

`--dlp` adds six outbound inspection cases: a published test card, an email in the body, Base64 and compressed/Base64 personal data, a labeled identity field, and an opaque attachment. All examples use synthetic data; nothing is sent to an external recipient.

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
python3 -m mcpsentry events --state-dir .mcpsentry/demo --format table
python3 -m mcpsentry report --state-dir .mcpsentry/demo
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

### Nested argument restrictions and call budgets

Add these fields inside `policy` to bound individual arguments and repeated operations:

```json
{
  "argument_constraints": {
    "database__query": {
      "/options/limit": {"type": "integer", "minimum": 1, "maximum": 100},
      "/operation": {"enum": ["read"]},
      "/query": {"type": "string", "max_length": 2000}
    }
  },
  "call_limits": {
    "mail__*": {"max_calls": 5, "window_seconds": 60}
  }
}
```

Constraint paths are JSON pointers: `/options/limit` addresses a nested field, `/items/0/id` an array element, `~1` escapes `/` and `~0` escapes `~`. Fields are required unless `"required": false` is set. Supported rules are `type`, `enum`, numeric `minimum`/`maximum`, and `max_length` for strings, arrays, or objects. Booleans do not count as integers. Enums use canonical JSON equality (including a distinction between `1` and `1.0`). These are explicit administrator constraints, not full JSON Schema validation. They do not parse SQL, constrain filesystem access, or establish the meaning of a tool argument.

Call limits count dispatch attempts, including upstream failures, across all tools matching each pattern. Calls blocked before dispatch consume no budget. Limits are shared by a pattern within one gateway process and expire using monotonic time; they reset on restart and are not a fleet-wide quota. Monitor mode reports violations but still dispatches and counts those calls.

### Remote HTTP servers

Use a `url` definition instead of `command` for a remote server. Authentication header values are read from environment variables so tokens need not live in the config or baseline:

```json
{
  "servers": {
    "remote": {
      "url": "https://mcp.example.com/mcp",
      "headers_env": {"Authorization": "MCP_REMOTE_AUTH"}
    }
  },
  "policy": {"default": "deny", "allow": ["remote__read_*"]},
  "timeout_seconds": 10
}
```

Set `MCP_REMOTE_AUTH` to the complete header value, such as `Bearer <token>`, in the gateway process environment (or your client's environment settings). Never commit credentials. Resolved header values and HTTP session IDs are not written to audit events. A baseline binds the URL and environment variable names, not the resolved header credentials.

```sh
python3 -m mcpsentry scan --config remote.json --allow-network
python3 -m mcpsentry run --config remote.json --allow-network
```

Mixed local/remote configs require both `--allow-exec` and `--allow-network`, including when launched by an MCP client. Existing stdio-only configurations continue to work with `--allow-exec` alone.

HTTPS validates the server certificate and hostname. Public destinations are required by default. Internal servers need `"allow_private_network": true`; link-local, multicast, unspecified, and reserved addresses remain prohibited. Every request resolves and checks all returned IP addresses and connects directly to a validated address, retaining hostname verification for TLS. Redirects and environment HTTP proxies are not used. For local development only, plaintext HTTP requires both `"allow_insecure_http": true` and private-network opt-in, and all resolved destinations must be loopback.

HTTP support covers initialization, session and protocol headers, POST JSON results, and inline SSE results including chunked transfer framing. It does not implement OAuth discovery/refresh, legacy HTTP+SSE, background GET streams, SSE resumption, or server-initiated requests. A lost stream or expired session fails the operation without automatic re-execution. Restart the gateway to establish a new session after a backend failure. HTTP behavior follows the scoped [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

### Activity reports

```sh
python3 -m mcpsentry report --state-dir .mcpsentry/demo
python3 -m mcpsentry report --state-dir .mcpsentry/demo --format json
python3 -m mcpsentry events --state-dir .mcpsentry/demo --decision block --format table
python3 -m mcpsentry events --state-dir .mcpsentry/demo --session SESSION_ID --follow
```

Reports distinguish attempts, dispatches, pre-dispatch blocks, withheld responses, upstream failures, tool errors, and monitor-mode violations. Started and finished events do not double-count call attempts. Average and maximum latency cover calls with recorded finish/failure events, including catalog refresh; incomplete calls remain visible as starts. Per-tool summaries show up to 500 tools; totals cover the full selected session or database. Filter reports with `--session` to avoid combining previous demo runs. Audit findings count events and may include multiple findings for a single call.

### Outbound sensitive-data inspection

DLP is enabled by default, even without `sensitive_sources`. It inspects argument keys, nested objects and arrays, strings, and numeric values before `tools/call` reaches either a stdio or HTTP upstream. In enforce mode, a detection blocks the entire call. Monitor mode records `would_block` and still forwards it.

| Category | Detection coverage |
| :--- | :--- |
| `credentials` | Common AWS, GitHub, OpenAI-style, Slack, Stripe, and Google token formats; JWT-shaped credentials; Bearer/Basic strings; URL user/password credentials; password/token/API-key fields and common assignments. |
| `private_key` | PEM and PGP private-key markers and labeled private-key fields. |
| `payment_card` | 13–19 digit candidates checked with Luhn, plus labeled card/CVV/CVC fields. |
| `iban` | Compact or grouped IBAN-like strings checked with mod-97, plus labeled IBAN fields. Country-specific lengths and actual account ownership are not verified. |
| `national_id` | Plausible hyphenated US SSN patterns and labeled SSN values. Other identifiers rely on field labels or custom rules. |
| `email`, `phone` | Email-shaped text and international `+` phone patterns, plus labeled email/phone fields. |
| `sensitive_field` | Labeled identity, address, birth-date, tax, bank, patient, and health data; administrator-defined fields. Labels are heuristics, not proof of sensitive content. |
| `custom` | Normalized literal terms supplied directly or through environment variables. |
| `confidential_text`, `health_information`, `personal_information` | Default context cues in free-form text, with optional additional findings from an explicitly configured local classifier. These are heuristics, not complete semantic PII detection. |
| `opaque_payload` | Explicit inline binary payloads or recognized binary formats that cannot be inspected, invalid explicit Base64, `file://` references, and labeled `file_path`, `attachment_path`, `upload_path`, `file_uri`, or `attachment_uri` arguments. |

Inspection normalizes Unicode compatibility characters and zero-width format characters; decodes HTML entities, URL percent escapes, JSON text, `\\u`/`\\x` escapes, Base64/Base64url, hex, readable byte arrays, and bounded gzip/zlib/ZIP content. ZIP names and comments are inspected without extracting files. Recognized PDFs and Office attachments use a separate text-extraction worker; missing parsers or incomplete document coverage remain opaque. Images, unsupported compression and encrypted ZIPs remain blocked. No argument-supplied local paths are opened and no URLs are fetched by the deterministic inspector. The optional local model adapter intentionally receives inspected text. Arbitrary unpadded encoded binary, unfamiliar encodings, encrypted data and deliberately fragmented payloads can evade heuristics; use isolated runners for stronger control of actual server egress.

Decoder limits fail closed: 32 structural levels, 20,000 visited nodes, four decoding layers, 1 MiB per expanded payload, and cumulative character/decoded-byte budgets of 4 MiB each. Generic ZIPs are limited to 32 entries and 1 MiB declared expansion; recognized Office packages use the separate worker's [document limits](docs/CONTROLS.md#3-inspect-document-attachments). Limits produce `dlp_inspection_limit` in enforce mode; classifier failure produces `semantic_inspection_failed`. Monitor mode still forwards policy violations. Large or complex benign payloads can hit these limits.

Add optional DLP settings inside `policy`:

```json
{
  "dlp": {
    "enabled": true,
    "custom_terms": ["INTERNAL PROJECT EXAMPLE"],
    "custom_terms_env": ["MCP_CONFIDENTIAL_REFERENCE"],
    "sensitive_fields": ["internal_notes", "customer_export"],
    "allow_rules": [
      {"tool": "mail__send", "path": "/to", "categories": ["email"]}
    ]
  }
}
```

Each custom-term environment variable holds one literal term (3–4096 normalized characters). Missing configured variables fail startup. Prefer environment variables for confidential literals: config files and baselines should not contain production secrets. Baselines bind environment variable names, not their resolved contents.

All listed categories block by default. `block_categories` can explicitly select a subset, for example `["credentials", "private_key", "payment_card", "iban", "national_id", "opaque_payload"]`; omitting personal-data categories reduces coverage. `block_secrets: false` removes credential and private-key DLP categories. `dlp.enabled: false` disables the new inspector while retaining the original narrow secret-pattern check when `block_secrets` is true. Changes to these settings change the config hash and require a deliberately reviewed new baseline.

Allow rules are exact JSON-pointer paths scoped to tool-name patterns and specific categories. They never broadly exempt the rest of the payload. Recipient fields that pass an explicit `recipient_allowlists` rule automatically receive an **email-only** exception for that field; the same email in `/body` is still blocked. Use allow rules to permit a known file-read tool's `/file_path` when appropriate. Exceptions do not override tool deny rules, call limits, tracked-source transfer controls, or inspection-limit failures.

`sensitive_destinations` bypasses only tracked-source transfer checks, not the new DLP categories. Configure narrow DLP allow rules separately for intentional sensitive transfers. Logs and client errors contain stable reason/category codes only—never matched values, payload previews, or JSON paths whose keys could themselves contain sensitive data.

Inspect a JSON argument file offline, without launching or contacting MCP servers:

```sh
python3 -m mcpsentry check --input payload.json
python3 -m mcpsentry check --input payload.json --config mcpsentry.json --tool mail__send
```

`check` also accepts JSON on stdin when `--input -` is used (the default). It returns categories only, with exit `2` for a block/inspection limit, `0` for no known pattern, and `3` for an invalid input or disabled inspector. It does not apply tool allow/deny, recipient allowlists, or live-session source tracking; explicit DLP allow rules still apply. A no-match result is not a safety guarantee.

### Track data returned by sensitive sources

`sensitive_sources` marks returned strings of 12 or more characters as sensitive. Strings inside structured JSON and JSON text blocks are tracked individually. Subsequent outbound arguments are compared after compatibility/zero-width normalization, case folding, and whitespace collapsing, including supported decoded representations. The cross-call window can also identify whole tracked values reconstructed from ordered fragments. Paraphrases, short values, arbitrary transforms, and fragments outside the retained window can evade it. Values stay in bounded session memory and are not persisted. If source tracking capacity is exceeded, untrusted destinations are blocked for the remainder of the session.

Enforce mode is the default. Monitor mode records `would_block` and **forwards policy-violating calls**:

```sh
python3 -m mcpsentry run --config mcpsentry.json --allow-exec --mode monitor
```

Malformed backend traffic and unsupported non-text tool content fail closed in both modes. Recognizable instruction patterns in descriptions and textual results can be blocked, but this small rule set will miss attacks and can flag benign text. Blocking a response happens after the underlying tool ran; side effects cannot be undone.

## Scan and approve a baseline

For local servers, these commands require explicit execution authorization. HTTP configurations instead require `--allow-network`; mixed configurations require both flags:

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
- Local server commands without a configured Docker profile run with your OS user's rights. Minimal environment inheritance is not isolation. Set `require_sandbox` to reject unrestricted local entries; remote HTTP servers cannot be OS-isolated by this gateway.
- Only traffic routed through this process is visible. Remote internals, server-side file/network access, and the client's built-in tools are outside coverage.
- Supported: client-facing newline JSON-RPC stdio, stdio and scoped Streamable HTTP upstreams, initialization/ping, paginated upstream tool listing, text/structured tool results, sequential calls. Stdio protocol versions: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25. HTTP uses the three 2025 versions.
- Not implemented: an incoming HTTP listener, OAuth, resources, prompts, sampling, elicitation, task APIs, client cancellation, native client permission dialogs, multi-client shared tracking, full JSON Schema validation of call arguments, OCR, or a network allowlist proxy for isolated containers. Server-initiated requests are rejected; upstream notifications are not forwarded. Outgoing inline arguments receive bounded DLP inspection; non-text upstream tool results remain blocked.
- DLP covers routed tool arguments, not the network activity a server performs internally, client built-in tools, or arbitrary referenced file contents. It cannot identify all sensitive data. False positives and false negatives are expected; free-form names, addresses, medical narratives, proprietary text, split payloads, and encrypted content require additional controls. Static authentication headers intentionally configured for remote MCP access are outside tool-argument DLP.
- A timeout after dispatch means the operation may already have happened. MCP-Sentry does not retry it. Calls are serialized and the timeout is per upstream request; refreshing several catalogs adds latency.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m mcpsentry demo
```

Tests include real stdio subprocesses, local HTTP fixtures, socket-free HTTP framing/session fixtures, DNS destination controls, policy enforcement, and audit privacy. In environments that deny binding loopback sockets, six live HTTP tests are explicitly skipped; socket-free tests still execute. Live HTTP/TLS interoperability with third-party servers remains unverified in this environment.

Architecture: `config.py` validates configuration; `transport.py` and `http_transport.py` connect upstreams; `sandbox.py` builds the isolation profile; `approvals.py` binds single-use grants; `documents.py` and its worker extract attachment text; `semantic.py` runs context/local classifiers; `dlp.py` inspects outbound data; `security.py` makes policy decisions; `gateway.py` serves the client; `audit.py` stores metadata; `cli.py` exposes commands.

Next milestones: complete the blocked integration checks, evaluate model quality with adversarial corpora, add controlled network egress and OCR, and replay policies against metadata-safe fixtures. Features above are scoped to this experimental project, not a production security certification.

## License

MIT. See [LICENSE](LICENSE).
