# Changelog

## 0.7.0

- Add a token-protected loopback dashboard with read-only audit access, session/decision filters, timeline search, live refresh and metadata export.
- Add interactive and preview-first Claude Desktop/Cursor setup, absolute launch paths, explicit direct-entry removal, private backups and change-aware rollback.
- Package dashboard assets and desktop launcher with the Python distribution.


## 0.6.0

- Hash-only tool metadata component baselines and field-level change reports, including annotations.
- Exact domain destination rules with internal/external lists, unknown blocking and optional external approval.
- Independent response DLP, explicit response redaction and expanded injection patterns.
- Offline synthetic policy scenarios with session history, virtual time and expected decisions.
- Runnable example policy/scenarios and CI checks.


## 0.5.0

- Add opt-in sensitive string-field redaction with safe-text preservation, whole-field removal for secrets/encodings, full policy rechecks and visible rewrite notices.
- Add private offline `redact` output, protected recipient/routing fields, redaction audit metrics and exact rewritten-request approval binding.
- Reconstruct bounded cross-call fragment channels across tools/servers, including independently encoded fragments, tracked source values and custom terms; keep dispatched data in session memory only.
- Add `demo --features` and adversarial tests for completing-call blocks, history expiry, blocked-attempt isolation, non-mutating monitor behavior and raw-data-free audit records.

## 0.4.0

- Add opt-in Docker isolation for local MCP servers, with no network, non-root execution, read-only files/root, dropped capabilities and resource constraints. Required isolation fails closed.
- Support a maintained pdfminer.six extraction fallback and discover the macOS Cursor launcher outside PATH. Official SDK client/server and pdfminer-backed PDF checks were executed in a dedicated offline-installed Python 3.13 environment.
- Add atomic single-use, expiring action approvals bound to the exact request, session, configuration and tool metadata, plus terminal review/confirmation and mandatory approval tool patterns.
- Extract Office XML text and optional PDF text in a limited worker; unsupported/incomplete documents remain blocked. No OCR or legacy Office parsing.
- Add built-in context cues and an opt-in local command/Ollama classifier that can add findings but never clear deterministic findings.
- Add runtime diagnostics, official SDK/PDF/Docker integration tests and strict inert Claude smoke checks. Local integration blockers remain documented; these checks are not claimed as passed without execution.

## 0.3.0

- Inspect nested outbound arguments and keys for credential formats, private keys, personal-data patterns, financial checksums, and labeled sensitive fields.
- Decode bounded inline Base64, URL/HTML escapes, hex, JSON, readable byte arrays, gzip/zlib, and ZIP content; reject recognized opaque attachments and file references by default in enforce mode.
- Add scoped tool/field/category exceptions, custom literals and environment-provided terms, and custom sensitive fields. All categories block by default; this can require new exceptions for previously allowed workflows.
- Normalize tracked source values and supported encoded outbound representations before transfer checks.
- Add offline `check` and a twelve-scenario `demo --dlp`; detection output never includes matched values.

This remains heuristic inspection of routed arguments, not complete PII recognition or OS-level egress control. Monitor mode continues to forward violations.

## 0.2.0

- Connect remote MCP tool servers using scoped Streamable HTTP: POST JSON and inline SSE, negotiated protocol headers, environment-provided authentication headers, and session lifecycle.
- Validate DNS destinations and pin addresses to sockets; reject redirects and unsafe addresses; require explicit remote-network authorization.
- Apply nested argument constraints using JSON pointers and share per-session call budgets across tool-name patterns.
- Summarize attempts, forwarding, blocks, failures, tool errors, and latency with `report`; filter and format live audit events.
- Preserve existing stdio configuration and default enforcement behavior.

HTTP listener, OAuth, background SSE streams, full schema validation, sandboxing, and interactive approvals remain outside this release. Live network integration tests require an environment that allows loopback sockets.

## 0.1.0

- Initial local stdio gateway, policy engine, sensitive-value tracking, metadata baseline checks, redacted audit events, and inert demo.
