# Security policy

Redaction is opt-in and affects only explicitly selected string fields. Candidates are rechecked; unresolved findings block the call, and opaque/uninspectable payloads cannot be redacted around inspection. Rewrites are disclosed to clients and audited without previews. Cross-call detection retains bounded dispatched fragments in memory and can block a completing call, but cannot recall earlier fragments or cover every transformation/window boundary. Monitor mode neither rewrites nor blocks. See [data protection](docs/DATA_PROTECTION.md).

MCP-Sentry is an experimental client-facing stdio gateway for local stdio and remote HTTP MCP servers. It has not received an independent security audit. The README lists current coverage and limitations.

Do not include credentials, customer records, raw tool responses, or private server configurations in public issues. Report reproducible security problems with inert examples and describe whether the issue bypasses a configured policy, discloses audit data, or crosses the documented protocol boundary.

Only the current development version receives fixes. Do not rely on this MVP as the sole control for untrusted code: server subprocesses retain your OS permissions. A tool may perform side effects before returning a blocked response or timing out.

Remote connections validate TLS by default, reject redirects, and pin validated DNS answers to sockets. Internal-address access requires explicit configuration; plaintext HTTP is limited to explicitly enabled loopback destinations. HTTP proxies, OAuth negotiation, and server-driven request handling are not supported. Report any bypass of these destination restrictions with an inert reproduction.

Outbound DLP inspects inline tool arguments with bounded decoding and emits category codes only. It does not open referenced files or monitor a server's independent network activity. Recognized opaque attachments and labeled file references are blocked in enforce mode unless explicitly exempted. Monitor mode forwards violations, including inspection-limit findings. Pattern matching and sensitive-field labels cannot identify all personal or proprietary information; semantic transformations, fragmentation, unfamiliar formats, and encryption can evade detection. Custom exception rules and disabled categories can reduce protection.

Optional Docker isolation blocks local server networking and restricts filesystem/process privileges; it requires a trusted local daemon and reviewed image, and is not enabled for ordinary direct-execution entries. Approval grants are local owner-operated capabilities, not protection from other processes with the same account/state access. Explicit interactive review prints the payload on the operator's terminal; audit/approval databases do not store it. Hard policy violations and uninspected/opaque payloads cannot be approved.

Document workers use deadlines/CPU and output bounds, with Linux address-space limits and a best-effort macOS RSS watchdog. They are not OS sandboxes. A configured semantic command receives inspected data as trusted local software; the Ollama adapter is loopback-only but the operator must choose a local model rather than a cloud-backed model. Context rules and model verdicts can miss malicious or private content. See [runtime controls](docs/CONTROLS.md) for exact limits and unverified integrations.
