# Security policy

MCP-Sentry is an experimental local stdio gateway. It has not received an independent security audit. The README lists current coverage and limitations.

Do not include credentials, customer records, raw tool responses, or private server configurations in public issues. Report reproducible security problems with inert examples and describe whether the issue bypasses a configured policy, discloses audit data, or crosses the documented protocol boundary.

Only the current development version receives fixes. Do not rely on this MVP as the sole control for untrusted code: server subprocesses retain your OS permissions. A tool may perform side effects before returning a blocked response or timing out.
