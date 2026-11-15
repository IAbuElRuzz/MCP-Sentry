# Advanced protection

MCP-Sentry 0.6 adds catalog change reports, destination policies, offline scenario tests, and independent response inspection. Existing configurations remain valid. Response DLP and destination restrictions require explicit configuration. Monitor mode reports findings without changing arguments or text responses.

## Tool-change detection

Create an explicit approved baseline after reviewing a server:

```sh
python -m mcpsentry baseline --config mcpsentry.json --allow-exec --output baseline.json
python -m mcpsentry scan --config mcpsentry.json --allow-exec --baseline baseline.json
python -m mcpsentry run --config mcpsentry.json --allow-exec --baseline baseline.json
```

For HTTP servers use `--allow-network`; mixed configurations require both flags. These commands start/contact the configured servers. Baselines contain hashes, never descriptions, schemas, commands or environment values. Version 2 stores individual hashes for description, inputSchema, outputSchema, title and annotations. Scan reports `catalog_changes`, including additions, removals, configuration changes, and the names of changed fields. Audit events also report these field names. Changes to annotations such as readOnlyHint or destructiveHint are detected even though the gateway does not forward those untrusted claims to clients.

The gateway refreshes tool metadata before every dispatch. Changed/new tools are blocked by default. Removed tools cannot be called. Without an explicit baseline, the first discovery is pinned only for the current session. Version 1 baselines remain usable, but cannot report per-field differences or compare historical annotations. Baselines do not prove server behavior; servers can lie or change behavior without changing metadata.

## Destination policies

Destination rules supplement exact recipient allowlists and DLP:

```json
{
  "destinations": {
    "rules": [{
      "tool": "mail__send",
      "path": "/to",
      "kind": "email",
      "internal_domains": ["company.test"],
      "external_domains": ["partner.test"],
      "external_action": "approval",
      "unknown": "block",
      "allow_subdomains": false
    }]
  },
  "approvals": {"enabled": true}
}
```

Place these keys under `policy`. `kind` accepts `email`, `url`, or `domain`. Paths are exact JSON pointers and can select a string or a list of strings. Every matching rule must pass. Missing, empty and malformed destinations are blocked. Domains are normalized using IDNA and case folding. Subdomains require an explicit opt-in and use a dot boundary; `company.test.evil.test` never matches `company.test`.

Known external destinations can be allowed (default), blocked (`external_action: block`), or require the existing exact-request approval workflow (`approval`). Approval requires `approvals.enabled`. If a domain appears in both lists, the external restriction applies. Unknown domains are blocked by default; `unknown: allow` is an explicit relaxation. Rules do not classify domains automatically.

URL destinations require HTTPS and reject credentials, fragments and malformed ports. Their paths and query strings still undergo DLP. Only the email-category finding for an approved recipient field is exempted; secrets, tracked values and other data remain inspected. Being an internal destination never bypasses body inspection. Redaction cannot modify configured destination fields. These controls inspect declared arguments; they do not intercept a backend's independent network traffic, DNS changes or redirects.

## Response inspection

Configure `policy.responses` independently from outbound DLP:

```json
{
  "responses": {
    "enabled": true,
    "redaction": {
      "enabled": true,
      "rules": [{
        "tool": "mail__send",
        "paths": ["/content/0/text"],
        "categories": ["email"]
      }]
    }
  }
}
```

All returned text blocks and structuredContent undergo response DLP before reaching the agent. Response DLP accepts the same `dlp` configuration as outbound inspection, including category controls and scoped allow rules; it does not inherit outbound exemptions. Explicit redaction rules can target text and structuredContent string fields. A rewritten response is re-inspected in full; any remaining violation withholds the entire original response. Redactions add a visible notice and metadata. Injection-pattern findings are withheld rather than rewritten, and existing `block_poisoning` remains enabled by default even when response DLP is off.

Images, resource blocks and other unsupported content remain withheld by the tools-only gateway. Injection detection is heuristic, with false positives and false negatives. Withholding a response cannot undo upstream side effects. Sensitive-source tracking conservatively observes the original result before response filtering, in process memory only. Audit events contain fixed reason codes and tool aliases, never response bodies.

## Offline policy tests

```sh
python -m mcpsentry policy-test \
  --config examples/protection-policy.json \
  --input examples/policy-scenarios.json
```

No MCP server starts and no endpoint is contacted. The runner accepts a bounded JSON `steps` array. Each step has `name`, optional `arguments`, an optional simulated MCP text `response`, optional `advance_seconds`, and optional `expect`. Supported expectations are `allow`, `block`, `redact`, `response_block`, `response_redact`, and `approval_required`. Exit status is 0 when expectations pass, 2 on mismatch, and 3 for invalid inputs. Omitted expectations simply report the decision.

Allowed simulated dispatches update call budgets and cross-call history. Supplied responses update sensitive-source history and undergo response inspection. A virtual clock makes expiry tests deterministic. Output contains step numbers, decisions and reason codes, without payloads. Test files themselves may contain sensitive information: use synthetic fixtures. External semantic command configurations are rejected so tests cannot invoke classifiers. Local document parsing can use the existing bounded extraction worker. Tests do not execute approval grants, inspect live catalogs or establish server safety.
