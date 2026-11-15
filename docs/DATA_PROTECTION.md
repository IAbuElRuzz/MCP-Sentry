# Redaction and cross-call leak detection

These are gateway features. They require no container installation and work with the stdio and HTTP upstream connections already supported by MCP-Sentry.

Try the inert demo:

```sh
python3 -m mcpsentry demo --features
```

It redacts a plain email, removes an encoded sensitive field, allows an initial fragment and blocks a later call that completes an email. All tools are inert: nothing is emailed or sent over the network.

## Redact eligible content before forwarding

Redaction is **off by default** because it changes the requested action. Enable exact string-field rules inside `policy`:

```json
{
  "redaction": {
    "enabled": true,
    "rules": [
      {
        "tool": "mail__send",
        "paths": ["/body"],
        "categories": ["email", "phone", "payment_card", "credentials", "private_key", "tracked_data"]
      }
    ]
  }
}
```

`examples/redaction.json` is a runnable demo-server configuration. Replace the server with one you have reviewed and adjust the tool aliases/field pointers for its schema.

For plain email, phone, payment-card, IBAN and national-ID patterns, matched spans become `[REDACTED]` while surrounding text is preserved. Credentials/private keys, semantic/custom classifications and supported encoded payloads lose the **whole selected string** when reliable substring offsets are unavailable. The `tracked_data` category permits removing a string containing a value previously returned by a sensitive source. Empty fields stay strings; numeric values and objects are not silently converted or deleted.

The gateway then repeats the full policy/DLP check on the candidate, including argument constraints and cross-call history. If anything remains blocked, the original request is blocked rather than partly sanitized and forwarded. After a successful rewrite, the tool result gets a visible notice and `_meta.mcpsentry` redaction/count metadata. Audit events record `call_redacted` and a fixed reason, not original values, snippets or paths. `report` includes a `redacted_calls` metric.

Known recipient/routing/operation fields and explicitly configured recipient fields cannot be redaction targets. Sensitive keys, opaque files, failed/incomplete inspection, tool denies, call budgets, metadata changes and injection findings stay blocked. Unknown custom routing fields cannot be inferred automatically; administrators must select only content fields whose modification is acceptable to that tool. An empty or modified body can still be rejected by the upstream tool. Full JSON Schema validation remains outside this version.

Monitor mode **does not rewrite or block**: it forwards the original arguments and records violations. Redaction rules require DLP to remain enabled. Field allow rules still govern classification; opting a category out of DLP also reduces what can be redacted.

### Generate a private sanitized request file

Input format:

```json
{
  "name": "mail__send",
  "arguments": {"to": "team@example.com", "body": "Contact fictional.person@example.com"}
}
```

```sh
python3 -m mcpsentry redact --config examples/redaction.json --input request.json --output sanitized.json
```

The command starts no MCP servers. It writes a new owner-only file, refuses overwrites, and prints metadata only. If a violation remains, it exits `2` and writes no output. A successful fresh-session check has no live source history or upstream metadata; it is not proof that all sensitive content was found. The output retains unredacted argument values, so keep it private.

If mandatory approvals are enabled, redaction occurs first and the grant binds the **rewritten** arguments. The pending response says `request_arguments_redacted=true`. Review the sanitized request, not the original, using the approval CLI; retrying changed arguments cannot reuse the grant. No human approval silently authorizes a different post-approval rewrite.

The offline command cannot reproduce a rewrite that depends on live fragment history or source values. For that case, prepare and submit an explicitly sanitized request, then review its new approval. A mismatched request file is rejected rather than granting an unseen payload.

## Recognize sensitive content spread across calls

Cross-call inspection is enabled by default. Settings inside `policy`:

```json
{
  "cross_call": {
    "enabled": true,
    "window_seconds": 120,
    "max_calls": 16,
    "scope": "session"
  }
}
```

The window keeps only **dispatched arguments**, including attempts that later time out because they may already have executed. Blocked attempts and original pre-redaction values do not enter it. Data stays in process memory and is dropped on expiry/session close; it is never written into the audit database.

The detector reconstructs normalized field/value channels and an aggregate channel across tool calls. It looks for tracked source values, configured custom literals, and recognizable credential, key-marker, email, phone, card, IBAN and SSN patterns crossing the new call boundary. Independently Base64/Base64url-, URL-, HTML- or hex-encoded readable fragments get a decoded channel as well. Known exact fragments can be matched in order despite unrelated intervening calls. Validated fixed recipient fields are excluded from the reconstruction streams.

`scope: session` correlates calls across tools and servers. `scope: server` uses the actual upstream server identity in the gateway, reducing cross-server correlation. The window can cover 2–64 dispatched calls and 1–3600 seconds. It is not shared between processes or restarts.

A match produces `cross_call_sensitive_transfer`. In enforce mode the completing call is blocked before forwarding. If an explicit redaction rule can identify and clear its contributing string field, that field can instead be removed and the candidate rechecked. Ambiguous aggregate findings remain blocked. Reconstruction failures/capacity limits produce the hard `cross_call_tracking_capacity` reason and cannot be bypassed with an action approval.

**Previously sent fragments cannot be retracted.** This catches some completions, not every partial disclosure. A recipient may already have learned useful information from the first fragment. Reordering, arbitrary padding/transforms, selecting characters, unsupported encoding split across calls, encrypted payloads, or spreading fragments outside the retained window can evade detection. Pattern reconstruction can also flag benign combinations. Existing whole-value DLP findings continue through ordinary DLP/approval handling rather than being treated as new fragment completions.

The implementation caps each request's reconstruction at 4,096 nodes/32 structural levels, 128 field/encoding channels plus aggregates, 65,536 intermediate characters and 131,072 retained channel characters. History is limited to 32 destination buckets and two million retained characters overall, with bounded prefix-comparison work. In enforce mode, exceeding a cap blocks rather than silently dropping history. Monitor mode can forward beyond coverage; the tracking gap is reported until its window expires. These limits can block large benign payloads; `cross_call.enabled: false` disables reconstruction while leaving single-call DLP/source checks active.

Only routed MCP arguments are observed. This does not inspect an MCP server's independent network activity or the AI client's provider traffic, and does not guarantee detection of every sensitive disclosure.
