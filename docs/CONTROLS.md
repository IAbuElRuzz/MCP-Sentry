# Runtime controls and verification

These controls are opt-in where they change execution privileges or require a local runtime. Use `python3 -m mcpsentry doctor` to see which dependencies are available. None of the commands below install Docker, start a daemon, download a model, or configure a cloud account automatically.

## 1. Isolate local MCP servers

MCP-Sentry can run a local stdio server inside a fixed Docker profile:

- No container network (`--network=none`).
- Read-only root filesystem and explicitly selected read-only host **files**, never host directory trees or sockets.
- Non-root UID/GID 65534, all capabilities dropped, no new privileges.
- CPU, memory/swap, process and temporary-storage limits.
- No image pulls during execution and no fallback to an unrestricted host process.

The administrator must trust the local Docker daemon and review/build the image. Prefer immutable image digests for actual deployments. A container is a security boundary with runtime/kernel dependencies, not proof that arbitrary code is harmless.

Build the inert fixture after starting Docker yourself:

```sh
docker --context default build -f examples/Dockerfile.demo -t mcpsentry-demo:local .
python3 -m mcpsentry sandbox-plan --config examples/sandbox.json
python3 -m mcpsentry scan --config examples/sandbox.json --allow-exec
```

`examples/sandbox.json` requires all local servers to have a sandbox. The same policy can be applied to another config with `"require_sandbox": true`. A sandbox server retains the usual `command`, `args`, and `env` fields; `command` must identify a program inside its image. Its optional profile is:

```json
{
  "sandbox": {
    "image": "your-reviewed-server:version",
    "workdir": "/workspace",
    "memory_mb": 256,
    "pids_limit": 64,
    "mounts": [{"source": "./public-input.txt", "target": "/workspace/input.txt"}]
  }
}
```

Mount sources resolve relative to the config. They must be individual regular files. Bake code directories into the image instead. Files containing gateway state or the approval key cannot be mounted. Environment values are passed through an unlinked private descriptor, not Docker's argv or its host process environment. Newline-containing sandbox environment values are rejected. `sandbox-plan` shows the server command/arguments, so do not put secrets in command arguments.

This profile intentionally prevents even otherwise approved tool calls from making network connections. Approvals do not weaken the container restrictions. Networked local servers need a future controlled egress proxy; remote HTTP servers remain outside local OS isolation. Direct local execution still exists for trusted servers unless `require_sandbox` is enabled.

## 2. Approve one exact action

Configure the gateway policy:

```json
{
  "approvals": {
    "enabled": true,
    "tools": ["mail__send"],
    "ttl_seconds": 120,
    "reasons": ["sensitive_data:*", "sensitive_data_transfer"]
  }
}
```

`tools` makes approval mandatory for every matching tool, even when no detector identifies a problem. Omit it to request approvals only for supported policy violations. The runnable inert config is `examples/approvals.json`.

When a call needs review, the gateway returns `approval_pending; request_id=...` without dispatching it. This is an out-of-band terminal workflow, not a native Claude/Cursor permission dialog. Keep the gateway process running. Save the exact request in a private file you control, including both fields:

```json
{
  "name": "mail__send",
  "arguments": {"to": "team@example.com", "body": "fictional.person@example.com"}
}
```

Then, in a separate terminal using the same private state directory:

```sh
python3 -m mcpsentry approvals list --state-dir .mcpsentry
python3 -m mcpsentry approvals approve REQUEST_ID --payload request.json --state-dir .mcpsentry --interactive
```

The interactive command displays the exact arguments and reason codes and requires a typed request-specific confirmation. It needs a real terminal. **This explicit local review displays sensitive values on your terminal**, which may itself be recorded by your environment. The application does not save the payload.

A two-command flow is also available:

```sh
python3 -m mcpsentry approvals review REQUEST_ID --payload request.json --state-dir .mcpsentry
python3 -m mcpsentry approvals approve REQUEST_ID --payload request.json --state-dir .mcpsentry --confirm REVIEW_CODE
```

After approving, retry the same MCP call once before expiry. The grant binds the gateway session, full configuration, tool definition, all reported violations, and exact arguments (including recipients and inline attachment bytes). Changed arguments or a new session cannot reuse it. The SQLite consume transaction is atomic; the token is spent before dispatch. Upstream timeouts do not restore it. `approvals deny REQUEST_ID` rejects a pending or approved grant.

Tool denies, argument constraints, call limits, tool-definition changes, injection findings, incomplete/over-limit inspection, and opaque/uninspected file references cannot be approved. Every violation must independently be eligible: approving a recipient change does not hide a secret violation. Credential release and new recipients require explicit additional `reasons` configuration. These are local owner-operated controls: a process with the same OS account and state access can approve actions, so do not expose the state to untrusted servers or AI shell tools. For stronger separation, run the operator control plane under a separate account outside the agent's access.

Only metadata and HMAC commitments are persisted in the approval database. An owner-only random key prevents guessing low-entropy arguments from those commitments; protect and back up the key/state together if needed. Approval storage is not encrypted payload storage or a remote authentication system.

## 3. Inspect document attachments

Inline Base64/byte payloads recognized as DOCX, XLSX or PPTX are parsed in a separate Python worker. It reassembles split XML text runs and includes textual metadata and relationship attributes. No files are extracted to disk, no external resources are fetched, and XML DTD/entity declarations are rejected.

PDF support requires the optional parser in the **same Python environment** as the gateway:

```sh
python3 -m pip install -e '.[documents]'
```

Alternatively install `.[documents-pdfminer]` for the maintained pdfminer.six backend. The worker prefers pypdf when installed, otherwise uses pdfminer.six. Both backends keep incomplete/active/image-bearing PDFs blocked; the pdfminer backend also treats Form XObjects conservatively as incomplete.

PDF text and ordinary metadata are extracted with the available backend. The worker does not render or execute document actions. Encrypted PDFs, image-only pages, images, annotations/forms/actions, embedded files/macros, unsupported binary parts, missing dependencies, parser errors and timeouts produce incomplete coverage and remain blocked as `opaque_payload`. OCR and legacy binary DOC/XLS/PPT are not implemented. This is text/metadata inspection, not forensic steganography detection or a document malware scanner.

Input is limited to 1 MiB. Worker limits include 32 PDF pages, 128 Office entries, 4 MiB declared Office expansion, 128 Ki characters extracted text, a five-second deadline and CPU limits. Linux uses a 384 MiB address-space limit. macOS may reject hard address/data limits; the parent uses a best-effort 384 MiB RSS watchdog at 200 ms intervals instead, and fails extraction if a required watchdog query is denied. Transient memory overshoot on macOS is possible. The worker is a separate resource-limited parser, not a separate OS sandbox; use a container/VM for stronger containment of parser vulnerabilities.

Use a virtual environment for PDF support: the isolated worker intentionally ignores user-site packages and `PYTHONPATH`. A parser installed only with `pip --user` may not be available to that worker.

Only inline bytes are inspected. `file_path`/`file://` references are not dereferenced and remain blocked unless a deliberate DLP field exception is configured. Approvals cannot turn an uninspected file reference into a content-bound grant.

## 4. Context classification and client interoperability

Built-in context rules add `confidential_text`, `health_information`, and `personal_information` findings for cues such as confidentiality markings, personal medical disclosures, and labeled personal prose. This default is a heuristic context layer, **not a trained semantic model**. It can miss subtle meaning or flag benign discussion. Disable it with `"semantic": {"mode": "off"}` inside `policy.dlp` if needed.

For a real local model, configure a reviewed one-shot classifier command. It receives only JSON on stdin and must return `{"categories": [...]}` using the three categories above. It cannot issue tools, alter arguments, or clear deterministic/context findings. Invalid results, excess output, timeouts or failures block the call. The launcher bounds CPU/output and, on Linux, address space; command mode accepts at most 65,536 characters. The command is trusted local software and may access data/network with your gateway user's rights.

The included Ollama adapter uses only `127.0.0.1:11434`, with no cloud endpoint, redirects, automatic pulls or tools. Start Ollama and install/select a **local** model yourself; do not select a cloud-backed model if data must stay local. Substitute your actual absolute paths and model:

```json
{
  "semantic": {
    "mode": "command",
    "command": ["/absolute/path/to/python3", "/absolute/path/to/MCP-Sentry/mcpsentry/ollama_adapter.py", "--model", "your-local-model"],
    "timeout_seconds": 10
  }
}
```

This belongs inside `policy.dlp`. Model quality and resistance to instructions embedded in inspected data are not guaranteed; deterministic rules always remain active. `examples/semantic.json` demonstrates the dependency-free context mode.

For official SDK interoperability:

```sh
python3 -m pip install -e '.[interop]'
python3 -m unittest discover -s tests -p test_optional_integrations.py -v
```

The real SDK client test initializes the gateway, lists tools and verifies a tool call is blocked. PDF tests use an actual generated PDF. Docker checks run only with a prebuilt fixture image and `MCP_SENTRY_RUN_DOCKER_TESTS=1`. The optional CI job installs these extras and runs Docker checks; its presence does not mean a CI run has passed.

Run an explicit real Claude check with inert data:

```sh
python3 scripts/client_smoke.py --client claude
```

It uses a temporary strict MCP config, disables built-in tools/settings sources/session persistence, permits only the inert fixture calls and verifies **gateway audit events**, not the model's narrative. It may use your configured Claude authentication/subscription. It does not configure credentials or bypass permissions. Cursor needs a manual GUI session; `--client cursor` reports that limitation instead of claiming success. Use `scripts/run_gateway.py` as the source-tree entry point when your client lacks `cwd` support.

### Local verification status for this implementation

| Check | Observed result |
| :--- | :--- |
| Unit tests, real stdio subprocesses, approval binding/replay, Office XML extraction and classifier protocol | Executed locally; see test output. |
| Live HTTP fixtures | Socket binding prohibited; socket-free framing/session tests execute. |
| Docker enforcement | Docker CLI present; after a Desktop restart, socket access still denied by this session; runtime test not verified here. |
| Official SDK integration | Installed MCP SDK 1.28.1 offline in a dedicated Python 3.13 environment. Real SDK client and upstream server tests passed. |
| PDF integration | Installed pdfminer.six 20260107 offline. Real PDF extraction/DLP and active-PDF coverage checks passed. pypdf remains unavailable. Long-running extraction can fail closed if this session denies the macOS memory watchdog. |
| Claude Code | CLI 2.1.231 available. Authentication status reports `loggedIn: false`, `authMethod: none`; strict fixture probe produced no required audit events. |
| Cursor | Installed app/CLI found outside PATH (1.7.44). GUI accessed; extension host reported unresponsive. MCP session remains unverified. |
| Ollama model | CLI present, local service probe unavailable; real model quality/integration not verified. |

The verified SDK/PDF environment is `.mcpsentry/integration-venv`; the default system Python does not share its packages. Run `.mcpsentry/integration-venv/bin/python -m mcpsentry doctor` or `.mcpsentry/integration-venv/bin/mcpsentry` from the source checkout. Installation used existing package caches without changing the original cache or downloading packages.
