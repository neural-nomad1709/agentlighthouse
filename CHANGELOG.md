# Changelog

All notable changes to AgentLighthouse are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

The root `pyproject.toml` version and the three workspace members
(`core/`, `verify/`, `governance/`) move together as one release version —
see `scripts/bump-version.sh`. The released git tag (`vX.Y.Z`) is the
source of truth; it is what `publish-image.yml` reads to tag the image.

## [Unreleased]

### Added
- HITL approvals are single-use **grants**. After approval the agent retries the
  same `tools/call`, optionally naming the request in
  `params._meta["agentlighthouse/hitl_request_id"]`. The grant is bound to the
  actor, tool, argument digest and session, and lapses `hitl_timeout_s` after
  approval. Retrying while a request is pending reuses it instead of queueing a
  duplicate.
- The approval request's `detail` shows the tool and its (DLP-redacted)
  arguments, so the approver sees what they are approving.
### Changed
- The control plane resolves approvals in the data plane's
  `capability_state.db` when `control.dataplane_dir` is set. Resolutions now
  persist in the store (table `approval_requests`, replacing `approvals`) until
  they are spent or their window lapses. Requests pending in the old table at
  upgrade are dropped, so agents re-ask.
- `ActionGate.resume()` takes the call's `args` and only allows the exact call
  that was approved, once.
### Fixed
- The HITL gate forgets approval requests two windows after they were filed,
  when every state is final. Before, its in-memory map grew without limit.
- Human approval now executes (D1). Before, an approved request had no path
  back to the call: every retry filed a new request. `/mcp` approvals also
  could never reach the data plane from the control plane.
### Security
- MCP `tools/list`: two different descriptors under one tool name are both
  withheld and receipted (`TOOL_DESCRIPTOR_DRIFT`). Before, a poisoned twin
  rode through on its clean twin's verdict (D2).
- MCP responses: a reply is relayed only if it answers an in-flight request,
  once. Duplicate or unknown ids are dropped and receipted, agents cannot reuse
  an in-flight id, and non-object `tools/call` results are withheld (D3).
- MCP server-initiated requests and notifications (`sampling/createMessage`,
  logging, progress) and error replies are content-scanned. Before, they
  reached the agent unscanned (D3). HTTP `/mcp` filters batch (array) replies
  instead of returning them raw.
- MCP replies are content-scanned whatever the method. `tools/call` results are
  scanned in full: embedded resources, `resource_link` descriptions,
  `structuredContent` and `_meta`, plus base64 `blob`/`data` that decodes to
  UTF-8 text. Binary media is skipped. A content block of unknown `type` is
  withheld. Replies to `resources/read`, `prompts/get`, `initialize` (its
  `instructions`) and list methods are scanned too, and a blocked one becomes
  a JSON-RPC error. Before, only `type:"text"` tool-result blocks were read
  (D4). A resource `uri` is scanned without its scheme, so `file://` resources
  do not trip the dangerous-scheme rule.
- MCP `tools/call` is allowed only for a tool in the last `tools/list` the agent
  received. Before, a tool withheld as poisoned, drifted or ambiguous could
  still be called by name (D5). The denial is `TOOL_NOT_ALLOWED` with rule
  `mcp.tool_not_advertised`. Paginated lists accumulate, a list without a
  `cursor` replaces the set, and `notifications/tools/list_changed` clears it.
  A later page that withholds a name (a different twin of an earlier page's
  tool) revokes that name.
  **Behavior change:** a client must list tools before calling them. A call
  sent before the `tools/list` reply arrives is denied.
- MCP: a server request that is blocked (e.g. a poisoned `sampling/createMessage`)
  is still answered upstream: `elicitation/create` with `{"action": "decline"}`,
  anything else with a JSON-RPC error. Before, it was dropped and the server
  waited forever.
- MCP: the agent's replies to server requests are forwarded only if they
  answer a request the agent was shown, once; others are dropped and
  receipted (`mcp.reply.unmatched_id`). An allowed reply is DLP-scanned on
  its way to the server: a secret is redacted, and an unredactable one (e.g.
  a seed phrase) replaces the reply with a refusal.
- Receipt spec: new action `mcp_client_reply` (additive; older verifiers
  still check these receipts) for the agent's replies to server requests.
- `McpSession.filter_response` returns a `FilterOutcome` (`forward` to the
  agent, `reply` to the server) instead of a dict, so a transport cannot drop
  the answer to a refused server request.
- Unanswered requests are capped at 1024 per direction per MCP session, so a
  peer that never answers cannot grow the session's memory.
- Chain detector: a flagged session keeps blocking every exfil-category call.
  Before, it stopped after the first flag, and padding the history could lapse
  the match (D10).

## [0.2.1] - 2026-09-27

### Added
### Changed
### Fixed
- `core/al_core/keys/` (the key-management module) is now tracked: the
  unanchored `keys/` ignore rule had kept it out of the repo, so a clean
  clone failed with `ModuleNotFoundError: al_core.keys`. Key material under
  `/keys/` stays ignored.
- `publish-image.yml`: the SBOM step no longer tries to upload a release
  asset (it needed `contents: write` and failed), which had also skipped
  cosign signing. The SBOM is attached to the image via `cosign attest`.

### Security

## [0.2.0] - 2026-09-27

### Added
- HITL approvals are served: approvals API plus `al hitl` CLI verbs.
- HITL approvals and taint marks are persisted and rehydrated on boot;
  HitlGate requests carry detail and session, persisted and surfaced.
- Opt-in detect-secrets adapter behind the `Scanner` protocol
  (`al-core[scanners]` + `scanner.detect_secrets.enabled: true`).
- `al_core.embed` embedding facade.
- Receipt spec v1.1: additive remote-execution actions (`remote_exec`,
  `session_open`, `session_close`, `permission_request`).
- `CHANGELOG.md`, `scripts/bump-version.sh`, and `make bump-version` for
  coordinated release versioning across the workspace (root + `core/` +
  `verify/` + `governance/` move as one version, tagged `vX.Y.Z`).

### Changed
- `.gitignore`: anchor `/.internal/` to the repo root; ignore `/paper/*`
  build output.
- `README.md`: refresh test counts (711 total / 699 passing), document the
  detect-secrets adapter, drop "pending trademark clearance".
- Root `pyproject.toml` version aligned with the workspace members (was
  `0.0.0`); `Makefile` `IMAGE` tag now tracked by `bump-version.sh`.

### Fixed
- Per-actor tool-call budgets are enforced at the ActionGate (previously
  declared but never checked); budget is consumed only after all gates pass,
  `0` means disabled, and the window is locked.

### Security
- AL-0 review fixes: adapter fail-opens closed, approvals tenancy enforced,
  deadline hardening.

## [0.1.0] - 2026-09-27

- Initial tracked version: egress gate, content gate, action gate, memory
  guard, signed evidence receipts; HITL approvals; per-actor tool-call
  budgets; A2A card/session hardening; standalone `al-verify` receipt
  verification.
