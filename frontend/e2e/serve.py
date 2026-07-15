"""Boot the control plane with seeded evidence for Playwright e2e.

Run from the repo root (Playwright's webServer cwd). Seeds a temp data dir with
a spread of receipts across orgs/verdicts, then serves the control plane (which
serves the built dashboard at /dashboard/) on :8899.
"""

from __future__ import annotations

import os
import tempfile

os.environ.setdefault("AL_ADMIN_API_TOKEN", "e2e-token")

import uvicorn  # noqa: E402

from al_core.app import create_app  # noqa: E402
from al_core.runtime import Runtime  # noqa: E402

DATA = os.environ.get("E2E_DATA") or tempfile.mkdtemp(prefix="al-e2e-")


def seed(rt: Runtime) -> None:
    # Spread across verdicts, orgs, and latency: the Trace board needs blocks and
    # holds (alert cards), the Performance board needs timed receipts (fetch and
    # llm_call are the actions that carry latency_ms).
    rt.record(actor="spiffe://acme/agent/claude-code", action="mcp_tool_call",
              target="tool:exec_shell", verdict="block", block_reason="TOOL_DENIED",
              session="sess-acme-1",
              findings=[{"scanner": "tool_policy", "rule_id": "policy.explicit_deny",
                         "severity": "high", "owasp": "ASI02", "mitre": "T1059"}])
    rt.record(actor="spiffe://acme/agent/claude-code", action="fetch",
              target="https://docs.python.org/3/", verdict="allow",
              session="sess-acme-1", latency_ms=142)
    rt.record(actor="user:alice", action="llm_call", target="openai:gpt-4o", verdict="allow",
              latency_ms=1180)
    rt.record(actor="user:bob", action="fetch", target="https://site/x", verdict="strip",
              redaction={"aws-access-key": 1}, latency_ms=205,
              findings=[{"scanner": "secrets", "rule_id": "secrets.aws_access_key",
                         "severity": "high", "owasp": "ASI03", "mitre": "T1552"}])
    rt.record(actor="spiffe://beta/agent/helper", action="fetch", target="https://evil/x",
              verdict="block", block_reason="INJECTION_BLOCKED",
              findings=[{"scanner": "injection", "rule_id": "override.ignore_previous",
                         "severity": "high", "owasp": "ASI01", "mitre": "T1204"}])
    # An irreversible verb held at the HITL gate: no block_reason, so the alert
    # card falls back to "held for approval".
    rt.record(actor="spiffe://acme/agent/claude-code", action="mcp_tool_call",
              target="tool:send_email", verdict="ask", session="sess-acme-1")


if __name__ == "__main__":
    rt = Runtime(None, data_dir=DATA)
    if rt.ledger.next_seq <= 1:  # only seed a fresh dir
        seed(rt)
    rt.close()
    app = create_app(None, data_dir=DATA)
    uvicorn.run(app, host="127.0.0.1", port=8899, log_level="warning")
