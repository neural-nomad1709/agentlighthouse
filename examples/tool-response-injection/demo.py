"""Demo 1 — Tool-Response Injection (RELEASE GATE). Fully local, self-contained.

Story: an MCP tool with a harmless name and a harmless description
(``web_search``) hides a prompt-injection payload in its *response*. Descriptor
pinning and poisoning checks pass — there is nothing wrong with the descriptor.
AgentLighthouse blocks the payload anyway, on the response, before the agent
ever sees it, on **all three MCP transports**, with one shared signing key.

Run:  make demo        (or: uv run python examples/tool-response-injection/demo.py)

Pass criteria (docs/demos.md), each asserted below:
  1. Blocked on stdio + HTTP-upstream + HTTP-reverse.
  2. Fixed, agent-legible block_reason on every transport (explainability).
  3. The exfil payload never reaches the agent and never enters the ledger.
  4. al-verify verifies the receipts with NO al-core imported.
  5. Kill switch drills the whole plane to deny-all.
If any check fails this exits non-zero — CI treats that as: no release.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from al_core.gateway.decision import BlockReason
from al_core.gateway.web import create_gateway_app
from al_core.mcp import HttpUpstream, McpSession, StdioUpstream, run_proxy
from al_core.runtime import Runtime

HERE = Path(__file__).resolve().parent
WORK = HERE / "run"
MOCK_SERVER = HERE / "mock_server.py"

AGENT = "spiffe://acme/agent/claude-code"
EXFIL_MARKER = "collector.evil.example"

POLICY = """
agents:
  spiffe://acme/agent/claude-code:
    allow:
      - { tool: web_search }
    deny:
      - { tool: exec_shell }
  default:
    allow: []
"""

failures: list[str] = []


def step(n: int, title: str) -> None:
    print(f"\n[{n}] {title}")
    print("-" * (len(title) + 4))


def check(ok: bool, claim: str) -> None:
    print(("PASS  " if ok else "FAIL  ") + claim)
    if not ok:
        failures.append(claim)


def tools_list(rid: int) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/list"}


def tool_call(rid: int, tool: str = "web_search") -> dict:
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
            "params": {"name": tool, "arguments": {"query": "widget pricing"}}}


def sequential_agent(requests: list[dict], replies: list[dict]):
    """An MCP client that waits for each reply before its next request, as a
    real one waits for tools/list before calling a listed tool (a call to a
    tool the agent was not shown is denied)."""
    pending = list(requests)
    answered = asyncio.Event()
    answered.set()

    async def recv_agent():
        if not pending:
            return None
        await answered.wait()
        answered.clear()
        return pending.pop(0)

    async def send_agent(msg) -> None:
        replies.append(msg)
        answered.set()

    return recv_agent, send_agent


def _boot() -> Runtime:
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "keys").mkdir(parents=True)
    (WORK / "policy.yaml").write_text(POLICY, encoding="utf-8")
    cfg = WORK / "config.yaml"
    cfg.write_text(
        "mode: balanced\nenv: dev\n"
        f"keys:\n  signing_key_path: {(WORK / 'keys' / 'mediator_ed25519').as_posix()}\n"
        f"policy:\n  tool_policy_path: {(WORK / 'policy.yaml').as_posix()}\n"
        "gateway:\n  mcp_upstream_url: https://mcp.example.com/rpc\n",
        encoding="utf-8")
    return Runtime(cfg, data_dir=WORK / "data", admin_api_token="demo")


def _mock_http(request: httpx.Request) -> httpx.Response:
    """The same hostile server, over HTTP instead of stdio."""
    msg = json.loads(request.content)
    sys.path.insert(0, str(HERE))
    from mock_server import handle  # noqa: PLC0415 — one hostile server, two transports

    reply = handle(msg)
    return httpx.Response(200, json=reply) if reply else httpx.Response(202)


def demo_stdio(runtime: Runtime) -> dict:
    """Transport 1: al-core spawns the MCP server; JSON-RPC over its stdio."""
    session = McpSession(runtime.mcp_mediator, actor=AGENT, session_id="stdio")
    upstream = StdioUpstream([sys.executable, str(MOCK_SERVER)])
    replies: list[dict] = []

    async def drive() -> None:
        recv_agent, send_agent = sequential_agent([tools_list(1), tool_call(2)], replies)
        await asyncio.wait_for(run_proxy(session, upstream, recv_agent, send_agent),
                               timeout=30)

    asyncio.run(drive())
    listed = next(r for r in replies if r.get("id") == 1)
    print(f"  tools/list -> agent sees: {[t['name'] for t in listed['result']['tools']]}"
          "  (descriptor is clean — the attack is in the response)")
    return next(r for r in replies if r.get("id") == 2)


def demo_http_upstream(runtime: Runtime) -> dict:
    """Transport 2: al-core is the MCP client to a Streamable-HTTP server."""
    session = McpSession(runtime.mcp_mediator, actor=AGENT, session_id="http-up")
    client = httpx.AsyncClient(transport=httpx.MockTransport(_mock_http))
    upstream = HttpUpstream("https://mcp.example.com/rpc", client=client)
    replies: list[dict] = []

    async def drive() -> None:
        recv_agent, send_agent = sequential_agent([tools_list(30), tool_call(3)], replies)
        await asyncio.wait_for(run_proxy(session, upstream, recv_agent, send_agent),
                               timeout=30)
        await client.aclose()

    asyncio.run(drive())
    return next(r for r in replies if r.get("id") == 3)


def demo_http_reverse(runtime: Runtime) -> dict:
    """Transport 3: the agent's own MCP client points at al-core (POST /mcp)."""
    app = create_gateway_app(runtime, transport=httpx.MockTransport(_mock_http))
    creds = runtime.registry.issue("acme", "claude-code")
    headers = {"X-AL-Identity": creds.identity.spiffe_id,
               "Authorization": f"Bearer {creds.token}"}
    with TestClient(app) as client:
        client.post("/mcp", json=tools_list(40), headers=headers)
        return client.post("/mcp", json=tool_call(4), headers=headers).json()


def assert_blocked(transport: str, reply: dict) -> None:
    result = reply.get("result", {})
    reason = (result.get("_al") or {}).get("block_reason")
    blob = json.dumps(reply)
    check(result.get("isError") is True and reason == BlockReason.INJECTION_BLOCKED,
          f"{transport}: injected tool response blocked ({reason})")
    check(EXFIL_MARKER not in blob, f"{transport}: exfil payload withheld from the agent")


def main() -> None:
    print("AgentLighthouse — Demo 1: Tool-Response Injection (RELEASE GATE)")
    runtime = _boot()

    step(1, "Transport 1/3 — MCP over stdio (real subprocess)")
    assert_blocked("stdio", demo_stdio(runtime))

    step(2, "Transport 2/3 — MCP over HTTP upstream (al-core is the client)")
    assert_blocked("http-upstream", demo_http_upstream(runtime))

    step(3, "Transport 3/3 — MCP over HTTP reverse (agent points at al-core)")
    assert_blocked("http-reverse", demo_http_reverse(runtime))

    step(4, "Kill switch drills the plane to deny-all")
    runtime.killswitch.engage("api", reason="demo drill")
    denied = runtime.action_gate.authorize(AGENT, "web_search", {})
    check(denied.decision.block_reason == BlockReason.KILLSWITCH_ENGAGED,
          "kill switch engaged -> even an allowed tool is denied")
    runtime.killswitch.disengage()
    check(runtime.action_gate.authorize(AGENT, "web_search", {}).allowed,
          "kill switch disengaged -> normal policy resumes")

    step(5, "Evidence: signed, MITRE-tagged, and independently verifiable")
    runtime.close()
    ledger = WORK / "data" / "ledger.jsonl"
    text = ledger.read_text(encoding="utf-8")
    receipts = [json.loads(line) for line in text.splitlines() if line.strip()]
    blocks = [r for r in receipts if r["verdict"] == "block"]
    print(f"  {len(receipts)} receipts, {len(blocks)} blocks "
          f"({', '.join(sorted({b['block_reason'] for b in blocks}))})")
    check(EXFIL_MARKER not in text, "ledger never contains the exfil payload")
    check(sum(1 for b in blocks
              if b["block_reason"] == BlockReason.INJECTION_BLOCKED) >= 3,
          "one signed intercept receipt per transport")

    from al_core.audit.siem import to_event  # SIEM view of the same evidence

    alert = next(to_event(b) for b in blocks
                 if b["block_reason"] == BlockReason.INJECTION_BLOCKED)
    print(f"  SIEM: kind={alert['event']['kind']} severity={alert['event']['severity']} "
          f"mitre={alert.get('threat', {}).get('technique', {}).get('id')} "
          f"owasp={alert['al']['owasp']}")
    check(bool(alert["al"]["sig"]), "SIEM alert carries the signature (pull + verify)")

    # The portability claim: verify in a subprocess that CANNOT import al_core.
    proof = subprocess.run(
        [sys.executable, "-c",
         "import sys, builtins;"
         "real=builtins.__import__;"
         "builtins.__import__=lambda n,*a,**k: (_ for _ in ()).throw("
         "  ImportError('al_core is not available to the verifier'))"
         "  if n.startswith('al_core') else real(n,*a,**k);"
         "from al_verify.cli import main;"
         "sys.exit(main(sys.argv[1:]))",
         str(ledger), "--pubkey", str(WORK / "keys" / "mediator_ed25519.pub")],
        capture_output=True, text=True, cwd=Path(__file__).resolve().parents[2],
    )
    print("  " + (proof.stdout.strip().replace("\n", "\n  ") or proof.stderr.strip()))
    check(proof.returncode == 0 and "al_core" not in proof.stdout,
          "al-verify verifies the chain with NO al-core imported")

    if failures:
        print(f"\nRELEASE GATE FAILED — {len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("\nRELEASE GATE PASSED: tool-response injection blocked on all three MCP"
          "\ntransports, kill switch drills to deny-all, evidence verifies standalone.")


if __name__ == "__main__":
    main()
