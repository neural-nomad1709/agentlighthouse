"""Content-gate helpers shared by the fetch + reverse-proxy handlers (L2/L3).

Keeps the FastAPI handlers in ``web.py`` readable: these turn a
:class:`~al_core.detect.GateResult` into the gateway's ``(Decision, receipt
fields)`` shape and provide the fail-closed SSE scanner.
"""

from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator

from ..detect import GateResult, ScanContext
from .decision import BlockReason, Decision

log = logging.getLogger("al.gateway.content")

# How much decoded response text to scan (bytes). Content beyond this is not a
# realistic injection carrier and scanning unbounded text is a DoS vector.
SCAN_TEXT_CAP = 1 * 1024 * 1024


def decode_body(body: bytes, content_type: str) -> str | None:
    """Best-effort text for scanning. Returns None only for content that is
    genuinely binary (images, archives) — nothing to scan there, so the gate
    allows it (the egress SSRF/size controls already governed *whether* to
    fetch it).

    A NUL byte in the sample is the binary tell. We do NOT trust the declared
    content-type to *skip* scanning — an attacker serving an injection payload
    as ``application/octet-stream`` must not slip past — so any NUL-free body
    is scanned regardless of its type. A declared-text type still forces a
    scan even if it somehow contains a NUL."""
    ct = (content_type or "").lower()
    declared_text = (not ct) or any(
        t in ct for t in ("text", "json", "xml", "html", "javascript", "csv")
    )
    sample = body[:SCAN_TEXT_CAP]
    if b"\x00" in sample and not declared_text:
        return None  # binary payload — nothing to scan
    return sample.decode("utf-8", errors="replace")


def gate_to_decision(result: GateResult, scanner_hint: str) -> Decision:
    """Map a blocking/ask GateResult to a gateway Decision (findings attached).

    ``allow``/``warn``/``strip`` are not denials — the caller uses
    ``result.text`` for the (possibly redacted) body and records the findings.
    """
    reason = result.block_reason or BlockReason.CONTENT_BLOCKED
    return Decision.block(reason, result.findings)


def receipt_extras(result: GateResult) -> dict[str, Any]:
    """Receipt kwargs carrying findings + redaction counts (never plaintext)."""
    extras: dict[str, Any] = {}
    if result.findings:
        extras["findings"] = result.findings
    if result.redaction:
        extras["redaction"] = result.redaction
    return extras


async def scan_sse_stream(
    upstream_lines: AsyncIterator[bytes],
    gate,
    ctx: ScanContext,
    *,
    on_complete,
) -> AsyncIterator[bytes]:
    """Relay an SSE stream while scanning it fail-closed.

    Each event carrying assistant text is scanned **before it is relayed**:
    the cumulative assistant message (deltas, not JSON envelope) is re-scanned
    and, on a block verdict, the offending event is **withheld** — it never
    reaches the agent — a terminal ``al_blocked`` event is emitted, and the
    stream is severed. Clean events already released cannot be recalled, but a
    malicious payload is caught on the first event that completes it, so it is
    stopped before delivery.

    Scanning is bounded: once the assistant text exceeds ``SCAN_TEXT_CAP`` it
    is no longer re-scanned (content that far into a reply is not a realistic
    injection carrier, and unbounded re-scan is a DoS vector). ``on_complete
    (GateResult|None, severed, assistant_text)`` fires once at the end.
    """
    assistant: list[str] = []
    total = 0
    severed = False
    last_result: GateResult | None = None

    async for raw in upstream_lines:
        text = _sse_delta_text(raw)
        if text and total <= SCAN_TEXT_CAP:
            assistant.append(text)
            total += len(text)
            # Scan the cumulative message and withhold *this* event on a block.
            last_result = gate.scan_text("".join(assistant), ctx)
            if last_result.blocked:
                severed = True
                yield _blocked_event(last_result.block_reason)
                break
        yield raw

    if not severed and last_result is None and assistant:
        last_result = gate.scan_text("".join(assistant), ctx)

    on_complete(last_result, severed, "".join(assistant))


def _sse_delta_text(raw: bytes) -> str:
    """Pull human-visible text out of one SSE line (OpenAI + Anthropic shapes)."""
    line = raw.decode("utf-8", errors="ignore").strip()
    if not line.startswith("data:"):
        return ""
    data = line[5:].strip()
    if not data or data == "[DONE]":
        return ""
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        return ""
    # OpenAI: choices[].delta.content ; Anthropic: delta.text
    out = []
    for choice in payload.get("choices", []) or []:
        delta = choice.get("delta") or {}
        if isinstance(delta.get("content"), str):
            out.append(delta["content"])
    delta = payload.get("delta") or {}
    if isinstance(delta.get("text"), str):
        out.append(delta["text"])
    return "".join(out)


def _blocked_event(reason: str | None) -> bytes:
    body = json.dumps({"error": "blocked_by_content_gate",
                       "block_reason": reason or BlockReason.CONTENT_BLOCKED})
    return f"event: al_blocked\ndata: {body}\n\n".encode("utf-8")


__all__ = [
    "SCAN_TEXT_CAP",
    "decode_body",
    "gate_to_decision",
    "receipt_extras",
    "scan_sse_stream",
]
