"""Tool-call chain detection (L4, ASI02) — recon -> stage -> exfil.

A single tool call can look benign; the *sequence* is the attack. An agent
that lists files, reads a secret, base64-encodes it, then POSTs it out has run
a recon -> stage -> exfil chain — even if dozens of legitimate calls are
interleaved. This detector classifies each tool call into a coarse category
and flags a configured pattern whenever it appears as an **ordered subsequence**
of the session's history (benign calls in between are tolerated, up to a gap
bound).

Categories are intent buckets, not tools, so the patterns stay small and the
tool->category map is the only thing that grows.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..gateway.decision import BlockReason, Decision, finding

# Coarse intent categories.
RECON = "recon"
STAGE = "stage"
EXFIL = "exfil"

# Default tool-name (prefix) -> category. Word-boundary matched.
_DEFAULT_CATEGORIES: dict[str, str] = {
    "list_dir": RECON, "read_file": RECON, "search": RECON, "glob": RECON,
    "grep": RECON, "env": RECON, "get_secret": RECON, "http_get": RECON,
    "fetch": RECON, "list": RECON, "describe": RECON,
    "write_file": STAGE, "encode": STAGE, "compress": STAGE, "archive": STAGE,
    "base64": STAGE, "zip": STAGE, "create": STAGE, "stage": STAGE,
    "http_post": EXFIL, "send_email": EXFIL, "upload": EXFIL, "transfer": EXFIL,
    "publish": EXFIL, "post": EXFIL, "send": EXFIL, "webhook": EXFIL, "dns": EXFIL,
}

# The default attack pattern: get info, prepare it, send it out. STAGE is
# optional in practice, so recon->exfil alone also flags (a superset pattern).
_DEFAULT_PATTERNS: list[tuple[str, ...]] = [
    (RECON, STAGE, EXFIL),
    (RECON, EXFIL),
]


def classify(tool: str, categories: dict[str, str]) -> str | None:
    t = tool.lower()
    if t in categories:
        return categories[t]
    for key, cat in categories.items():
        if t.startswith(key + "_") or t == key:
            return cat
    return None


def _is_subsequence(pattern: tuple[str, ...], seq: list[str], gap: int) -> bool:
    """True if ``pattern`` appears in order within ``seq``, with at most ``gap``
    non-matching elements between consecutive matched stages."""
    pi = 0
    since = 0
    for cat in seq:
        if pi >= len(pattern):
            break
        if cat == pattern[pi]:
            pi += 1
            since = 0
        elif pi > 0:
            since += 1
            if since > gap:
                # too much benign distance broke the chain; restart from the
                # first stage if this element could begin a new attempt
                pi = 1 if cat == pattern[0] else 0
                since = 0
    return pi >= len(pattern)


@dataclass
class _Session:
    categories: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    flagged: bool = False


class ChainDetector:
    """Per-session ordered-subsequence detector for attack chains."""

    def __init__(
        self,
        *,
        categories: dict[str, str] | None = None,
        patterns: list[tuple[str, ...]] | None = None,
        gap_tolerance: int = 6,
    ) -> None:
        self._categories = categories or dict(_DEFAULT_CATEGORIES)
        self._patterns = patterns or list(_DEFAULT_PATTERNS)
        self._gap = gap_tolerance
        self._sessions: dict[str, _Session] = {}

    def record(self, session_id: str, tool: str) -> Decision | None:
        """Record a tool call; return a block Decision if it completes a chain.

        Returns ``None`` while no configured pattern is a subsequence yet. Once
        a session is flagged it stays flagged (re-flagging is suppressed so the
        receipt fires once per chain)."""
        s = self._sessions.setdefault(session_id, _Session())
        s.tools.append(tool)
        cat = classify(tool, self._categories)
        if cat is not None:
            s.categories.append(cat)
        if s.flagged:
            return None
        for pattern in self._patterns:
            if _is_subsequence(pattern, s.categories, self._gap):
                s.flagged = True
                return Decision.block(
                    BlockReason.TOOL_CHAIN_DETECTED,
                    [finding("mcp_chain", f"mcp.chain.{'_'.join(pattern)}", "high",
                             owasp="ASI02", mitre="T1041")],
                )
        return None

    def is_flagged(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        return bool(s and s.flagged)

    def history(self, session_id: str) -> list[str]:
        s = self._sessions.get(session_id)
        return list(s.categories) if s else []

    def clear(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)


__all__ = ["ChainDetector", "classify", "EXFIL", "RECON", "STAGE"]
