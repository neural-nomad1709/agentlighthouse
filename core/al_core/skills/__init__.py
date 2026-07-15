"""L4/L5 Skill Guard — agent instruction files are untrusted input too.

``SKILL.md``, ``CLAUDE.md``, ``.cursorrules``, ``AGENTS.md`` and their kin are
text the model reads **as authority** and acts on. A poisoned one is a
persistent, high-privilege prompt injection with none of the noise of an
indirect web injection — and until now it was the one ingestion path
AgentLighthouse did not mediate, because the agent framework opens these files
straight off local disk.

The guard closes that. It is deliberately a *composition of two things already
proven* rather than a new invention:

* **screening** — the file's text runs through the same L2/L3 content gate as
  every other untrusted input, so an injection hidden behind zero-width
  characters or base64 is folded and caught (`SKILL_POISONED`);
* **pinning** — the file's SHA-256 is pinned on first sight, exactly like an MCP
  tool descriptor or an A2A Agent Card. A file that changes behind a trusted
  name is a rug-pull, blocked until an operator re-approves it (`SKILL_DRIFT`).
  This is the half a CI check cannot give you: it catches the file that was
  clean when you scanned it and hostile by the time the agent read it.

A poisoned or drifted instruction file also **taints the session**, so a later
protected tool call in it faces the tightened HITL gate.

Every decision is receipted as `skill_load`.
"""

from .guard import SkillGuard, SkillOutcome, SkillPinner

__all__ = ["SkillGuard", "SkillOutcome", "SkillPinner"]
