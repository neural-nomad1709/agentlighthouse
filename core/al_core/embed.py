"""The embedding facade (AL-0.4) — the declared, stable surface for embedders.

A host application that embeds AgentLighthouse as a library (rather than
running it as a proxy) imports from THIS module and nothing else:

    from al_core.embed import Runtime, ScanContext

    rt = Runtime(config_path, data_dir=...)   # boots key, ledger, gates
    outcome = rt.action_gate.authorize(actor, tool, args, session_id=...)
    result  = rt.content_gate.scan_text(text, ScanContext(actor=actor))
    receipt = rt.record(actor=..., action=..., target=..., verdict=...)
    rt.close()

Everything re-exported here is contract: renaming or reshaping it is a
breaking change for embedders and gets a deliberate version bump. Internals
not listed in ``__all__`` may change freely. The contract test
(tests/test_embed_facade.py) imports only this surface.

`Runtime` is itself the factory — construct it with a config path and a data
directory; there is deliberately no separate ``create_runtime()``.
"""

from __future__ import annotations

from .capability.gate import ActionGate, ActionOutcome
from .capability.hitl import ApprovalRequest, HitlGate
from .capability.store import CapabilityStore
from .capability.taint import TaintSource, TaintTracker
from .detect import ContentGate, GateResult, ScanContext, ScanFinding
from .gateway.decision import BlockReason, Decision
from .receipt import ACTIONS, VERDICTS
from .runtime import Runtime

__all__ = [
    "ACTIONS",
    "VERDICTS",
    "ActionGate",
    "ActionOutcome",
    "ApprovalRequest",
    "BlockReason",
    "CapabilityStore",
    "ContentGate",
    "Decision",
    "GateResult",
    "HitlGate",
    "Runtime",
    "ScanContext",
    "ScanFinding",
    "TaintSource",
    "TaintTracker",
]
