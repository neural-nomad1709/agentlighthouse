"""Per-actor tool-call rate budgets — a sliding 60-second window.

The tripwire behind ``AgentPolicy.budgets.max_tool_calls_per_min``. Enforced at
the ActionGate: an actor may make at most N authorized calls in any rolling
minute; the N+1th within the window is denied (``BUDGET_EXCEEDED``) and
receipted like any other decision. The window truly slides — the earliest call
ages out exactly 60s after it happened, not on a fixed bucket boundary — so a
burst cannot ride a bucket reset.

State is per-actor and in-memory: a rate window is soft, self-healing state,
not evidence (the receipts are the record), so it does not need the persistence
the HITL/taint store carries.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Callable

WINDOW_S = 60.0


class BudgetTracker:
    """Counts authorized calls per actor over a sliding window."""

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        import time

        self._clock = clock or time.monotonic
        self._calls: dict[str, deque[float]] = defaultdict(deque)
        # The gate serves requests from a thread pool; the check-and-append is
        # a read-modify-write, so without a lock two racing calls could both
        # pass the limit check and both append — the exact overrun a rate cap
        # exists to prevent.
        self._lock = threading.Lock()

    def check_and_consume(self, actor: str, limit: int) -> bool:
        """Record a call for ``actor`` if it fits within ``limit`` per minute.

        Returns True and consumes a slot when there is room; returns False and
        consumes nothing when the actor is already at the limit.
        """
        with self._lock:
            now = self._clock()
            window = self._calls[actor]
            cutoff = now - WINDOW_S
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= limit:
                return False
            window.append(now)
            return True


__all__ = ["BudgetTracker", "WINDOW_S"]
