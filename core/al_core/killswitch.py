"""Kill switch — one sentinel, many triggers, full deny-all (L6/ops).

When something is wrong — a poisoned agent, a leaking tool, a compromised
upstream — the operator needs one action that stops *everything* the plane
mediates, from any of several independent paths, without a deploy:

* **Control API** — ``POST /api/killswitch`` on the control plane (admin
  token; agents have no route to it).
* **CLI** — ``al killswitch engage`` on the host.
* **Sentinel file** — ``touch data/KILLSWITCH`` (works over any channel that
  can reach the filesystem: cron, EDR, a human with a shell).
* **Signal** — ``SIGUSR1`` to the gateway process (POSIX only).

All triggers converge on the same mechanism: the sentinel file's existence IS
the engaged state. That makes engagement crash-safe (survives restarts),
cross-process (the CLI engages a running gateway), and trivially auditable.
Alongside the sentinel, a metadata file records who/why/when for ``status``.

Enforcement is checked at every ingress (gateway middleware, CONNECT proxy,
ActionGate, MemoryGuard callers) via :meth:`engaged` — a single existence
check. Engage/disengage each emit a signed ``killswitch`` receipt (engage is
CRITICAL); an engagement discovered via the sentinel (touched out-of-band)
is receipted on first detection.
"""

from __future__ import annotations

import json
import logging
import signal
from pathlib import Path
from typing import Any, Callable

from .receipt import utcnow_iso

log = logging.getLogger("al.killswitch")

Recorder = Callable[..., Any]

SENTINEL_NAME = "KILLSWITCH"


class KillSwitch:
    def __init__(self, data_dir: Path, *, recorder: Recorder | None = None) -> None:
        self._sentinel = Path(data_dir) / SENTINEL_NAME
        self._meta = Path(data_dir) / "killswitch.json"
        self._record = recorder or (lambda **_: None)
        # Tracks whether the current engagement has been receipted, so a
        # sentinel touched out-of-band is receipted exactly once on detection.
        self._receipted = self._sentinel.exists() and self._meta.exists()

    # -- state -----------------------------------------------------------------

    def engaged(self) -> bool:
        """The enforcement check — called on every mediated request."""
        if not self._sentinel.exists():
            self._receipted = False
            return False
        if not self._receipted:
            # Discovered out-of-band (operator touched the sentinel directly).
            self._receipted = True
            self._record(
                actor="operator", action="killswitch", target="killswitch:sentinel",
                verdict="block", block_reason="KILLSWITCH_ENGAGED",
                findings=[{"scanner": "killswitch", "rule_id": "killswitch.engaged",
                           "severity": "critical"}],
            )
            log.critical("kill switch engaged via sentinel file — deny-all")
        return True

    def status(self) -> dict[str, Any]:
        meta: dict[str, Any] = {}
        if self._meta.exists():
            try:
                meta = json.loads(self._meta.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {}
        engaged = self._sentinel.exists()
        if engaged and not meta:
            meta = {"source": "sentinel", "reason": None, "ts": None, "actor": None}
        return {"engaged": engaged, **({k: meta.get(k) for k in
                                        ("source", "actor", "reason", "ts")} if engaged else {})}

    # -- triggers ---------------------------------------------------------------

    def engage(self, source: str, *, actor: str = "operator",
               reason: str | None = None) -> dict[str, Any]:
        """Engage from any trigger; idempotent. Returns status."""
        self._sentinel.parent.mkdir(parents=True, exist_ok=True)
        self._meta.write_text(json.dumps({
            "source": source, "actor": actor, "reason": reason, "ts": utcnow_iso(),
        }, indent=2), encoding="utf-8")
        already = self._sentinel.exists()
        self._sentinel.touch()
        if not already or not self._receipted:
            self._receipted = True
            self._record(
                actor=actor, action="killswitch", target=f"killswitch:{source}",
                verdict="block", block_reason="KILLSWITCH_ENGAGED",
                findings=[{"scanner": "killswitch", "rule_id": "killswitch.engaged",
                           "severity": "critical"}],
            )
            log.critical("kill switch ENGAGED via %s (%s) — deny-all", source, reason or "no reason")
        return self.status()

    def disengage(self, *, actor: str = "operator") -> dict[str, Any]:
        """Lift the switch (idempotent); receipted so recovery is auditable."""
        was = self._sentinel.exists()
        self._sentinel.unlink(missing_ok=True)
        self._meta.unlink(missing_ok=True)
        self._receipted = False
        if was:
            self._record(actor=actor, action="killswitch",
                         target="killswitch:disengage", verdict="allow")
            log.warning("kill switch disengaged by %s", actor)
        return self.status()

    def install_signal_handler(self) -> bool:
        """SIGUSR1 -> engage (POSIX only; returns False where unsupported)."""
        sig = getattr(signal, "SIGUSR1", None)
        if sig is None:
            return False
        try:
            signal.signal(sig, lambda *_: self.engage("signal"))
        except ValueError:  # not the main thread
            return False
        return True


__all__ = ["KillSwitch", "SENTINEL_NAME"]
