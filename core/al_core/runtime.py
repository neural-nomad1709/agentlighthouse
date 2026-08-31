"""Runtime wiring — boots the plane fail-closed and exposes health.

Boot order matters and is itself an invariant:

1. Load + validate config (a bad config at boot is fatal — refuse to start).
2. Load or (dev-only) create the Ed25519 signing key, enforcing permissions.
3. Open the audit ledger, which re-verifies the existing JSONL chain and
   refuses to run on tamper, then resumes the chain from its tail.
4. Run the L0 bypass self-test (prod/enabled): if the process can reach the
   internet without al-core, record a signed CRITICAL receipt and refuse to
   start — a choke-point that can be walked around is not a choke-point.
5. Record a signed ``config_change`` receipt for the applied boot config, and
   wire subsequent config reloads to emit their own signed records.

Anything raising in this sequence stops the process — that is the point.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from .a2a.mediator import A2aMediator, CardPinner, SessionRegistry
from .audit import Ledger
from .capability.gate import ActionGate
from .capability.hitl import HitlGate
from .capability.policy import ToolPolicy
from .capability.store import CapabilityStore
from .capability.taint import TaintTracker
from .config import ConfigManager, Settings
from .config.watch import ConfigWatcher
from .detect import ContentGate
from .detect.budget import RateBudgetLedger
from .detect.scanners import default_scanners, skill_scanners
from .egress import EgressBypassError, probe_bypass, self_test_enabled
from .egress.selftest import ConnectFn
from .gateway.vkeys import BudgetLedger, VirtualKeyStore
from .identity import IdentityRegistry
from .keys import load_or_create_signing_key
from .killswitch import KillSwitch
from .learn.bundle import load_bundle
from .learn.scanner import LearnedScanner
from .mcp.chain import ChainDetector
from .mcp.descriptors import ToolPinner
from .mcp.mediator import McpMediator
from .memory import MemoryGuard, MemoryStore
from .skills import SkillGuard, SkillPinner

log = logging.getLogger("al.runtime")

# System/mediator actor used for receipts not attributable to a specific agent
# (config changes, kill switch, boot). A plain string per the receipt schema.
MEDIATOR_ACTOR = "spiffe://local/al-core"


class Runtime:
    def __init__(
        self,
        config_path: str | Path | None = None,
        *,
        data_dir: str | Path = "data",
        probe_connect: ConnectFn | None = None,  # DI seam for the bypass self-test
        **overrides: Any,
    ) -> None:
        self._data_dir = Path(data_dir)
        self._config_path = Path(config_path) if config_path is not None else None
        self._watcher: ConfigWatcher | None = None
        self._record_lock = threading.Lock()
        self._gate_cache: tuple[str, ContentGate] | None = None

        # 1. Config (fail-closed at boot). No change callback yet — the ledger
        #    that would record the change does not exist until step 3.
        self._config = ConfigManager(config_path, **overrides)
        settings = self._config.current

        # 2. Signing key (dev auto-gen / prod refuse-if-missing; perms enforced).
        self._signing_key = load_or_create_signing_key(
            settings.keys.signing_key_path,
            auto_generate=settings.keys.auto_generate,
            env=settings.env,
            minimum=settings.keys.min_permissions,
        )
        self._public_key = self._signing_key.public_key()

        # 3. Ledger (verify-on-startup + resume). Refuses to run on tamper.
        #    The mirror backend is a config swap (sqlite | postgres); the JSONL
        #    remains canonical either way.
        self._ledger = Ledger(
            self._signing_key,
            self._public_key,
            jsonl_path=self._data_dir / "ledger.jsonl",
            db_path=self._data_dir / "al.sqlite",
            dsn=(settings.audit.dsn.get_secret_value()
                 if settings.audit.backend == "postgres" and settings.audit.dsn
                 else None),
        )

        # 4. L0 bypass self-test: out-of-band egress must FAIL. Any success is
        #    evidence the topology is broken — receipt it, then refuse to run.
        if self_test_enabled(settings.egress, settings.env):
            reached = probe_bypass(
                settings.egress.probe_targets,
                timeout_s=settings.egress.probe_timeout_s,
                connect=probe_connect,
            )
            if reached:
                self._ledger.record(
                    actor=MEDIATOR_ACTOR,
                    action="killswitch",
                    target=",".join(reached),
                    verdict="block",
                    block_reason="EGRESS_BYPASS_DETECTED",
                    findings=[{
                        "scanner": "egress",
                        "rule_id": "egress.bypass_detected",
                        "severity": "critical",
                        "owasp": "ASI02",
                    }],
                )
                log.critical("egress bypass detected (reached %s) — refusing to start", reached)
                raise EgressBypassError(
                    f"out-of-band egress succeeded to {reached}; "
                    "the deployment is not a choke-point"
                )

        # 5. Identity registry + virtual keys/budgets (gateway state).
        self._registry = IdentityRegistry(self._data_dir / "identities.json")
        vk_path = settings.gateway.virtual_keys_path
        if not vk_path.is_absolute():
            vk_path = self._data_dir / vk_path
        self._vkeys = VirtualKeyStore(vk_path)
        self._budget = BudgetLedger(self._ledger.db)

        # L4 action gate: long-lived session state (taint/chain/HITL) plus the
        # identity-bound tool policy loaded from YAML. Taint and pending
        # approvals persist in SQLite next to the ledger mirror and rehydrate
        # on boot: a restart must neither drop an in-flight approval nor
        # launder a tainted session (deadlines stay anchored to the original
        # submission — persistence never extends one).
        self._capability_store = CapabilityStore(self._data_dir / "capability_state.db")
        self._taint = TaintTracker(store=self._capability_store)
        self._chain = ChainDetector(gap_tolerance=settings.policy.chain_gap_tolerance)
        self._hitl = HitlGate(timeout_s=settings.policy.hitl_timeout_s,
                              store=self._capability_store)
        self._pinner = ToolPinner(self._data_dir / "tool_pins.json")
        self._tool_policy = self._load_tool_policy(settings)

        # A2A (ASI07): peer-card pins + session ownership persist, so a
        # rug-pull or a smuggled session is still caught after a restart.
        self._card_pinner = CardPinner(self._data_dir / "agent_cards.json")
        self._a2a_sessions = SessionRegistry(self._data_dir / "a2a_sessions.json")

        # Instruction-file pins persist: a file that is clean when scanned and
        # hostile when read is exactly the case a CI check cannot catch.
        self._skill_pinner = SkillPinner(self._data_dir / "skill_pins.json")

        # L6 kill switch: sentinel-file mechanism, receipted transitions. The
        # sentinel dir may live on a volume shared with the control plane (see
        # ControlConfig) so an operator on control-net can drill the data plane
        # without any network path from agents. If the switch was engaged
        # before this boot, the plane comes up denying.
        self._killswitch = KillSwitch(
            settings.control.killswitch_dir or self._data_dir, recorder=self.record)
        if self._killswitch.engaged():
            log.critical("kill switch is engaged — the plane boots in deny-all")

        # 6. Record the applied config only if it changed since the last boot,
        #    so repeated starts / health checks do not spam the ledger. Then arm
        #    change-recording for hot reloads.
        if self._ledger.last_config_hash() != self._config.current_hash:
            self._ledger.record(
                actor=MEDIATOR_ACTOR,
                action="config_change",
                target="config:boot",
                verdict="allow",
                policy_hash=self._config.current_hash,
            )
        self._config.set_on_change(self._on_config_change)

    # -- accessors ---------------------------------------------------------
    @property
    def settings(self) -> Settings:
        return self._config.current

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    @property
    def registry(self) -> IdentityRegistry:
        return self._registry

    @property
    def vkeys(self) -> VirtualKeyStore:
        return self._vkeys

    @property
    def budget(self) -> BudgetLedger:
        return self._budget

    @property
    def config_hash(self) -> str:
        return self._config.current_hash

    @property
    def content_gate(self) -> ContentGate:
        """L2×L3 content gate for the *current* config (rebuilt on hot-reload).

        Scanner set + mode + timeouts all derive from config, so the gate is
        cached by config hash and dropped when the config changes.
        """
        key = self._config.current_hash
        if self._gate_cache is None or self._gate_cache[0] != key:
            s = self.settings
            scanners = [*default_scanners(s), *self._learned_scanners(s)]
            gate = ContentGate(
                scanners,
                mode=s.mode,
                max_unwrap_depth=s.scanner.normalize.max_unwrap_depth,
                max_variants=s.scanner.normalize.max_variants,
                scan_timeout_s=s.scanner.scan_timeout_s,
            )
            self._gate_cache = (key, gate)
        return self._gate_cache[1]

    def _learned_scanners(self, settings: Settings) -> list[Any]:
        """Approved learned rules, loaded from a SIGNED bundle.

        An unsigned or tampered bundle raises — boot is fail-closed, and a rule
        set we cannot attribute is exactly what an attacker would supply."""
        path = settings.learn.rule_bundle
        if path is None:
            return []
        doc = load_bundle(path, self._public_key)  # raises UnsignedBundleError
        log.info("loaded %d learned rule(s) from signed bundle %s",
                 len(doc["rules"]), doc["bundle_id"])
        return [LearnedScanner(doc["rules"])]

    @staticmethod
    def _load_tool_policy(settings: Settings) -> ToolPolicy:
        """Load the identity-bound tool policy; a missing file = deny-all."""
        path = settings.policy.tool_policy_path
        if path.exists():
            return ToolPolicy.from_yaml(path)
        log.warning("tool policy %s not found — defaulting to deny-all", path)
        return ToolPolicy.from_dict({"agents": {"default": {"allow": []}}})

    @property
    def action_gate(self) -> ActionGate:
        """L4 gate for one tool call: identity -> policy -> chain -> HITL.

        Rebuilt per access (cheap ref-wiring) so it always uses the current
        content gate, while the persistent taint/chain/HITL state is shared."""
        return ActionGate(
            self._tool_policy,
            chain=self._chain, hitl=self._hitl, taint=self._taint,
            content_gate=self.content_gate, recorder=self.record,
            killswitch=self._killswitch.engaged,
        )

    @property
    def mcp_mediator(self) -> McpMediator:
        """MCP mediation: descriptor pinning + poisoning + call authorization."""
        return McpMediator(
            self.action_gate, self.content_gate,
            pinner=self._pinner, recorder=self.record,
        )

    @property
    def killswitch(self) -> KillSwitch:
        return self._killswitch

    @property
    def skill_guard(self) -> SkillGuard:
        """Screen + pin agent instruction files (SKILL.md / CLAUDE.md / rules).

        Uses a **skill-tuned** content gate (``skill_scanners``): the same
        engines, scoped for human-authored prose so a documented localhost or a
        git SHA is not a false block — while injection, secrets, PII, seed
        phrases and the cloud-metadata SSRF endpoint are kept in full. Shares the
        L4 TaintTracker, so a poisoned or drifted instruction file taints the
        session and a later protected tool call in it needs approval."""
        s = self.settings
        gate = ContentGate(
            skill_scanners(s), mode=s.mode,
            max_unwrap_depth=s.scanner.normalize.max_unwrap_depth,
            max_variants=s.scanner.normalize.max_variants,
            scan_timeout_s=s.scanner.scan_timeout_s,
        )
        return SkillGuard(
            gate,
            pinner=self._skill_pinner,
            taint=self._taint,
            recorder=self.record,
            max_bytes=s.skills.max_bytes,
        )

    @property
    def a2a_mediator(self) -> A2aMediator:
        """Inter-agent message mediation (ASI07): card pinning + poisoning,
        session-smuggling checks, payload scanning, untrusted-agent taint.

        Shares the L4 TaintTracker, so a hostile inter-agent message tightens
        the *same* session's tool policy — the point of the interface."""
        return A2aMediator(
            self.content_gate,
            pinner=self._card_pinner,
            sessions=self._a2a_sessions,
            taint=self._taint,
            recorder=self.record,
        )

    @property
    def memory_guard(self) -> MemoryGuard:
        """L5 guarded memory (screen/baseline/quarantine/snapshot) over data_dir.

        Built per access so it always screens with the current content gate;
        all its state (store, baselines, quarantine, snapshots) is file-backed,
        and session taint is shared with the L4 gate — hostile memory content
        tightens the same session's tool policy."""
        s = self.settings
        store_path = s.memory.store_path
        if not store_path.is_absolute():
            store_path = self._data_dir / store_path
        return MemoryGuard(
            MemoryStore(store_path),
            content_gate=self.content_gate,
            baseline_path=self._data_dir / "memory_baselines.json",
            quarantine_path=self._data_dir / "memory_quarantine.json",
            snapshot_dir=self._data_dir / "memory_snapshots",
            protected_keys=s.memory.protected_keys,
            trusted_writers=set(s.memory.trusted_writers) | {MEDIATOR_ACTOR},
            max_value_bytes=s.memory.max_value_bytes,
            recorder=self.record,
            taint=self._taint,
        )

    @property
    def rate_budget(self) -> RateBudgetLedger:
        """Per-domain rate limit + data budget over the ledger's SQLite mirror.

        Cheap to construct (wraps the db + two thresholds), so it is built from
        current config on each access — no stale window state to preserve, the
        counters live in the table."""
        s = self.settings
        return RateBudgetLedger(
            self._ledger.db,
            per_domain_rps=s.scanner.rate_limit.per_domain_rps,
            per_domain_bytes=s.scanner.data_budget.per_domain_bytes,
        )

    @property
    def signing_key(self):  # noqa: ANN201
        """The mediator's Ed25519 private key.

        Exposed so a layer above (e.g. governance posture attestation) can sign
        a *standalone* document with the same key that signs receipts — one
        mediator identity, so an auditor verifies both with one public key."""
        return self._signing_key

    @property
    def public_key(self):  # noqa: ANN201
        return self._public_key

    def record(self, **fields: Any) -> dict[str, Any]:
        """Thread-safe receipt write — the gateway's recorder.

        The signer's hash chain is single-writer state; gateway handlers run
        on multiple threads/tasks, so appends are serialized here.
        """
        with self._record_lock:
            return self._ledger.record(**fields)

    # -- hooks -------------------------------------------------------------
    def _on_config_change(self, old, new, old_hash: str, new_hash: str) -> None:
        self._ledger.record(
            actor=MEDIATOR_ACTOR,
            action="config_change",
            target="config:reload",
            verdict="allow",
            policy_hash=new_hash,
        )
        log.info("config changed %s -> %s (signed record emitted)", old_hash[:19], new_hash[:19])

    def reload_config(self) -> Settings:
        return self._config.reload()

    def start_config_watch(self) -> None:
        """Begin watching the config file for changes (no-op without a file)."""
        if self._config_path is None or self._watcher is not None:
            return
        self._watcher = ConfigWatcher(self._config_path, self.reload_config).start()

    def stop_config_watch(self) -> None:
        if self._watcher is not None:
            self._watcher.stop()
            self._watcher = None

    # -- health ------------------------------------------------------------
    def healthz(self) -> dict[str, Any]:
        """Report config validity + chain-verify status (the /healthz payload)."""
        chain_ok, chain_len, chain_err = True, 0, None
        try:
            chain_len = self._ledger.verify(self._public_key)
        except Exception as exc:  # noqa: BLE001 — any verify failure is unhealthy
            chain_ok, chain_err = False, str(exc)
        healthy = chain_ok
        return {
            "status": "healthy" if healthy else "unhealthy",
            "mode": self.settings.mode,
            "env": self.settings.env,
            "config_hash": self._config.current_hash,
            "chain": {"verified": chain_ok, "length": chain_len, "error": chain_err},
            "next_seq": self._ledger.next_seq,
        }

    def close(self) -> None:
        self.stop_config_watch()
        self._capability_store.close()
        self._ledger.close()
