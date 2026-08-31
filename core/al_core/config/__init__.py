"""Configuration as an enforcement boundary (invariant #6).

Config is not a convenience layer; it is a security boundary:

* **Unknown keys fail validation** — every model is ``extra="forbid"``, including
  nested scanner sub-configs, so a typo or a smuggled key is rejected, not ignored.
* **Secrets are ``SecretStr``** — unprintable in logs and error messages, and
  excluded from the config hash / signed record.
* **Permissive defaults are rejected outside ``mode: audit``** — you cannot turn
  a protection off while claiming to run balanced/strict.
* **Last-good config is preserved** — an invalid hot-reload keeps the running
  config and alerts; the mediator never runs a broken config. At boot there is
  no last-good, so an invalid config there is fatal (refuse to start).
* **Every applied config change emits a signed decision record** (action
  ``config_change``) via an injected callback, so changes are auditable.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Callable, Literal

import json

import yaml
from pydantic import BaseModel, ConfigDict, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from al_verify.verify import sha256_hex

log = logging.getLogger("al.config")

_STRICT = ConfigDict(extra="forbid")


class KeysConfig(BaseModel):
    model_config = _STRICT
    signing_key_path: Path = Path("keys/mediator_ed25519")
    auto_generate: bool = True  # forced False when env != "dev" (see Settings validator)
    min_permissions: int = 0o600  # looser -> refuse to start


class DlpConfig(BaseModel):
    model_config = _STRICT
    enabled: bool = True


class InjectionConfig(BaseModel):
    model_config = _STRICT
    enabled: bool = True


class PiiConfig(BaseModel):
    model_config = _STRICT
    enabled: bool = True
    action: Literal["redact", "block", "warn"] = "redact"


class Bip39Config(BaseModel):
    model_config = _STRICT
    enabled: bool = True


class NormalizeConfig(BaseModel):
    model_config = _STRICT
    max_unwrap_depth: int = 2
    max_variants: int = 32


class SsrfConfig(BaseModel):
    model_config = _STRICT
    block_private: bool = True
    dns_rebind_protection: bool = True


class EntropyConfig(BaseModel):
    model_config = _STRICT
    path_threshold: float = 4.0
    subdomain_threshold: float = 3.5


class RateLimitConfig(BaseModel):
    model_config = _STRICT
    per_domain_rps: int = 10


class DataBudgetConfig(BaseModel):
    model_config = _STRICT
    per_domain_bytes: int = 10_485_760


class DetectSecretsConfig(BaseModel):
    """Optional detect-secrets adapter (install with ``al-core[scanners]``).
    Opt-in: the library is an optional dependency, and enabling it without
    the package installed refuses at boot rather than silently skipping."""

    model_config = _STRICT
    enabled: bool = False


class ScannerConfig(BaseModel):
    model_config = _STRICT
    dlp: DlpConfig = DlpConfig()
    detect_secrets: DetectSecretsConfig = DetectSecretsConfig()
    injection: InjectionConfig = InjectionConfig()
    pii: PiiConfig = PiiConfig()
    bip39: Bip39Config = Bip39Config()
    normalize: NormalizeConfig = NormalizeConfig()
    ssrf: SsrfConfig = SsrfConfig()
    entropy: EntropyConfig = EntropyConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()
    data_budget: DataBudgetConfig = DataBudgetConfig()
    url_max_len: int = 8192
    scan_timeout_s: float = 5.0


class UpstreamConfig(BaseModel):
    """Reverse-proxy upstreams. Provider API keys come from env/secrets only
    (``AL_GATEWAY__UPSTREAM__OPENAI_API_KEY`` etc.), never from the YAML file."""

    model_config = _STRICT
    openai_base_url: str = "https://api.openai.com"
    anthropic_base_url: str = "https://api.anthropic.com"
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None


class GatewayConfig(BaseModel):
    model_config = _STRICT
    allow_hosts: list[str] = []  # default-deny; "*.example.com" matches subdomains
    allow_ports: list[int] = [80, 443]
    require_identity: bool = True  # no identity -> deny (forward/fetch ingress)
    forward_listen: str = "127.0.0.1:8080"  # CONNECT proxy bind
    fetch_max_bytes: int = 5_242_880
    max_redirects: int = 3
    request_timeout_s: float = 30.0
    pin_ttl_s: float = 300.0
    virtual_keys_path: Path = Path("virtual_keys.json")  # relative -> under data_dir
    upstream: UpstreamConfig = UpstreamConfig()
    # HTTP-reverse MCP: agents POST /mcp here; al-core mediates and forwards
    # to this operator-configured Streamable-HTTP MCP server (None = 502).
    mcp_upstream_url: str | None = None


class EgressConfig(BaseModel):
    """L0 boot bypass self-test. ``auto`` = enabled iff env == "prod" (a dev
    laptop has legitimate direct internet; a production agent netns must not)."""

    model_config = _STRICT
    bypass_self_test: Literal["auto", "enabled", "disabled"] = "auto"
    probe_targets: list[str] = ["1.1.1.1:443", "8.8.8.8:53"]
    probe_timeout_s: float = 3.0


class PolicyConfig(BaseModel):
    """L4 action gate: identity-bound tool policy + HITL + chain detection."""

    model_config = _STRICT
    tool_policy_path: Path = Path("policies/default-deny.yaml")
    hitl_timeout_s: float = 300.0
    chain_gap_tolerance: int = 6


class SkillsConfig(BaseModel):
    """Agent instruction files (SKILL.md / CLAUDE.md / .cursorrules / AGENTS.md).

    They are text the model reads as authority, so they are screened and pinned
    like any other untrusted, trusted-by-name input. Disabling the guard is a
    permissive setting: audit mode only."""

    model_config = _STRICT
    enabled: bool = True
    paths: list[str] = ["CLAUDE.md", "SKILL.md", "AGENTS.md", ".cursorrules"]
    max_bytes: int = 262_144


class LearnConfig(BaseModel):
    """Learning loop (Phase 7). ``rule_bundle`` points at a SIGNED bundle; an
    unsigned or tampered one is refused at boot (never loaded with a warning)."""

    model_config = _STRICT
    rule_bundle: Path | None = None


class AuditConfig(BaseModel):
    """Evidence mirror backend. The JSONL ledger is always canonical; this only
    chooses the *query* mirror. ``postgres`` is the concurrent-writer path (two
    mediators sharing one mirror must not race the quota table)."""

    model_config = _STRICT
    backend: Literal["sqlite", "postgres"] = "sqlite"
    dsn: SecretStr | None = None  # postgres only; from env/secrets, never YAML in prod

    @model_validator(mode="after")
    def _dsn_required_for_postgres(self) -> "AuditConfig":
        if self.backend == "postgres" and self.dsn is None:
            raise ValueError("audit.backend=postgres requires audit.dsn "
                             "(set AL_AUDIT__DSN from env/secrets)")
        return self


class ControlConfig(BaseModel):
    """Control plane (L6/ops). The kill-switch sentinel lives here.

    In compose the control plane is a *separate service on control-net* that
    agents cannot route to, so its sentinel directory is a small volume shared
    with al-core: engaging the switch is a file the data plane sees, never a
    network path an agent could reach. Default (None) = the runtime data dir.
    """

    model_config = _STRICT
    killswitch_dir: Path | None = None
    # Data-plane evidence, mounted read-only into the control plane so the
    # dashboard can show gateway receipts without a second writer touching
    # that chain. Points at the data plane's data_dir (its al.sqlite mirror,
    # ledger.jsonl and keys/ live under it). None = single-ledger deployment.
    dataplane_dir: Path | None = None
    # Public key that verifies data-plane receipts. Default (None) =
    # <dataplane_dir>/keys/mediator_ed25519.pub.
    dataplane_pubkey: Path | None = None


class MemoryConfig(BaseModel):
    """L5 memory guard: guarded store, integrity baselines, quarantine (ASI06)."""

    model_config = _STRICT
    enabled: bool = True
    store_path: Path = Path("memory.json")  # relative -> under data_dir
    protected_keys: list[str] = ["system/*"]
    trusted_writers: list[str] = []  # identities allowed to write protected keys
    max_value_bytes: int = 65_536


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AL_",
        env_file=".env",  # NON-SECRET settings + pointers only — never key material
        env_nested_delimiter="__",
        # Docker secrets, when present (file names carry the env prefix, e.g.
        # /run/secrets/al_admin_api_token). None on dev hosts — no noise.
        secrets_dir="/run/secrets" if os.path.isdir("/run/secrets") else None,
        extra="forbid",  # unknown keys fail validation
    )

    mode: Literal["audit", "balanced", "strict"] = "balanced"
    env: Literal["dev", "prod"] = "dev"
    listen: str = "0.0.0.0:8888"
    keys: KeysConfig = KeysConfig()
    scanner: ScannerConfig = ScannerConfig()
    gateway: GatewayConfig = GatewayConfig()
    egress: EgressConfig = EgressConfig()
    policy: PolicyConfig = PolicyConfig()
    memory: MemoryConfig = MemoryConfig()
    control: ControlConfig = ControlConfig()
    audit: AuditConfig = AuditConfig()
    learn: LearnConfig = LearnConfig()
    skills: SkillsConfig = SkillsConfig()
    admin_api_token: SecretStr

    @model_validator(mode="after")
    def _enforce_boundary(self) -> "Settings":
        # Never auto-generate signing keys outside dev.
        if self.env != "dev":
            self.keys.auto_generate = False

        # Permissive protections are only allowed in audit mode.
        permissive: list[str] = []
        if not self.scanner.dlp.enabled:
            permissive.append("scanner.dlp.enabled=false")
        if not self.scanner.injection.enabled:
            permissive.append("scanner.injection.enabled=false")
        if not self.scanner.pii.enabled:
            permissive.append("scanner.pii.enabled=false")
        if not self.scanner.bip39.enabled:
            permissive.append("scanner.bip39.enabled=false")
        if not self.scanner.ssrf.block_private:
            permissive.append("scanner.ssrf.block_private=false")
        if not self.scanner.ssrf.dns_rebind_protection:
            permissive.append("scanner.ssrf.dns_rebind_protection=false")
        if not self.gateway.require_identity:
            permissive.append("gateway.require_identity=false")
        if not self.memory.enabled:
            permissive.append("memory.enabled=false")
        if not self.skills.enabled:
            permissive.append("skills.enabled=false")
        if self.env == "prod" and self.egress.bypass_self_test == "disabled":
            permissive.append("egress.bypass_self_test=disabled")
        if permissive and self.mode != "audit":
            raise ValueError(
                "permissive settings require mode: audit — offending keys: "
                + ", ".join(permissive)
            )
        return self


def public_dict(settings: Settings) -> dict[str, Any]:
    """Config as a plain dict with secrets removed (safe to hash / log / record)."""
    data = settings.model_dump(mode="json")
    data.pop("admin_api_token", None)
    return data


def config_hash(settings: Settings) -> str:
    """Stable ``sha256:...`` over the non-secret config.

    Uses sorted-key JSON (not the receipt RFC 8785 canonicalizer) because config
    legitimately contains floats (e.g. entropy thresholds), which receipts forbid.
    This hash is an opaque ``policy_hash`` for change detection, not a portable
    cross-implementation receipt field.
    """
    blob = json.dumps(
        public_dict(settings), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return sha256_hex(blob.encode("utf-8"))


def load_settings(path: str | Path | None = None, **overrides: Any) -> Settings:
    """Load + validate settings from an optional YAML file, env, and overrides.

    Precedence: explicit ``overrides`` > YAML file > environment / .env / secrets.
    Raises on any validation failure (fail-closed).
    """
    data: dict[str, Any] = {}
    if path is not None:
        p = Path(path)
        if p.exists():
            loaded = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"config file {p} must contain a YAML mapping")
            data.update(loaded)
    data.update(overrides)
    return Settings(**data)


OnChange = Callable[["Settings | None", "Settings", str, str], None]


class ConfigManager:
    """Holds the running (last-good) config and mediates reloads.

    ``on_change(old, new, old_hash, new_hash)`` is invoked after a config is
    successfully applied and its hash changed — the wiring point for the signed
    ``config_change`` receipt.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        on_change: OnChange | None = None,
        **overrides: Any,
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._overrides = overrides
        self._on_change = on_change
        self._current: Settings | None = None
        self._current_hash: str | None = None
        # Initial load must succeed — no last-good exists yet (boot is fail-closed).
        self.reload()

    def set_on_change(self, on_change: OnChange | None) -> None:
        """Arm (or clear) the config-change callback after construction.

        Used at boot: the ledger that records a change does not exist while the
        initial config is loaded, so the callback is wired only afterwards.
        """
        self._on_change = on_change

    @property
    def current(self) -> Settings:
        assert self._current is not None
        return self._current

    @property
    def current_hash(self) -> str:
        assert self._current_hash is not None
        return self._current_hash

    def reload(self) -> Settings:
        """Validate and apply config. Keep last-good on failure (after boot)."""
        try:
            new = load_settings(self._path, **self._overrides)
        except Exception as exc:  # noqa: BLE001 — validation / YAML / value errors
            if self._current is None:
                # Boot with no last-good: refuse to start.
                raise
            log.error("invalid config reload rejected; keeping last-good: %s", exc)
            return self._current

        new_hash = config_hash(new)
        old, old_hash = self._current, self._current_hash
        self._current, self._current_hash = new, new_hash
        if new_hash != old_hash and self._on_change is not None:
            self._on_change(old, new, old_hash or "", new_hash)
        return new


__all__ = [
    "AuditConfig",
    "Bip39Config",
    "ConfigManager",
    "ControlConfig",
    "DataBudgetConfig",
    "DlpConfig",
    "EgressConfig",
    "EntropyConfig",
    "GatewayConfig",
    "InjectionConfig",
    "KeysConfig",
    "LearnConfig",
    "MemoryConfig",
    "NormalizeConfig",
    "PiiConfig",
    "PolicyConfig",
    "RateLimitConfig",
    "ScannerConfig",
    "Settings",
    "SkillsConfig",
    "SsrfConfig",
    "UpstreamConfig",
    "config_hash",
    "load_settings",
    "public_dict",
]
