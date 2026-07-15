"""L3 detection adapters — the built-in scanner set.

Each adapter implements the ``Scanner`` surface from ``detect.base`` and does
one job. They are intentionally dependency-free (regex + stdlib) so the core
runs anywhere; the interface is the contract, so LLM Guard / Presidio /
detect-secrets can be dropped in later behind the same ``scan()`` without
touching the engine.

Scanners never see policy and never mutate text. ``strip`` findings carry a
span + typed ``redaction_class``; ``block`` findings carry severity + OWASP/
MITRE tags for the receipt. The engine (``detect.engine``) owns precedence,
redaction, and fail-closed behaviour.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urlsplit

from .base import ScanContext, ScanFinding
from .bip39_words import BIP39_WORDS

# ============================================================================
# injection — tiered heuristics (LLM Guard is the future primary; this is the
# dependency-free baseline). ASI01 goal-hijack.
# ============================================================================

# High-confidence imperative override patterns. Word boundaries + limited
# intervening words so "ignore ... instructions" still matches across fillers.
_INJECTION_HIGH = [
    (r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+"
     r"(?:\w+\s+){0,3}?(?:instruction|prompt|direction|rule|context|message)", "override.ignore_previous"),
    (r"disregard\s+(?:all\s+|the\s+|your\s+)?(?:\w+\s+){0,3}?(?:instruction|prompt|rule|guideline|direction)", "override.disregard"),
    (r"forget\s+(?:everything|all|your|the)\s+(?:\w+\s+){0,3}?(?:instruction|prompt|rule|above|prior|context)", "override.forget"),
    (r"(?:you\s+are\s+now|from\s+now\s+on\s+you(?:'re|\s+are)|act\s+as|pretend\s+to\s+be)\s+"
     r"(?:a\s+|an\s+)?(?:dan|jailbroken|unrestricted|developer\s+mode|evil|unfiltered)", "jailbreak.persona"),
    (r"(?:reveal|print|show|repeat|output|disclose)\s+(?:me\s+)?(?:your|the)\s+"
     r"(?:system\s+prompt|initial\s+instructions|instructions|system\s+message|prompt\b)", "exfil.system_prompt"),
    (r"</?(?:system|instructions?|admin|developer)>", "injection.fake_role_tag"),
    (r"\[/?(?:INST|SYS|SYSTEM|s)\]", "injection.fake_chat_template"),
    (r"###\s*(?:system|instruction|admin)\b", "injection.fake_section_header"),
    (r"do\s+anything\s+now\b", "jailbreak.dan"),
    (r"developer\s+mode\s+(?:enabled|on|activated)", "jailbreak.developer_mode"),
]

# Lower-confidence signals — warn, or escalate under strict mode.
_INJECTION_MED = [
    (r"\bsystem\s*prompt\b", "injection.mentions_system_prompt"),
    (r"\boverride\s+(?:the\s+)?(?:safety|security|guardrail|filter)", "injection.override_safety"),
    (r"\bbypass\s+(?:the\s+)?(?:filter|guardrail|restriction|safety|security)", "injection.bypass"),
    (r"\b(?:base64|rot13|hex)\s*(?:decode|encoded)?\s*(?:the\s+following|this)?\s*:?\s*(?:and\s+(?:run|execute|follow))", "injection.decode_and_run"),
]


class InjectionScanner:
    name = "injection"

    def __init__(self) -> None:
        self._high = [(re.compile(p, re.I), rid) for p, rid in _INJECTION_HIGH]
        self._med = [(re.compile(p, re.I), rid) for p, rid in _INJECTION_MED]

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        for rx, rid in self._high:
            if rx.search(text):
                out.append(ScanFinding(
                    scanner=self.name, rule_id=rid, severity="high", action="block",
                    owasp="ASI01", mitre="T1204",
                ))
        for rx, rid in self._med:
            if rx.search(text):
                out.append(ScanFinding(
                    scanner=self.name, rule_id=rid, severity="medium", action="warn",
                    owasp="ASI01",
                ))
        return out


# ============================================================================
# secrets — credential patterns + high-entropy assignments. ASI03/T1552.
# ============================================================================

_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "secrets.aws_access_key", "aws-access-key"),
    (r"ASIA[0-9A-Z]{16}", "secrets.aws_temp_key", "aws-access-key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "secrets.google_api_key", "google-api-key"),
    (r"ghp_[0-9A-Za-z]{36}", "secrets.github_pat", "github-pat"),
    (r"gho_[0-9A-Za-z]{36}", "secrets.github_oauth", "github-token"),
    (r"github_pat_[0-9A-Za-z_]{22,}", "secrets.github_fine_pat", "github-pat"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "secrets.slack_token", "slack-token"),
    (r"sk-ant-[0-9A-Za-z\-_]{20,}", "secrets.anthropic_key", "anthropic-key"),
    (r"sk-(?!ant-)(?:proj-)?[0-9A-Za-z\-_]{20,}", "secrets.openai_key", "openai-key"),
    (r"glpat-[0-9A-Za-z\-_]{20,}", "secrets.gitlab_pat", "gitlab-pat"),
    (r"(?:r|s)k_live_[0-9A-Za-z]{24,}", "secrets.stripe_key", "stripe-key"),
    (r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY", "secrets.private_key", "private-key"),
    (r"eyJ[0-9A-Za-z\-_]{10,}\.eyJ[0-9A-Za-z\-_]{10,}\.[0-9A-Za-z\-_]{10,}", "secrets.jwt", "jwt"),
]

# key = value where the value is long + high-entropy (generic secret catch-all)
_ASSIGN_RE = re.compile(
    r"(?i)\b(?:secret|token|password|passwd|pwd|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|client[_\-]?secret|auth)\b\s*[:=]\s*['\"]?([^\s'\"]{16,})",
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class SecretScanner:
    name = "secrets"

    def __init__(self) -> None:
        self._patterns = [(re.compile(p), rid, cls) for p, rid, cls in _SECRET_PATTERNS]

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        for rx, rid, cls in self._patterns:
            for m in rx.finditer(text):
                out.append(ScanFinding(
                    scanner=self.name, rule_id=rid, severity="high", action="strip",
                    owasp="ASI03", mitre="T1552", span=(m.start(), m.end()),
                    redaction_class=cls,
                ))
        for m in _ASSIGN_RE.finditer(text):
            value = m.group(1)
            if shannon_entropy(value) >= 3.0:
                out.append(ScanFinding(
                    scanner=self.name, rule_id="secrets.high_entropy_assignment",
                    severity="high", action="strip", owasp="ASI03", mitre="T1552",
                    span=(m.start(1), m.end(1)), redaction_class="generic-secret",
                ))
        return out


# ============================================================================
# bip39 — seed-phrase / wallet-recovery material. Block (never redact — the
# whole sequence is the secret and its presence is the signal). ASI03.
# ============================================================================

_WORD_RE = re.compile(r"[a-z]+")


class Bip39Scanner:
    name = "bip39"
    #: BIP-39 mnemonics are 12/15/18/21/24 words. 12 is the shortest valid one;
    #: below that a run of common words is almost certainly natural language.
    MIN_RUN = 12

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        tokens = _WORD_RE.findall(text.lower())
        run = 0
        best = 0
        for tok in tokens:
            if tok in BIP39_WORDS:
                run += 1
                best = max(best, run)
            else:
                run = 0
        if best >= self.MIN_RUN:
            return [ScanFinding(
                scanner=self.name, rule_id="bip39.seed_phrase", severity="critical",
                action="block", owasp="ASI03", mitre="T1552",
            )]
        return []


# ============================================================================
# pii — regex core (Presidio is the optional upgrade). Redact by default;
# config can force block/warn. Not an OWASP-agentic risk per se, but DLP.
# ============================================================================

_LUHN_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_PII_PATTERNS = [
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "pii.email", "email", "medium"),
    (r"\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b", "pii.phone", "phone", "low"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "pii.ssn", "us-ssn", "high"),
]


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class PiiScanner:
    name = "pii"

    def __init__(self, action: str = "redact") -> None:
        # config uses "redact"; the engine vocabulary calls it "strip"
        self._action = "strip" if action == "redact" else action
        self._patterns = [
            (re.compile(p), rid, cls, sev) for p, rid, cls, sev in _PII_PATTERNS
        ]

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        for rx, rid, cls, sev in self._patterns:
            for m in rx.finditer(text):
                out.append(self._finding(rid, cls, sev, m.start(), m.end()))
        for m in _LUHN_RE.finditer(text):
            digits = re.sub(r"[ -]", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                out.append(self._finding(
                    "pii.credit_card", "credit-card", "high", m.start(), m.end()
                ))
        return out

    def _finding(self, rid: str, cls: str, sev: str, start: int, end: int) -> ScanFinding:
        return ScanFinding(
            scanner=self.name, rule_id=rid, severity=sev, action=self._action,
            span=(start, end), redaction_class=cls,
        )


# ============================================================================
# content-ssrf — URLs/hosts embedded in content that point at internal targets.
# Distinct from the L1 egress SSRF (which guards the *destination* of a fetch);
# this guards *content* carrying an internal address (indirect SSRF / exfil).
# ASI01/ASI08.
# ============================================================================

import ipaddress  # noqa: E402

from ..gateway.ssrf import classify_ip  # noqa: E402 — avoid import cycle at top

_URL_RE = re.compile(r"\b(?:https?|ftp|gopher|file|dict|ldap)://([^\s/:?#]+)", re.I)
_BARE_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_METADATA_HOSTS = {"metadata.google.internal", "metadata.goog", "instance-data"}


def _classify_host(host: str) -> str | None:
    """Block label for a host that *is* an IP literal, else None. Hostnames
    (which need DNS to resolve) are out of scope for content scanning."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return classify_ip(host)


class ContentSsrfScanner:
    name = "ssrf"

    def __init__(self, *, metadata_only: bool = False) -> None:
        # ``metadata_only`` keeps only the findings that are hostile in *any*
        # context — the cloud-metadata endpoints (169.254.169.254 et al.) — and
        # drops private/loopback/CGNAT URL shapes. Those shapes are exfil-signal
        # in fetched web content but ordinary documentation in human-authored
        # text ("the dashboard runs at 127.0.0.1:8899"), so the skill guard asks
        # for metadata-only. It narrows scope, it does not weaken detection: a
        # metadata endpoint in an instruction file still blocks.
        self._metadata_only = metadata_only

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        seen: set[str] = set()
        for m in _URL_RE.finditer(text):
            host = m.group(1).split("@")[-1].strip("[]").lower()
            if host in _METADATA_HOSTS and host not in seen:
                seen.add(host)
                out.append(self._finding("ssrf.metadata_host"))
                continue
            label = _classify_host(host)
            if label and host not in seen and not self._metadata_only:
                seen.add(host)
                out.append(self._finding(f"ssrf.private_url.{label}"))
        for m in _BARE_IP_RE.finditer(text):
            ip = m.group(0)
            label = _classify_host(ip)
            if label not in ("metadata", "loopback", "private", "link_local", "cgnat"):
                continue
            if self._metadata_only and label != "metadata":
                continue
            if ip not in seen:
                seen.add(ip)
                out.append(self._finding(f"ssrf.private_ip.{label}"))
        return out

    def _finding(self, rid: str) -> ScanFinding:
        sev = "high" if "metadata" in rid else "medium"
        return ScanFinding(
            scanner=self.name, rule_id=rid, severity=sev, action="block",
            owasp="ASI01", mitre="T1552",
        )


# ============================================================================
# entropy — high-Shannon path/subdomain segments (DNS tunnel / base64 blob).
# Warn (balanced) / block (strict). ASI08 exfil-shaped. Config thresholds.
# ============================================================================

_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


class EntropyScanner:
    name = "entropy"

    def __init__(self, path_threshold: float = 4.0, subdomain_threshold: float = 3.5) -> None:
        self._path_t = path_threshold
        self._sub_t = subdomain_threshold

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        for m in _URL_RE.finditer(text):
            host = m.group(1)
            labels = host.split(".")
            for label in labels[:-2] if len(labels) > 2 else []:
                if len(label) >= 20 and shannon_entropy(label) >= self._sub_t:
                    out.append(self._finding("entropy.high_subdomain"))
                    break
        for m in _LONG_TOKEN_RE.finditer(text):
            tok = m.group(0)
            if len(tok) >= 32 and shannon_entropy(tok) >= self._path_t:
                out.append(self._finding("entropy.high_token"))
                break  # one signal is enough; avoid receipt spam
        return out

    def _finding(self, rid: str) -> ScanFinding:
        return ScanFinding(
            scanner=self.name, rule_id=rid, severity="medium", action="warn",
            owasp="ASI08",
        )


# ============================================================================
# url-shape — scheme / CRLF / path-traversal in embedded URLs and content.
# Block. Cheap structural checks the injection heuristics don't cover.
# ============================================================================

_DANGEROUS_SCHEMES = re.compile(r"\b(file|gopher|dict|ldap|ftp|jar|data|javascript|vbscript)://", re.I)
_CRLF_RE = re.compile(r"(?:%0d%0a|%0a|%0d|\r\n|\r|\n)(?=[A-Za-z\-]+\s*:)")
_TRAVERSAL_RE = re.compile(r"(?:\.\./|\.\.\\|%2e%2e[/\\]|\.\.%2f){2,}", re.I)


class UrlShapeScanner:
    name = "url_shape"

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        if _DANGEROUS_SCHEMES.search(text):
            out.append(self._finding("url_shape.dangerous_scheme", "high"))
        if _TRAVERSAL_RE.search(text):
            out.append(self._finding("url_shape.path_traversal", "high"))
        # CRLF header-injection only meaningful when it appears inside a URL
        for m in _URL_RE.finditer(text):
            frag = text[m.start(): m.start() + 512]
            if _CRLF_RE.search(frag):
                out.append(self._finding("url_shape.crlf_injection", "medium"))
                break
        return out

    def _finding(self, rid: str, sev: str) -> ScanFinding:
        return ScanFinding(
            scanner=self.name, rule_id=rid, severity=sev, action="block",
            owasp="ASI02", mitre="T1059",
        )


def default_scanners(settings) -> list:
    """Build the built-in scanner set from a ``Settings`` scanner config.

    Disabled scanners (only legal in audit mode) are simply omitted.
    """
    sc = settings.scanner
    scanners: list = []
    if sc.injection.enabled:
        scanners.append(InjectionScanner())
    if sc.dlp.enabled:
        scanners.append(SecretScanner())
    if sc.bip39.enabled:
        scanners.append(Bip39Scanner())
    if sc.pii.enabled:
        scanners.append(PiiScanner(action=sc.pii.action))
    if sc.ssrf.block_private:
        scanners.append(ContentSsrfScanner())
    scanners.append(EntropyScanner(
        path_threshold=sc.entropy.path_threshold,
        subdomain_threshold=sc.entropy.subdomain_threshold,
    ))
    scanners.append(UrlShapeScanner())
    return scanners


def skill_scanners(settings) -> list:
    """Scanner set tuned for agent instruction files (SKILL.md / CLAUDE.md / ...).

    Same engines, a different *scope*, because the input is different. An
    instruction file is human-authored prose, so two things that are exfil-signal
    in fetched web content are ordinary documentation here and are deliberately
    left out:

    * the generic **entropy** scanner — a git SHA or a base64 example in a fenced
      code block is not a DNS-tunnel blob;
    * private/loopback/CGNAT **URL shapes** — "run the dashboard at 127.0.0.1:8899"
      is a dev note, not an SSRF. (The cloud-**metadata** endpoints stay: an
      instruction file telling the agent to read 169.254.169.254 IS an attack, so
      the SSRF scanner runs in ``metadata_only`` mode, not omitted.)

    What matters for an instruction file is kept in full: injection (block — the
    core threat), secrets + PII (redact — a pasted credential is a leak), seed
    phrases (block), and URL shape (traversal/CRLF). The omissions narrow false
    positives on documentation; they do not create a blind spot for any threat an
    instruction file actually carries.
    """
    sc = settings.scanner
    scanners: list = []
    if sc.injection.enabled:
        scanners.append(InjectionScanner())
    if sc.dlp.enabled:
        scanners.append(SecretScanner())
    if sc.bip39.enabled:
        scanners.append(Bip39Scanner())
    if sc.pii.enabled:
        scanners.append(PiiScanner(action=sc.pii.action))
    if sc.ssrf.block_private:
        scanners.append(ContentSsrfScanner(metadata_only=True))
    scanners.append(UrlShapeScanner())
    return scanners


__all__ = [
    "Bip39Scanner",
    "ContentSsrfScanner",
    "EntropyScanner",
    "InjectionScanner",
    "PiiScanner",
    "SecretScanner",
    "UrlShapeScanner",
    "default_scanners",
    "shannon_entropy",
    "skill_scanners",
]
