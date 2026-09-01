"""detect-secrets behind the Scanner Protocol — adapter pattern.

Yelp's detect-secrets brings keyword- and format-aware detectors (AWS, GitHub,
Slack, Stripe, JWT, private keys, …) that go beyond the baseline regexes in
:mod:`.scanners`. It is wrapped, not integrated: the engine sees one more
``Scanner``, the fail-closed matrix applies unchanged (a crash or hang in the
library blocks), and findings carry redaction classes only — the matched
plaintext never leaves this module.

The detector instances are constructed once, in ``__init__``, and
``analyze_line`` is called on them directly. The library's own
``transient_settings`` route is deliberately avoided: it mutates a
process-global singleton, and the engine runs scans concurrently — a scanner
must own its state (Scanner Protocol: thread-safe, side-effect free).

The generic entropy plugins (Base64/Hex "high entropy string") are deliberately
NOT used: they flag ordinary prose, and AL ships its own tuned EntropyScanner.
The curated list below keeps the high-signal, typed detectors.

Opt-in via config (``scanner.detect_secrets.enabled: true``) because the
library is an optional dependency: install with ``al-core[scanners]``.
Constructing the scanner without the library raises ImportError, so an
operator who enabled it refuses at boot rather than silently skipping.
"""

from __future__ import annotations

from .base import ScanContext, ScanFinding

# High-signal, typed detectors only (see module docstring).
DEFAULT_PLUGINS: tuple[str, ...] = (
    "AWSKeyDetector",
    "AzureStorageKeyDetector",
    "BasicAuthDetector",
    "DiscordBotTokenDetector",
    "GitHubTokenDetector",
    "GitLabTokenDetector",
    "JwtTokenDetector",
    "MailchimpDetector",
    "NpmDetector",
    "OpenAIDetector",
    "PrivateKeyDetector",
    "SendGridDetector",
    "SlackDetector",
    "StripeDetector",
    "TelegramBotTokenDetector",
    "TwilioKeyDetector",
)

# Detectors whose reported secret_value is a sentinel (e.g. the PEM armor
# header), not the material itself. Redacting the sentinel would deliver the
# payload under a 'strip' verdict, so these block outright.
_BLOCK_TYPES: frozenset[str] = frozenset({"Private Key"})


def _redaction_class(secret_type: str) -> str:
    """'AWS Access Key' -> 'ds-aws-access-key' (typed, never the material)."""
    return "ds-" + "-".join(secret_type.lower().split())


class DetectSecretsScanner:
    """The first non-regex engine behind the Strategy seam."""

    name = "detect_secrets"

    def __init__(self, plugins: tuple[str, ...] = DEFAULT_PLUGINS) -> None:
        import detect_secrets  # noqa: F401 — fail here, at boot, if absent
        from detect_secrets.core.plugins.initialize import from_plugin_classname

        self._detectors = [from_plugin_classname(name) for name in plugins]

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        offset = 0
        for line in text.splitlines(keepends=True):
            bare = line.rstrip("\n")
            for detector in self._detectors:
                for hit in detector.analyze_line(filename="<memory>", line=bare):
                    findings.extend(self._findings(hit, line, offset))
            offset += len(line)
        return findings

    def _findings(self, hit, line: str, offset: int) -> list[ScanFinding]:
        cls = _redaction_class(hit.type)
        rule_id = f"ds.{cls[3:]}"
        secret = hit.secret_value
        start = line.find(secret) if secret else -1
        if hit.type in _BLOCK_TYPES or start < 0:
            # Sentinel-only detection, or material we cannot locate for a
            # faithful redaction: the payload would survive a strip -> block.
            return [ScanFinding(
                scanner=self.name, rule_id=rule_id, severity="high",
                action="block", owasp="ASI03", mitre="T1552",
                redaction_class=cls, block_reason="CONTENT_BLOCKED",
            )]
        # detect-secrets dedupes identical secrets per line; redact every
        # occurrence, not just the first.
        out: list[ScanFinding] = []
        while start >= 0:
            out.append(ScanFinding(
                scanner=self.name, rule_id=rule_id, severity="high",
                action="strip", owasp="ASI03", mitre="T1552",
                span=(offset + start, offset + start + len(secret)),
                redaction_class=cls,
            ))
            start = line.find(secret, start + len(secret))
        return out


__all__ = ["DEFAULT_PLUGINS", "DetectSecretsScanner"]
