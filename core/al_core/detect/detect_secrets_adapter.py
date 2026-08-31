"""detect-secrets behind the Scanner Protocol (AL-0.3) — adapter pattern.

Yelp's detect-secrets brings keyword- and format-aware detectors (AWS, GitHub,
Slack, Stripe, JWT, private keys, …) that go beyond the baseline regexes in
:mod:`.scanners`. It is wrapped, not integrated: the engine sees one more
``Scanner``, the fail-closed matrix applies unchanged (a crash or hang in the
library blocks), and findings carry redaction classes only — the matched
plaintext never leaves this function.

The generic entropy plugins (Base64/Hex "high entropy string") are deliberately
NOT used: they flag ordinary prose, and AL ships its own tuned EntropyScanner.
The curated list below keeps the high-signal, typed detectors.

Opt-in via config (``scanner.detect_secrets.enabled: true``) because the
library is an optional dependency: install with ``al-core[scanners]``.
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


def _redaction_class(secret_type: str) -> str:
    """'AWS Access Key' -> 'ds-aws-access-key' (typed, never the material)."""
    return "ds-" + "-".join(secret_type.lower().split())


class DetectSecretsScanner:
    """The first non-regex engine behind the Strategy seam."""

    name = "detect_secrets"

    def __init__(self, plugins: tuple[str, ...] = DEFAULT_PLUGINS) -> None:
        self._plugins = plugins

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        # Imported here so al-core without the [scanners] extra still imports
        # this module; enabling the scanner without the library installed
        # fails at build time in default_scanners (fail-closed, not silent).
        from detect_secrets.core.scan import scan_line
        from detect_secrets.settings import transient_settings

        findings: list[ScanFinding] = []
        offset = 0
        with transient_settings(
            {"plugins_used": [{"name": name} for name in self._plugins]}
        ):
            for line in text.splitlines(keepends=True):
                for hit in scan_line(line.rstrip("\n")):
                    findings.append(self._finding(hit, line, offset))
                offset += len(line)
        return findings

    def _finding(self, hit, line: str, offset: int) -> ScanFinding:
        cls = _redaction_class(hit.type)
        secret = hit.secret_value
        start = line.find(secret) if secret else -1
        if start < 0:
            # Cannot locate the material to redact it faithfully -> block.
            # (PrivateKeyDetector, e.g., reports the armor header only.)
            return ScanFinding(
                scanner=self.name, rule_id=f"ds.{cls[3:]}", severity="high",
                action="block", owasp="ASI03", mitre="T1552",
                redaction_class=cls, block_reason="CONTENT_BLOCKED",
            )
        return ScanFinding(
            scanner=self.name, rule_id=f"ds.{cls[3:]}", severity="high",
            action="strip", owasp="ASI03", mitre="T1552",
            span=(offset + start, offset + start + len(secret)),
            redaction_class=cls,
        )


__all__ = ["DEFAULT_PLUGINS", "DetectSecretsScanner"]
