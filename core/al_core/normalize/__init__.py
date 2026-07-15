"""L2 — six-pass content normalization (evasion-resistant scanning surface).

Attackers do not send ``ignore previous instructions``; they send it wrapped in
zero-width characters, Cyrillic lookalikes, ``1gn0r3``-speak, per-character
spacing, or a base64 blob. Scanners that only see the raw bytes miss all of it.

This module turns one input text into a bounded set of **scan variants**:

    pass 1  ``nfkc``        Unicode NFKC (fullwidth, ligatures, math alphabets)
    pass 2  ``zero_width``  strip zero-width / bidi / other format (Cf) chars
    pass 3  ``homoglyph``   fold Cyrillic/Greek/… confusables to ASCII
    pass 4  ``leet``        fold leetspeak digits/symbols with letter context
    pass 5  ``collapse``    join per-char spacing, squash char runs + whitespace
    pass 6  ``unwrap``      decode base64/hex blobs; re-enter passes 1–5 at
                            depth+1 (bounded)

The variants are **for scanning only** — delivery content is never rewritten
here (redaction is the detection engine's job, applied to the original text).
L3 scanners run over *every* variant ("re-scan each pass"), so a payload that
becomes visible at any stage is caught. All work is bounded (variant count,
decode depth, blob size) so normalization itself cannot be used for DoS.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

# -- pass 2: zero-width / format characters ----------------------------------

# U+00AD SOFT HYPHEN is category Cf in modern Unicode, listed explicitly for
# clarity; every other zero-width, bidi-control and joiner char is category Cf.
_EXTRA_STRIP = {"­"}


def strip_zero_width(text: str) -> str:
    """Remove format (Cf) characters: zero-width space/joiners, bidi controls,
    BOM, soft hyphen. These render invisibly and exist only to split tokens."""
    return "".join(
        ch for ch in text if unicodedata.category(ch) != "Cf" and ch not in _EXTRA_STRIP
    )


# -- pass 3: homoglyph folding ------------------------------------------------

# Confusable → ASCII. NFKC already folds fullwidth/mathematical forms; this
# table covers the cross-script lookalikes NFKC deliberately leaves alone.
_HOMOGLYPHS = {
    # Cyrillic lowercase
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ց": "g",
    "ν": "v",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "І": "I",
    "Ј": "J",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "τ": "t", "υ": "u",
    "ρ": "p", "σ": "s", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
    # Misc singles
    "ı": "i", "ł": "l", "ẞ": "SS", "ß": "ss",
}

_HOMOGLYPH_TRANS = str.maketrans(_HOMOGLYPHS)


def fold_homoglyphs(text: str) -> str:
    return text.translate(_HOMOGLYPH_TRANS)


# -- pass 4: leetspeak folding -------------------------------------------------

_LEET = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "9": "g", "@": "a", "$": "s", "!": "i", "+": "t", "|": "l",
}


def fold_leetspeak(text: str) -> str:
    """Fold leet chars **only when a letter is adjacent** — ``1gn0re`` becomes
    ``ignore`` while ``192.168.1.1`` and plain numbers stay untouched, so
    later variants do not destroy IPs/keys that other scanners rely on."""
    chars = list(text)
    out = []
    n = len(chars)
    for i, ch in enumerate(chars):
        sub = _LEET.get(ch)
        if sub is not None:
            before = chars[i - 1] if i > 0 else ""
            after = chars[i + 1] if i < n - 1 else ""
            if before.isalpha() or after.isalpha():
                out.append(sub)
                continue
        out.append(ch)
    return "".join(out)


# -- pass 5: vowel/space collapse ----------------------------------------------

# letters separated one-by-one: "i g n o r e" / "i.g.n.o.r.e" / "i-g-n-o-r-e"
_CHAR_SPACING = re.compile(r"\b(?:\w[ \t.\-_]){2,}\w\b")
_RUNS = re.compile(r"(\w)\1{2,}")  # "ignoooore" -> "ignore"
_WS = re.compile(r"\s+")


def collapse(text: str) -> str:
    """Join per-character spacing, squash 3+ repeated chars, collapse
    whitespace runs — the "vowel/space collapse" pass."""
    text = _CHAR_SPACING.sub(lambda m: re.sub(r"[ \t.\-_]", "", m.group(0)), text)
    text = _RUNS.sub(lambda m: m.group(1), text)
    return _WS.sub(" ", text).strip()


# -- pass 6: base64 / hex unwrap -------------------------------------------------

_B64_RE = re.compile(r"[A-Za-z0-9+/_\-]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")
_MAX_BLOB = 65536  # decoded bytes cap per blob


def _mostly_text(raw: bytes) -> str | None:
    """Decoded bytes are interesting only if they look like text."""
    if not raw or len(raw) > _MAX_BLOB:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t ")
    letters = sum(1 for c in s if c.isalpha())
    if printable / len(s) < 0.9 or letters < 4:
        return None
    return s


def _try_b64(blob: str) -> str | None:
    pad = "=" * (-len(blob) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = _mostly_text(decoder(blob + pad))
        except (binascii.Error, ValueError):
            continue
        if decoded is not None:
            return decoded
    return None


def unwrap_encodings(text: str, *, max_blobs: int = 8) -> list[str]:
    """Decode base64/hex-looking blobs to text payloads (bounded count)."""
    found: list[str] = []
    for match in _B64_RE.finditer(text):
        if len(found) >= max_blobs:
            break
        decoded = _try_b64(match.group(0))
        if decoded is not None and decoded != text:
            found.append(decoded)
    for match in _HEX_RE.finditer(text):
        if len(found) >= max_blobs:
            break
        try:
            decoded = _mostly_text(bytes.fromhex(match.group(0).lower()))
        except ValueError:
            decoded = None
        if decoded is not None and decoded != text:
            found.append(decoded)
    return found


# -- the pipeline -----------------------------------------------------------------


@dataclass(frozen=True)
class Variant:
    """One scannable view of the input. ``passes`` is provenance — which
    normalization steps produced it; ``depth`` counts decode unwraps."""

    text: str
    passes: tuple[str, ...]
    depth: int = 0


_PASSES = (
    ("nfkc", lambda s: unicodedata.normalize("NFKC", s)),
    ("zero_width", strip_zero_width),
    ("homoglyph", fold_homoglyphs),
    ("leet", fold_leetspeak),
    ("collapse", collapse),
)


def normalize_variants(
    text: str,
    *,
    max_unwrap_depth: int = 2,
    max_variants: int = 32,
) -> list[Variant]:
    """All scan variants of ``text``: the original, the output of each pass
    (cumulative, deduplicated), and — for every base64/hex payload found —
    the decoded text run back through the same passes, ``max_unwrap_depth``
    deep. The first variant is always the original text unchanged."""
    variants: list[Variant] = []
    seen: set[str] = set()

    def add(candidate: str, passes: tuple[str, ...], depth: int) -> bool:
        if len(variants) >= max_variants or not candidate or candidate in seen:
            return False
        seen.add(candidate)
        variants.append(Variant(candidate, passes, depth))
        return True

    def expand(current: str, provenance: tuple[str, ...], depth: int) -> None:
        add(current, provenance, depth)
        stages: list[tuple[str, str]] = [("raw", current)]
        staged = current
        applied: list[str] = list(provenance)
        for name, fn in _PASSES:
            staged = fn(staged)
            applied.append(name)
            add(staged, tuple(applied), depth)
            stages.append((name, staged))
        if depth < max_unwrap_depth:
            # Unwrap from every stage: a blob may only become contiguous after
            # zero-width stripping, yet be corrupted by later passes (leet
            # folds digits — fatal to base64), so no single view suffices.
            tried: set[str] = set()
            for src_name, source in stages:
                if source in tried:
                    continue
                tried.add(source)
                for payload in unwrap_encodings(source):
                    if len(variants) >= max_variants:
                        return
                    expand(payload, (*provenance, f"unwrap[{src_name}]"), depth + 1)

    expand(text, (), 0)
    return variants


__all__ = [
    "Variant",
    "collapse",
    "fold_homoglyphs",
    "fold_leetspeak",
    "normalize_variants",
    "strip_zero_width",
    "unwrap_encodings",
]
