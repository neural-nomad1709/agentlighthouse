"""RFC 8785 JSON Canonicalization Scheme (JCS) — minimal, self-contained.

This is the canonicalization used to hash and sign AgentLighthouse receipts.
It lives in the *verifier* (not core) on purpose: a third party must be able to
reproduce the exact bytes that were signed using only this file + a JSON parser.

Scope note (fail-closed by construction):
    Receipts use only strings, integers, booleans, null, objects and arrays.
    Floating-point numbers are intentionally REJECTED: RFC 8785 mandates
    ECMAScript `Number.prototype.toString` for them, which is subtle and
    error-prone. Every numeric receipt field (seq, counts, severity-as-string)
    is an integer or string, so refusing floats removes a whole class of
    canonicalization ambiguity rather than papering over it.
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized per this JCS profile."""


def _encode_string(s: str) -> str:
    # Python's json string encoder already matches RFC 8785 string rules:
    # it emits the short escapes \" \\ \b \t \n \f \r, encodes other control
    # characters (< 0x20) as \u00xx, does NOT escape '/', and (with
    # ensure_ascii=False) leaves all other code points as literal UTF-8.
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def _encode(value: Any) -> str:
    # bool must be checked before int (bool is a subclass of int in Python).
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise CanonicalizationError(
            "floats are not permitted in receipts; use integers or strings"
        )
    if isinstance(value, dict):
        # RFC 8785: object members are sorted by the UTF-16 code units of their
        # keys. Encoding each key to UTF-16 big-endian and comparing the byte
        # sequences yields exactly that ordering (correct even for astral keys).
        for k in value:
            if not isinstance(k, str):
                raise CanonicalizationError(f"object keys must be strings, got {type(k)!r}")
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_encode_string(k) + ":" + _encode(v) for k, v in items) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    raise CanonicalizationError(f"unsupported type for canonicalization: {type(value)!r}")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 JCS canonical form of ``value`` as UTF-8 bytes."""
    return _encode(value).encode("utf-8")
