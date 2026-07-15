"""JCS (RFC 8785) canonicalization correctness — the evidence integrity base."""

from __future__ import annotations

import pytest

from al_verify.canonical import CanonicalizationError, canonicalize


def c(obj) -> str:
    return canonicalize(obj).decode("utf-8")


def test_object_keys_sorted():
    assert c({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_ascii_key_order_is_codeunit_not_lexicase():
    # 'A'(0x41) < 'a'(0x61): uppercase sorts before lowercase.
    assert c({"a": 1, "A": 2}) == '{"A":2,"a":1}'


def test_nested_and_array_order_preserved():
    assert c({"z": [3, 2, 1], "a": {"y": 1, "x": 2}}) == '{"a":{"x":2,"y":1},"z":[3,2,1]}'


def test_integers_and_bools_and_null():
    assert c({"n": 0, "neg": -5, "t": True, "f": False, "z": None}) == (
        '{"f":false,"n":0,"neg":-5,"t":true,"z":null}'
    )


def test_string_control_char_escaping():
    # Short escapes for \t and \n; no escaping of '/'.
    assert c({"s": "a\tb\nc/d"}) == '{"s":"a\\tb\\nc/d"}'


def test_unicode_preserved_literally():
    assert c({"s": "café"}) == '{"s":"café"}'


def test_utf16_codeunit_key_ordering_astral():
    # The RFC 8785 gotcha: keys sort by UTF-16 code units, NOT code points.
    # '😀' U+1F600 encodes to surrogate 0xD83D... ; 'ﬀ' U+FB00 is a BMP char.
    # By code point ﬀ(0xFB00) < 😀(0x1F600), but by UTF-16 code unit
    # 😀(first unit 0xD83D) < ﬀ(0xFB00), so 😀 must come first.
    out = c({"\U0001F600": 1, "ﬀ": 2})
    assert out == '{"\U0001F600":1,"ﬀ":2}'
    assert out.index("\U0001F600") < out.index("ﬀ")


def test_floats_are_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": 1.5})


def test_unsupported_type_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": {1, 2}})  # a set is not JSON
