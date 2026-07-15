"""Config-as-enforcement-boundary (config_test — Phase 0 acceptance)."""

from __future__ import annotations

import pytest

from al_core.config import ConfigManager, load_settings


def _write(tmp_path, text: str):
    p = tmp_path / "cfg.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_valid_config_loads(tmp_path):
    p = _write(tmp_path, "mode: balanced\nenv: dev\n")
    s = load_settings(p, admin_api_token="x")
    assert s.mode == "balanced"


def test_unknown_top_level_key_rejected(tmp_path):
    p = _write(tmp_path, "mode: balanced\nbogus_key: 1\n")
    with pytest.raises(Exception):
        load_settings(p, admin_api_token="x")


def test_unknown_nested_scanner_key_rejected(tmp_path):
    p = _write(tmp_path, "scanner:\n  ssrf:\n    not_a_real_option: true\n")
    with pytest.raises(Exception):
        load_settings(p, admin_api_token="x")


def test_permissive_default_rejected_outside_audit(tmp_path):
    p = _write(tmp_path, "mode: balanced\nscanner:\n  ssrf:\n    block_private: false\n")
    with pytest.raises(ValueError):
        load_settings(p, admin_api_token="x")


def test_permissive_allowed_in_audit_mode(tmp_path):
    p = _write(tmp_path, "mode: audit\nscanner:\n  ssrf:\n    block_private: false\n")
    s = load_settings(p, admin_api_token="x")
    assert s.scanner.ssrf.block_private is False


def test_prod_forces_no_autogenerate(tmp_path):
    p = _write(tmp_path, "mode: balanced\nenv: prod\n")
    s = load_settings(p, admin_api_token="x")
    assert s.keys.auto_generate is False


def test_secret_not_leaked_in_repr(tmp_path):
    p = _write(tmp_path, "mode: balanced\n")
    s = load_settings(p, admin_api_token="super-secret-value")
    assert "super-secret-value" not in repr(s)
    assert "super-secret-value" not in str(s)


def test_public_dict_excludes_secret(tmp_path):
    from al_core.config import public_dict

    p = _write(tmp_path, "mode: balanced\n")
    s = load_settings(p, admin_api_token="super-secret-value")
    assert "admin_api_token" not in public_dict(s)


def test_last_good_preserved_on_invalid_reload(tmp_path):
    p = _write(tmp_path, "mode: balanced\n")
    changes: list = []
    mgr = ConfigManager(p, admin_api_token="x", on_change=lambda *a: changes.append(a))
    assert mgr.current.mode == "balanced"

    # Corrupt the file, then reload: manager keeps last-good and does not raise.
    p.write_text("mode: balanced\nbogus_key: 1\n", encoding="utf-8")
    result = mgr.reload()
    assert result.mode == "balanced"  # unchanged, still valid
    assert mgr.current.mode == "balanced"


def test_change_callback_fires_on_real_change(tmp_path):
    p = _write(tmp_path, "mode: balanced\n")
    changes: list = []
    mgr = ConfigManager(p, admin_api_token="x")
    mgr.set_on_change(lambda old, new, oh, nh: changes.append((oh, nh)))

    p.write_text("mode: strict\n", encoding="utf-8")
    mgr.reload()
    assert len(changes) == 1
    assert changes[0][0] != changes[0][1]  # hash changed


def test_boot_with_invalid_config_raises(tmp_path):
    p = _write(tmp_path, "mode: not_a_mode\n")
    with pytest.raises(Exception):
        ConfigManager(p, admin_api_token="x")


# -- Phase 1: gateway / egress config boundary --------------------------------

def test_unknown_gateway_key_rejected(tmp_path):
    p = _write(tmp_path, "gateway:\n  not_an_option: true\n")
    with pytest.raises(Exception):
        load_settings(p, admin_api_token="x")


def test_bypass_self_test_disabled_in_prod_requires_audit(tmp_path):
    p = _write(tmp_path, "mode: balanced\nenv: prod\negress:\n  bypass_self_test: disabled\n")
    with pytest.raises(ValueError):
        load_settings(p, admin_api_token="x")


def test_bypass_self_test_disabled_in_prod_allowed_in_audit(tmp_path):
    p = _write(tmp_path, "mode: audit\nenv: prod\negress:\n  bypass_self_test: disabled\n")
    s = load_settings(p, admin_api_token="x")
    assert s.egress.bypass_self_test == "disabled"


def test_bypass_self_test_disabled_in_dev_is_not_permissive(tmp_path):
    # Dev laptops have legitimate direct internet; disabling there is normal.
    p = _write(tmp_path, "mode: balanced\nenv: dev\negress:\n  bypass_self_test: disabled\n")
    s = load_settings(p, admin_api_token="x")
    assert s.egress.bypass_self_test == "disabled"


def test_upstream_api_key_never_plaintext_in_public_dict(tmp_path):
    from al_core.config import public_dict

    p = _write(tmp_path, "mode: balanced\n")
    s = load_settings(p, admin_api_token="x")
    s.gateway.upstream.openai_api_key = __import__("pydantic").SecretStr("sk-real-key")
    blob = str(public_dict(s))
    assert "sk-real-key" not in blob
