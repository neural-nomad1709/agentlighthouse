"""Runtime boot + /healthz + config-change receipting."""

from __future__ import annotations

from al_core.runtime import Runtime


def _cfg(tmp_path, text):
    p = tmp_path / "cfg.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_boot_is_healthy(tmp_path):
    rt = Runtime(_cfg(tmp_path, "mode: balanced\n"), data_dir=tmp_path / "data")
    h = rt.healthz()
    assert h["status"] == "healthy"
    assert h["chain"]["verified"] is True
    assert h["mode"] == "balanced"
    rt.close()


def test_boot_records_config_once_then_idempotent(tmp_path):
    data = tmp_path / "data"
    cfg = _cfg(tmp_path, "mode: balanced\n")

    rt = Runtime(cfg, data_dir=data)
    assert rt.ledger.next_seq == 1  # one config:boot receipt recorded
    rt.close()

    # Reboot with identical config: no new receipt.
    rt2 = Runtime(cfg, data_dir=data)
    assert rt2.ledger.next_seq == 1
    rt2.close()


def test_config_reload_emits_signed_record(tmp_path):
    data = tmp_path / "data"
    cfg = _cfg(tmp_path, "mode: balanced\n")
    rt = Runtime(cfg, data_dir=data)
    start = rt.ledger.next_seq

    cfg.write_text("mode: strict\n", encoding="utf-8")
    rt.reload_config()
    assert rt.ledger.next_seq == start + 1
    assert rt.healthz()["chain"]["verified"] is True
    rt.close()


def test_config_hot_reload_watcher(tmp_path):
    import time

    data = tmp_path / "data"
    cfg = _cfg(tmp_path, "mode: balanced\n")
    rt = Runtime(cfg, data_dir=data)
    rt.start_config_watch()
    try:
        assert rt.settings.mode == "balanced"
        # watchfiles needs a real mtime change; rewrite the file.
        time.sleep(0.2)
        cfg.write_text("mode: strict\n", encoding="utf-8")

        deadline = time.time() + 8
        while time.time() < deadline and rt.settings.mode != "strict":
            time.sleep(0.1)
        assert rt.settings.mode == "strict", "hot-reload did not apply within 8s"
    finally:
        rt.close()


def test_healthz_endpoint(tmp_path):
    from fastapi.testclient import TestClient

    from al_core.app import create_app

    app = create_app(_cfg(tmp_path, "mode: balanced\n"), data_dir=tmp_path / "data")
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
