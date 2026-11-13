"""The al-core wheel is usable with no clone and no Node.

A pip/uv install has no repository root, so the shipped configs, the
default-deny tool policy and the built dashboard travel inside the wheel
(``al_core/_bundled``) and ``al init`` lays the editable ones down in the
working directory.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from al_core import resources
from al_core.cli.main import app

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def test_a_checkout_resolves_bundled_data_at_the_repo_root():
    assert resources.bundled("configs") == ROOT / "configs"
    assert resources.bundled("policies") == ROOT / "policies"
    assert resources.bundled("dashboard") == ROOT / "frontend" / "dist"
    assert (resources.bundled("configs") / "balanced.yaml").is_file()


def test_an_installed_wheel_resolves_bundled_data_inside_the_package(tmp_path, monkeypatch):
    packaged = tmp_path / "_bundled"
    (packaged / "configs").mkdir(parents=True)
    monkeypatch.setattr(resources, "_PACKAGED", packaged)
    assert resources.bundled("configs") == packaged / "configs"
    # Not in the wheel (a build without the dashboard): fall back, never crash.
    assert resources.bundled("dashboard") == ROOT / "frontend" / "dist"


def test_bundled_rejects_an_unknown_name():
    with pytest.raises(KeyError):
        resources.bundled("keys")


def test_init_in_an_empty_directory_lays_down_configs_and_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = runner.invoke(app, ["init"])
    assert r.exit_code == 0, r.stdout
    for name in ("audit.yaml", "balanced.yaml", "strict.yaml"):
        assert (tmp_path / "configs" / name).read_bytes() == (
            ROOT / "configs" / name).read_bytes()
    assert (tmp_path / "policies" / "default-deny.yaml").is_file()
    # The workspace it produced boots with the shipped config and policy.
    r = runner.invoke(app, ["healthz", "--config", "configs/balanced.yaml"])
    assert r.exit_code == 0, r.stdout


def test_init_never_overwrites_an_operators_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "configs").mkdir()
    mine = tmp_path / "configs" / "balanced.yaml"
    mine.write_text("mode: strict\n", encoding="utf-8")
    r = runner.invoke(app, ["init"])
    assert r.exit_code == 0, r.stdout
    assert mine.read_text(encoding="utf-8") == "mode: strict\n"
    assert not (tmp_path / "configs" / "audit.yaml").exists()  # dir left alone


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build the wheel")
def test_the_wheel_carries_configs_policy_and_dashboard(tmp_path):
    out = tmp_path / "dist"
    built = subprocess.run(
        ["uv", "build", "--wheel", "--package", "al-core", "-o", str(out)],
        cwd=ROOT, capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    (wheel,) = out.glob("al_core-*.whl")
    names = set(zipfile.ZipFile(wheel).namelist())
    assert "al_core/_bundled/configs/balanced.yaml" in names
    assert "al_core/_bundled/configs/audit.yaml" in names
    assert "al_core/_bundled/configs/strict.yaml" in names
    assert "al_core/_bundled/policies/default-deny.yaml" in names
    if (ROOT / "frontend" / "dist" / "index.html").is_file():
        assert "al_core/_bundled/dashboard/index.html" in names
    # Every tracked source file is in the wheel. (.gitignore's `keys/` rule
    # once dropped the al_core.keys package from it.)
    tracked = subprocess.run(
        ["git", "ls-files", "al_core"], cwd=ROOT / "core",
        capture_output=True, text=True, check=True).stdout.split()
    assert "al_core/keys/__init__.py" in tracked
    assert not [f for f in tracked if f not in names]
    # No secrets, no runtime data, no build junk ride along.
    assert not [n for n in names if "keys/" in n and "al_core/keys/" not in n]
    assert not [n for n in names if n.endswith((".sqlite", ".jsonl", ".env"))]
    assert not [n for n in names if "__pycache__" in n or "node_modules" in n]
