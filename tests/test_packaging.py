"""The al-core wheel is usable with no clone and no Node.

A pip/uv install has no repository root, so the shipped configs, the
default-deny tool policy and the built dashboard travel inside the wheel
(``al_core/_bundled``) and ``al init`` lays the editable ones down in the
working directory.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
import zipfile
from pathlib import Path

import pytest
import yaml
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


# PyPI project name -> (workspace directory, GitHub environment of its trusted
# publisher). PyPI refuses `al-core` and friends as look-alikes of existing
# projects, and allows one pending publisher per (repo, workflow, environment),
# so each project publishes from its own environment.
PYPI_PROJECTS = {
    "agentlighthouse-core": ("core", "pypi"),
    "agentlighthouse-verify": ("verify", "pypi-verify"),
    "agentlighthouse-governance": ("governance", "pypi-governance"),
}  # the environment names are the ones registered on pypi.org


def test_each_package_carries_its_pypi_project_name():
    for project, (directory, _) in PYPI_PROJECTS.items():
        meta = tomllib.loads((ROOT / directory / "pyproject.toml").read_text(encoding="utf-8"))
        assert meta["project"]["name"] == project


def test_each_package_is_published_from_its_own_environment():
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "publish-pypi.yml").read_text(encoding="utf-8"))
    publish = workflow["jobs"]["publish"]
    assert publish["environment"] == "${{ matrix.environment }}"
    assert "${{ matrix.dist }}" in publish["steps"][-1]["run"]
    published = {(m["dist"], m["environment"]) for m in publish["strategy"]["matrix"]["include"]}
    assert published == {
        (project.replace("-", "_"), environment)
        for project, (_, environment) in PYPI_PROJECTS.items()}


def _package_dir(project: str) -> Path:
    return ROOT / PYPI_PROJECTS[project][0]


@pytest.mark.parametrize("project", PYPI_PROJECTS)
def test_each_package_ships_the_repository_license(project):
    meta = tomllib.loads((_package_dir(project) / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["license-files"] == ["LICENSE"]
    # A package builds from its own directory, so it carries its own copy.
    assert (_package_dir(project) / "LICENSE").read_bytes() == (ROOT / "LICENSE.txt").read_bytes()


@pytest.mark.parametrize("project", PYPI_PROJECTS)
def test_each_package_has_a_pypi_page(project):
    meta = tomllib.loads((_package_dir(project) / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["readme"] == "README.md"
    page = (_package_dir(project) / "README.md").read_text(encoding="utf-8")
    assert f"pip install {project}" in page
    # PyPI renders the page away from the repository: a relative link or
    # image is dead there.
    targets = re.findall(r"\]\(([^)\s]+)", page) + re.findall(r'(?:src|href)="([^"]+)"', page)
    assert targets
    assert not [t for t in targets if not t.startswith(("https://", "#"))]


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build the wheel")
@pytest.mark.parametrize("project", PYPI_PROJECTS)
def test_each_built_wheel_carries_the_license_and_the_page(project, tmp_path):
    out = tmp_path / "dist"
    built = subprocess.run(
        ["uv", "build", "--wheel", "--package", project, "-o", str(out)],
        cwd=ROOT, capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    (wheel,) = out.glob("*.whl")
    with zipfile.ZipFile(wheel) as z:
        (license_file,) = [n for n in z.namelist() if n.endswith(".dist-info/licenses/LICENSE")]
        assert z.read(license_file) == (ROOT / "LICENSE.txt").read_bytes()
        (metadata,) = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
        described = z.read(metadata).decode("utf-8")
    assert "Description-Content-Type: text/markdown" in described
    assert f"pip install {project}" in described


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv to build the wheel")
def test_the_wheel_carries_configs_policy_and_dashboard(tmp_path):
    out = tmp_path / "dist"
    built = subprocess.run(
        ["uv", "build", "--wheel", "--package", "agentlighthouse-core", "-o", str(out)],
        cwd=ROOT, capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    (wheel,) = out.glob("agentlighthouse_core-*.whl")
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
