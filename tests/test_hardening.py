"""Phase 8 — hardening + packaging invariants.

Live enforcement happens elsewhere: the compose probes prove the topology on
every `up`, and syft/cosign run on a release host with registry access. What
CAN rot silently is the files those rely on — the hardening baseline, the
gVisor profile, the Dockerfile's privilege posture, and the packaging
entry points. These tests pin them, and run everywhere (including Windows).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
GVISOR = ROOT / "docker-compose.gvisor.yml"
DOCKERFILE = ROOT / "Dockerfile"
MAKEFILE = ROOT / "Makefile"
RELEASE_SH = ROOT / "scripts" / "release-image.sh"
PILOT_SH = ROOT / "scripts" / "pilot-install.sh"
PILOT_PS1 = ROOT / "scripts" / "pilot-install.ps1"

# Services that stay up (vs. the one-shot probes) get the FULL baseline.
LONG_RUNNING = ("al-core", "al-control", "agent-sandbox")
ONE_SHOT = ("agent-selftest", "agent-control-probe")


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def gvisor() -> dict:
    return yaml.safe_load(GVISOR.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


# -- container hardening baseline --------------------------------------------


def test_long_running_services_carry_the_full_baseline(compose):
    for name in LONG_RUNNING:
        svc = compose["services"][name]
        assert svc.get("cap_drop") == ["ALL"], name
        assert svc.get("security_opt") == ["no-new-privileges:true"], name
        assert svc.get("read_only") is True, name
        assert svc.get("tmpfs") == ["/tmp"], name
        assert svc.get("pids_limit") == 256, name
        assert svc.get("mem_limit") == "1g", name


def test_one_shot_probes_keep_the_privilege_baseline(compose):
    """Probes exit immediately, so no resource caps — but never privileges."""
    for name in ONE_SHOT:
        svc = compose["services"][name]
        assert svc.get("cap_drop") == ["ALL"], name
        assert svc.get("security_opt") == ["no-new-privileges:true"], name
        assert svc.get("read_only") is True, name
        assert svc.get("restart") == "no", name


def test_image_runs_non_root(dockerfile):
    """uid 10001, created as a system user, and USER set before ENTRYPOINT."""
    assert "--uid 10001" in dockerfile
    user_at = dockerfile.index("\nUSER al")
    entry_at = dockerfile.index("ENTRYPOINT")
    assert user_at < entry_at


def test_image_copies_no_secrets_or_runtime_data(dockerfile):
    """keys/, .env, data/ must never be baked into a layer."""
    for line in dockerfile.splitlines():
        if not line.strip().startswith("COPY"):
            continue
        assert "keys" not in line, line
        assert ".env" not in line, line
        assert not re.search(r"\bdata/", line), line


def test_image_excludes_the_governance_layer(dockerfile):
    """governance/ is neither copied nor installed in the image (it runs on
    the control host; the core never imports it). Phase 6 made it a workspace
    member, which broke the image build until the frozen sync skipped it —
    pin the fix."""
    assert "COPY governance" not in dockerfile
    assert "--no-install-package al-governance" in dockerfile


def test_image_base_is_the_pinned_slim_python(dockerfile):
    froms = [l for l in dockerfile.splitlines() if l.startswith("FROM python")]
    assert froms, "no python base stage found"
    assert all("python:3.12-slim" in l for l in froms), froms


# -- gVisor optional runtime profile ------------------------------------------


def test_gvisor_profile_targets_only_the_agent_workload(gvisor, compose):
    """Agents get the syscall sandbox; the mediator keeps the native runtime."""
    services = gvisor["services"]
    assert set(services) == {"agent-sandbox", *ONE_SHOT}
    for name in ("al-core", "al-control"):
        assert name not in services
        assert name in compose["services"]  # the override matches real services


def test_gvisor_profile_swaps_the_runtime_and_nothing_else(gvisor):
    """The override must not touch networks, volumes, or the baseline."""
    assert set(gvisor) == {"services"}
    for name, svc in gvisor["services"].items():
        assert svc == {"runtime": "runsc"}, name


# -- packaging: SBOM + signed images + pilot install --------------------------


def test_makefile_exposes_the_packaging_targets():
    text = MAKEFILE.read_text(encoding="utf-8")
    for target in ("sbom:", "sign:", "pilot:"):
        assert re.search(rf"^{target}", text, re.MULTILINE), target
    assert "scripts/release-image.sh" in text
    assert "scripts/pilot-install.sh" in text


def test_release_script_builds_sbom_and_signs():
    text = RELEASE_SH.read_text(encoding="utf-8")
    assert "set -euo pipefail" in text
    assert "syft" in text and "spdx-json" in text  # SBOM generated
    assert "cosign sign" in text  # image signed
    assert "cosign attest" in text and "--predicate" in text  # SBOM attached
    assert "docker push" in text  # cosign signs the registry digest


def test_pilot_install_exists_for_both_platforms():
    for script in (PILOT_SH, PILOT_PS1):
        text = script.read_text(encoding="utf-8")
        assert "uv sync" in text, script.name
        assert "al init" in text, script.name
        assert "pytest" in text, script.name
        assert "docker compose up" in text, script.name
        assert "healthz" in text, script.name


def test_pilot_install_gates_on_the_topology_proofs():
    """The installer must FAIL if either one-shot probe fails — a pilot that
    starts agents on an unproven topology defeats the product."""
    for script in (PILOT_SH, PILOT_PS1):
        text = script.read_text(encoding="utf-8")
        assert "agent-selftest" in text, script.name
        assert "agent-control-probe" in text, script.name
        assert "ExitCode" in text, script.name


# -- supply chain: pinned inputs, one image name, the signed image -------------

IMAGE_REPO = "ghcr.io/neural-nomad1709/agentlighthouse"


def _project_version() -> str:
    import tomllib

    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"]["version"]


def test_every_image_the_build_pulls_is_pinned_by_digest(dockerfile):
    """A tag can be moved after review; a digest cannot."""
    refs = re.findall(r"^FROM (?:--platform=\S+ )?(\S+)", dockerfile, re.MULTILINE)
    refs += re.findall(r"--from=(\S+)", dockerfile)
    external = [r for r in refs if "/" in r or ":" in r]  # not a stage name
    assert external, "no external image references found"
    for ref in external:
        assert "@sha256:" in ref, ref
        assert ":latest" not in ref, ref


def test_compose_pulls_the_released_image_and_never_builds(compose):
    """Compose runs the cosign-signed release, not a local rebuild."""
    ours = [n for n, s in compose["services"].items() if n != "agent-sandbox"]
    for name in ours:
        svc = compose["services"][name]
        assert "build" not in svc, name
        assert svc["image"] == f"{IMAGE_REPO}:{_project_version()}", name


def test_local_build_override_builds_every_service_from_one_tag(compose):
    override = yaml.safe_load(
        (ROOT / "docker-compose.build.yml").read_text(encoding="utf-8"))
    ours = {n for n in compose["services"] if n != "agent-sandbox"}
    assert set(override["services"]) == ours
    assert "build" in override["services"]["al-core"]
    assert len({s["image"] for s in override["services"].values()}) == 1


def test_there_is_one_image_name():
    """Makefile, compose and the publish workflow agree; Docker Hub is gone."""
    makefile = MAKEFILE.read_text(encoding="utf-8")
    assert f"IMAGE ?= {IMAGE_REPO}:{_project_version()}" in makefile
    workflow = (ROOT / ".github" / "workflows" / "publish-image.yml").read_text(
        encoding="utf-8")
    assert "ghcr.io/${GITHUB_REPOSITORY,,}" in workflow
    for path in (MAKEFILE, COMPOSE, RELEASE_SH, ROOT / "README.md",
                 ROOT / "scripts" / "bump-version.sh"):
        text = path.read_text(encoding="utf-8")
        assert "amitkala/agentlighthouse" not in text, path.name
        assert "agentlighthouse/al-core" not in text, path.name


def test_version_bump_also_moves_the_compose_image_tag():
    text = (ROOT / "scripts" / "bump-version.sh").read_text(encoding="utf-8")
    assert "x-image: &image" in text and "docker-compose.yml" in text


def test_published_image_is_multi_arch():
    workflow = (ROOT / ".github" / "workflows" / "publish-image.yml").read_text(
        encoding="utf-8")
    assert "platforms: linux/amd64,linux/arm64" in workflow
    assert "docker/setup-qemu-action" in workflow


def test_ci_runs_the_suite_on_windows_too():
    ci = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    assert set(ci["jobs"]["test"]["strategy"]["matrix"]["os"]) >= {
        "ubuntu-latest", "windows-latest"}


def test_packages_report_the_released_version():
    import al_core
    import al_governance
    import al_verify

    version = _project_version()
    assert al_core.__version__ == version
    assert al_verify.__version__ == version
    assert al_governance.__version__ == version
