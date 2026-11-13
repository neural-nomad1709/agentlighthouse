"""Where the shipped configs, tool policy and dashboard live.

Two layouts, one lookup. A wheel carries them inside the package
(``al_core/_bundled``, put there by ``core/hatch_build.py``). A checkout, an
editable install and the container image keep them at the repository root.
"""

from __future__ import annotations

from pathlib import Path

_PACKAGED = Path(__file__).resolve().parent / "_bundled"
_REPO_ROOT = Path(__file__).resolve().parents[2]

# bundle name -> path under the repository root
_IN_REPO = {
    "configs": "configs",
    "policies": "policies",
    "dashboard": "frontend/dist",
}


def bundled(name: str) -> Path:
    """Directory holding ``configs``, ``policies`` or the built ``dashboard``.

    The returned path may not exist (a checkout with no dashboard build);
    callers already handle that."""
    in_repo = _IN_REPO[name]
    packaged = _PACKAGED / name
    return packaged if packaged.is_dir() else _REPO_ROOT / in_repo


__all__ = ["bundled"]
