"""al-core — AgentLighthouse data + control plane (MIT)."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _dist_version

# The version lives in pyproject.toml (scripts/bump-version.sh); read it back
# from the installed distribution so the two cannot drift.
try:
    __version__ = _dist_version("agentlighthouse-core")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"
