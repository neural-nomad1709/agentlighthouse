"""AgentLighthouse governance layer — org tenancy, RBAC, budgets, attestation.

MIT-licensed, like the rest of the workspace. The core never imports this
package; this package builds on the core.
"""

from importlib.metadata import PackageNotFoundError, version as _dist_version

# The version lives in pyproject.toml (scripts/bump-version.sh); read it back
# from the installed distribution so the two cannot drift.
try:
    __version__ = _dist_version("al-governance")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"
