"""Build hook: put the repo-level runtime data inside the al-core wheel.

configs/, policies/ and the built dashboard live at the repository root, which
a pip/uv install does not have. A release wheel carries them under
``al_core/_bundled`` (read back by ``al_core.resources``).

An editable install is skipped: it runs from a checkout, where the same files
are found at the repository root.

The dashboard needs Node to build, so a local ``uv build`` may go without it.
The release job sets ``AL_REQUIRE_DASHBOARD=1`` so a published wheel cannot.
"""

from __future__ import annotations

import os
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# path under the repository root -> directory under al_core/_bundled
BUNDLE = {
    "configs": "configs",
    "policies": "policies",
    "frontend/dist": "dashboard",
}


class BundleRuntimeData(BuildHookInterface):
    def initialize(self, version: str, build_data: dict) -> None:
        if version == "editable":
            return
        repo = Path(self.root).parent
        for source, name in BUNDLE.items():
            path = repo / source
            if path.is_dir():
                build_data["force_include"][str(path)] = f"al_core/_bundled/{name}"
            elif name != "dashboard" or os.environ.get("AL_REQUIRE_DASHBOARD"):
                # Also what a wheel built from an sdist hits: fail the build
                # rather than ship a wheel that boots without its policy.
                raise RuntimeError(
                    f"al-core wheel: {source}/ not found next to core/ "
                    "(build the wheel from the repository, after the dashboard build)")
