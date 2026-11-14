"""A JSON file that one process writes and another re-reads when it changes.

The credential stores (agent identities, virtual keys, console users) are JSON
files. The gateway holds one in memory for its whole life, while ``al vkey
revoke`` and friends run as separate processes and edit the same file. A store
that reads the file once at boot never sees those edits, so a revoked
credential keeps working until the next restart.

``JsonFile`` gives a store the two things it needs to stay current:

* ``changed()`` — cheap (one ``stat``), so a store can ask before every lookup;
* ``write()`` — atomic (temp file + rename), so a reader never sees half a file.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

_NEVER_READ = object()
_REPLACE_ATTEMPTS = 5


class JsonFile:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._seen: Any = _NEVER_READ

    def _stamp(self) -> tuple[int, int] | None:
        """Identity of the file's current content (None when it is absent)."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def changed(self) -> bool:
        """True when the file differs from what this object last read or wrote
        (always True before the first read)."""
        return self._stamp() != self._seen

    def read(self) -> Any:
        """The parsed content, or None when the file does not exist.

        A file that cannot be read or parsed raises, and still counts as
        changed, so the next call tries again."""
        stamp = self._stamp()  # taken first: a write during the read is seen next time
        data = None if stamp is None else json.loads(self.path.read_text(encoding="utf-8"))
        self._seen = stamp
        return data

    def write(self, data: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        for attempt in range(_REPLACE_ATTEMPTS):
            try:
                os.replace(tmp, self.path)
                break
            except PermissionError:
                # Windows refuses the rename while another process has the
                # file open to read it. That lasts microseconds.
                if attempt == _REPLACE_ATTEMPTS - 1:
                    tmp.unlink(missing_ok=True)
                    raise
                time.sleep(0.05)
        self._seen = self._stamp()


__all__ = ["JsonFile"]
