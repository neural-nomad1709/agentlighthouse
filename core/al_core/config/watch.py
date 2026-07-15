"""Automatic config hot-reload via watchfiles.

Runs a daemon thread that watches the config file and triggers a reload on
change. The reload itself is fail-closed and last-good-preserving (see
``ConfigManager.reload``): a bad edit is rejected and the running config is kept,
so the watcher can never put the mediator into a broken state.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable

from watchfiles import watch

log = logging.getLogger("al.config.watch")


class ConfigWatcher:
    def __init__(self, path: str | Path, on_change: Callable[[], None]) -> None:
        self._path = Path(path)
        self._on_change = on_change
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "ConfigWatcher":
        if self._thread is not None:
            return self
        self._thread = threading.Thread(
            target=self._run, name="al-config-watch", daemon=True
        )
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            for _changes in watch(str(self._path), stop_event=self._stop):
                try:
                    self._on_change()
                except Exception:  # noqa: BLE001 — a bad reload must not kill the watcher
                    log.exception("config hot-reload failed; keeping last-good")
        except Exception:  # noqa: BLE001 — watcher backend error
            log.exception("config watcher stopped unexpectedly")

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
