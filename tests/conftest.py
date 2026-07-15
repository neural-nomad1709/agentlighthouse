from __future__ import annotations

import pytest

from al_core.keys import generate_signing_key
from al_core.receipt import ReceiptSigner

from dev_errors import DevErrorRecorder, make_run_id  # tests/ is on sys.path

# -- development_errors recorder ------------------------------------------------
# Every failing/erroring test phase is appended to the `development_errors`
# table in data/development.sqlite (a separate db from the evidence mirror).
# Recording is best-effort and never affects test outcomes.

_recorder: DevErrorRecorder | None = None


def pytest_configure(config):  # noqa: ARG001
    global _recorder
    _recorder = DevErrorRecorder(make_run_id())


def pytest_runtest_logreport(report):
    if _recorder is None or report.passed or report.skipped:
        return
    # report.failed is True for assertion failures (call phase) and for
    # setup/teardown errors — record both, tagged by phase.
    outcome = "error" if report.when in ("setup", "teardown") else "failed"
    # TestReport has no excinfo; the crash line lives on longrepr.reprcrash
    # (present for real failures; longrepr can also be a plain string).
    exc_type = message = None
    reprcrash = getattr(getattr(report, "longrepr", None), "reprcrash", None)
    if reprcrash is not None and getattr(reprcrash, "message", None):
        crash = reprcrash.message.splitlines()[0]
        # "AssertionError: assert 1 == 2" -> type + message; a bare exception
        # ("StopIteration") has no colon and IS the type.
        exc_type = crash.split(":", 1)[0].strip() or None
        message = crash
    _recorder.record(
        nodeid=report.nodeid,
        test_file=report.nodeid.split("::", 1)[0],
        phase=report.when or "call",
        outcome=outcome,
        exc_type=exc_type,
        message=message,
        longrepr=str(report.longrepr) if report.longrepr else None,
        duration=getattr(report, "duration", None),
    )


def pytest_terminal_summary(terminalreporter, exitstatus, config):  # noqa: ARG001
    if _recorder is not None and _recorder.recorded:
        terminalreporter.write_line(
            f"[development_errors] recorded {_recorder.recorded} failure row(s) "
            f"-> data/development.sqlite (run {_recorder.run_id})"
        )


def pytest_unconfigure(config):  # noqa: ARG001
    if _recorder is not None:
        _recorder.close()


@pytest.fixture(autouse=True)
def _admin_token(monkeypatch):
    # Deterministic secret so Settings construction never depends on a .env file.
    monkeypatch.setenv("AL_ADMIN_API_TOKEN", "test-admin-token")


@pytest.fixture
def signing_key(tmp_path):
    return generate_signing_key(tmp_path / "mediator_ed25519")


@pytest.fixture
def public_key(signing_key):
    return signing_key.public_key()


@pytest.fixture
def signer(signing_key):
    return ReceiptSigner(signing_key)
