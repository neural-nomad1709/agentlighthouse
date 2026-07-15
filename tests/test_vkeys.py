"""Virtual keys + budgets (proxy_test — Phase 1 acceptance).

Per-user key auth (hashed at rest, shown once), revocation, and daily budget
enforcement: over-budget → deny; post-hoc usage always recorded; window
rollover resets counters.
"""

from __future__ import annotations

import json

import pytest

from al_core.audit.db import SqliteMirror
from al_core.gateway.vkeys import TOKEN_PREFIX, BudgetLedger, VirtualKeyStore


@pytest.fixture
def store(tmp_path):
    return VirtualKeyStore(tmp_path / "virtual_keys.json")


@pytest.fixture
def db():
    with SqliteMirror(":memory:") as mirror:
        yield mirror


class FakeDay:
    def __init__(self) -> None:
        self.day = "2026-07-10"

    def __call__(self) -> str:
        return self.day


# -- key store -----------------------------------------------------------------

def test_issue_and_authenticate(store):
    vk, token = store.issue("alice", max_requests_per_day=10)
    assert token.startswith(TOKEN_PREFIX)
    got = store.authenticate(token)
    assert got is not None and got.key_id == vk.key_id and got.actor == "user:alice"


def test_wrong_or_missing_token_denied(store):
    store.issue("alice")
    assert store.authenticate("alk_not-a-real-token") is None
    assert store.authenticate(None) is None
    assert store.authenticate("") is None


def test_plaintext_token_never_persisted(store, tmp_path):
    _, token = store.issue("alice")
    blob = (tmp_path / "virtual_keys.json").read_text(encoding="utf-8")
    assert token not in blob
    assert "sha256:" in blob


def test_revoked_key_denied(store):
    vk, token = store.issue("alice")
    assert store.revoke(vk.key_id)
    assert store.authenticate(token) is None
    assert not store.revoke("vk_nonexistent")


def test_store_persists_across_instances(tmp_path):
    s1 = VirtualKeyStore(tmp_path / "vk.json")
    _, token = s1.issue("bob", max_tokens_per_day=1000)
    s2 = VirtualKeyStore(tmp_path / "vk.json")
    got = s2.authenticate(token)
    assert got is not None and got.max_tokens_per_day == 1000


def test_store_file_is_valid_json_list(tmp_path):
    s = VirtualKeyStore(tmp_path / "vk.json")
    s.issue("a")
    s.issue("b")
    data = json.loads((tmp_path / "vk.json").read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == 2


# -- budgets ---------------------------------------------------------------------

def test_request_budget_enforced(store, db):
    vk, _ = store.issue("alice", max_requests_per_day=2)
    budget = BudgetLedger(db, today=FakeDay())
    assert budget.try_consume(vk, requests=1)
    assert budget.try_consume(vk, requests=1)
    assert not budget.try_consume(vk, requests=1)  # third request over budget


def test_token_budget_enforced_and_usage_recorded(store, db):
    vk, _ = store.issue("alice", max_tokens_per_day=100)
    budget = BudgetLedger(db, today=FakeDay())
    assert budget.try_consume(vk, requests=1)  # request itself unlimited
    budget.add_usage(vk, tokens=150)  # post-hoc usage always recorded
    assert budget.usage(vk) == (1, 150)
    assert not budget.try_consume(vk, requests=1, tokens=1)  # now over token budget


def test_unlimited_key_never_denied(store, db):
    vk, _ = store.issue("root")  # both limits None
    budget = BudgetLedger(db, today=FakeDay())
    for _ in range(50):
        assert budget.try_consume(vk, requests=1, tokens=10_000)


def test_zero_budget_denies_first_request(store, db):
    vk, _ = store.issue("blocked", max_requests_per_day=0)
    budget = BudgetLedger(db, today=FakeDay())
    assert not budget.try_consume(vk, requests=1)


def test_window_rollover_resets_budget(store, db):
    vk, _ = store.issue("alice", max_requests_per_day=1)
    day = FakeDay()
    budget = BudgetLedger(db, today=day)
    assert budget.try_consume(vk, requests=1)
    assert not budget.try_consume(vk, requests=1)
    day.day = "2026-07-11"  # midnight rollover
    assert budget.try_consume(vk, requests=1)
    assert budget.usage(vk) == (1, 0)  # fresh window, yesterday not counted


def test_budgets_are_per_key(store, db):
    a, _ = store.issue("alice", max_requests_per_day=1)
    b, _ = store.issue("bob", max_requests_per_day=1)
    budget = BudgetLedger(db, today=FakeDay())
    assert budget.try_consume(a, requests=1)
    assert budget.try_consume(b, requests=1)  # alice's spend does not hit bob
    assert not budget.try_consume(a, requests=1)
