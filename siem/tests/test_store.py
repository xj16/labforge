"""Tests for the log store — reads, tail, search, and path-traversal safety."""
from __future__ import annotations

import os

import pytest

from labforge_siem.store import LogStore


def test_list_hosts_finds_seeded_hosts(store):
    names = {h["name"] for h in store.list_hosts()}
    assert {"attacker", "dvwa", "juice", "siem", "victim"} <= names
    for h in store.list_hosts():
        assert h["lines"] > 0
        assert h["bytes"] > 0


def test_list_hosts_empty(empty_store):
    assert empty_store.list_hosts() == []


def test_list_hosts_missing_root(tmp_path):
    store = LogStore(str(tmp_path / "does-not-exist"))
    assert store.list_hosts() == []


def test_safe_host_path_accepts_known_host(store):
    path = store.safe_host_path("dvwa")
    assert path is not None
    assert os.path.isfile(path)


def test_safe_host_path_rejects_unknown_host(store):
    assert store.safe_host_path("nope") is None


@pytest.mark.parametrize("evil", [
    "../../etc/passwd",
    "..",
    "../victim",
    "dvwa/../victim",
    "/etc/passwd",
    "dvwa/messages.log",
    "..\\..\\windows\\system32",
    "",
    "has space",
    "semi;colon",
])
def test_safe_host_path_blocks_traversal_and_junk(store, evil):
    # None of these may ever resolve to a readable path outside the allow-list.
    assert store.safe_host_path(evil) is None


def test_safe_host_path_cannot_escape_root(tmp_path):
    # A file that exists just outside LOG_ROOT must never be reachable.
    root = tmp_path / "logs"
    (root / "dvwa").mkdir(parents=True)
    (root / "dvwa" / "messages.log").write_text("x\n")
    secret = tmp_path / "secret.log"
    secret.write_text("TOPSECRET\n")
    store = LogStore(str(root))
    for attempt in ("../secret", "../secret.log", "%2e%2e/secret"):
        assert store.safe_host_path(attempt) is None


def test_tail_returns_last_n_lines(tmp_path):
    root = tmp_path / "logs"
    (root / "h").mkdir(parents=True)
    p = root / "h" / "messages.log"
    p.write_text("\n".join(f"line{i}" for i in range(100)) + "\n")
    store = LogStore(str(root))
    tail = store.tail(str(p), 10)
    assert tail == [f"line{i}" for i in range(90, 100)]


def test_tail_zero_or_negative(tmp_path):
    root = tmp_path / "logs"
    (root / "h").mkdir(parents=True)
    p = root / "h" / "messages.log"
    p.write_text("a\nb\n")
    store = LogStore(str(root))
    assert store.tail(str(p), 0) == []
    assert store.tail(str(p), -5) == []


def test_tail_host_unknown_returns_none(store):
    assert store.tail_host("../../etc") is None
    assert store.tail_host("ghost") is None


def test_tail_host_reads_content(store):
    lines = store.tail_host("dvwa", 5)
    assert lines is not None
    assert len(lines) == 5


def test_search_all_is_case_insensitive(store):
    hits = store.search_all("FAILED PASSWORD")
    assert len(hits) >= 5
    assert all("failed password" in line.lower() for _, line in hits)


def test_search_all_empty_term(store):
    assert store.search_all("") == []


def test_search_all_respects_limit(store):
    hits = store.search_all("labforge", limit=2)
    assert len(hits) == 2


def test_all_events_parses_everything(store):
    events = list(store.all_events())
    assert len(events) > 50
    assert any(e.event_id == 4625 for e in events)
