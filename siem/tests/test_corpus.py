"""Tests for the canned corpus that seeds the demo and the tests.

Guards the invariant that the corpus keeps telling a complete attack story, so
the static portfolio demo never silently loses a detection.
"""
from __future__ import annotations

import json

from labforge_siem.corpus import build_corpus, export_json, write_corpus
from labforge_siem.store import LogStore


def test_corpus_is_deterministic():
    assert build_corpus() == build_corpus()


def test_corpus_covers_expected_hosts():
    corpus = build_corpus()
    assert set(corpus) == {"attacker", "siem", "juice", "dvwa", "victim"}
    for host, lines in corpus.items():
        assert lines, f"{host} has no lines"


def test_written_corpus_triggers_every_rule(tmp_path):
    root = tmp_path / "logs"
    root.mkdir()
    write_corpus(str(root))
    dets = LogStore(str(root)).detections()
    fired = {d.rule_id for d in dets}
    assert {
        "ssh-brute-force", "rdp-brute-force", "logon-after-brute",
        "port-sweep", "sqlmap-scan", "nikto-scan",
    } <= fired


def test_export_json_is_serializable_and_complete():
    bundle = export_json()
    # Round-trips through JSON (this is what the static demo embeds).
    text = json.dumps(bundle)
    again = json.loads(text)
    assert again["hosts"]
    assert set(again["logs"]) == {"attacker", "siem", "juice", "dvwa", "victim"}
    # Host stats line up with the actual log contents.
    for h in again["hosts"]:
        assert h["lines"] == len(again["logs"][h["name"]])
