"""Tests for the detection engine — the flagship blue-team subsystem."""
from __future__ import annotations

from labforge_siem.detections import (
    RDP_BRUTE_THRESHOLD,
    SSH_BRUTE_THRESHOLD,
    DEFAULT_RULES,
    run_detections,
)
from labforge_siem.parser import parse_lines


def _events(lines, host="h"):
    return list(parse_lines(lines, host=host))


def _line(host, tag, msg, i=0):
    return f"2026-07-06T14:00:{i % 60:02d}Z {host} {tag}: {msg}"


# --- full-corpus behaviour --------------------------------------------------

def test_corpus_fires_all_expected_rules(store):
    dets = store.detections()
    fired = {d.rule_id for d in dets}
    expected = {
        "ssh-brute-force", "rdp-brute-force", "logon-after-brute",
        "port-sweep", "sqlmap-scan", "nikto-scan",
    }
    assert expected <= fired, f"missing: {expected - fired}"


def test_findings_sorted_worst_first(store):
    dets = store.detections()
    ranks = [d.severity_rank for d in dets]
    assert ranks == sorted(ranks)
    assert dets[0].severity == "critical"  # logon-after-brute leads


def test_every_finding_has_evidence_and_attribution(store):
    for d in store.detections():
        assert d.evidence, f"{d.rule_id} has no evidence"
        assert d.technique.startswith("T")
        assert d.count >= 1


# --- SSH brute force --------------------------------------------------------

def test_ssh_brute_fires_at_threshold():
    lines = [_line("dvwa", "sshd", f"Failed password for root from 10.20.0.10 port {i}", i)
             for i in range(SSH_BRUTE_THRESHOLD)]
    dets = run_detections(_events(lines, host="dvwa"))
    ssh = [d for d in dets if d.rule_id == "ssh-brute-force"]
    assert len(ssh) == 1
    assert ssh[0].source == "10.20.0.10"
    assert ssh[0].count == SSH_BRUTE_THRESHOLD


def test_ssh_brute_silent_below_threshold():
    lines = [_line("dvwa", "sshd", f"Failed password for root from 10.20.0.10 port {i}", i)
             for i in range(SSH_BRUTE_THRESHOLD - 1)]
    dets = run_detections(_events(lines, host="dvwa"))
    assert not [d for d in dets if d.rule_id == "ssh-brute-force"]


# --- RDP / Windows brute force ---------------------------------------------

def test_rdp_brute_fires_on_4625_burst():
    lines = [_line("victim", "labforge",
                   f"EventID=4625 failed logon Source Network Address: 10.20.0.10 attempt {i}", i)
             for i in range(RDP_BRUTE_THRESHOLD)]
    dets = run_detections(_events(lines, host="victim"))
    rdp = [d for d in dets if d.rule_id == "rdp-brute-force"]
    assert len(rdp) == 1
    assert rdp[0].severity == "high"
    assert rdp[0].source == "10.20.0.10"


def test_rdp_brute_silent_below_threshold():
    lines = [_line("victim", "labforge",
                   f"EventID=4625 failed logon from 10.20.0.10 attempt {i}", i)
             for i in range(RDP_BRUTE_THRESHOLD - 1)]
    dets = run_detections(_events(lines, host="victim"))
    assert not [d for d in dets if d.rule_id == "rdp-brute-force"]


# --- logon after brute (credential-stuffing success) ------------------------

def test_logon_after_brute_is_critical():
    lines = [_line("victim", "labforge",
                   f"EventID=4625 failed logon from 10.20.0.10 attempt {i}", i)
             for i in range(RDP_BRUTE_THRESHOLD)]
    lines.append(_line("victim", "labforge",
                       "EventID=4624 successful logon from 10.20.0.10", 59))
    dets = run_detections(_events(lines, host="victim"))
    hit = [d for d in dets if d.rule_id == "logon-after-brute"]
    assert len(hit) == 1
    assert hit[0].severity == "critical"


def test_no_logon_after_brute_without_success():
    lines = [_line("victim", "labforge",
                   f"EventID=4625 failed logon from 10.20.0.10 attempt {i}", i)
             for i in range(RDP_BRUTE_THRESHOLD)]
    dets = run_detections(_events(lines, host="victim"))
    assert not [d for d in dets if d.rule_id == "logon-after-brute"]


# --- nmap port sweep --------------------------------------------------------

def test_port_sweep_fires_on_many_ports():
    lines = [_line("dvwa", "kernel",
                   f"[nft] SYN-scan SRC=10.20.0.10 DST=10.20.0.32 DPT={p} SYN", p)
             for p in range(20)]
    dets = run_detections(_events(lines, host="dvwa"))
    sweep = [d for d in dets if d.rule_id == "port-sweep"]
    assert len(sweep) == 1
    assert sweep[0].source == "10.20.0.10"


def test_port_sweep_silent_on_few_ports():
    lines = [_line("dvwa", "kernel",
                   f"[nft] SYN-scan SRC=10.20.0.10 DST=10.20.0.32 DPT={p} SYN", p)
             for p in range(3)]
    dets = run_detections(_events(lines, host="dvwa"))
    assert not [d for d in dets if d.rule_id == "port-sweep"]


# --- scanner fingerprints ---------------------------------------------------

def test_sqlmap_fingerprint():
    lines = [_line("dvwa", "apache2",
                   '10.20.0.10 - - "GET /?id=1 HTTP/1.1" 200 1 "-" "sqlmap/1.8"')]
    dets = run_detections(_events(lines, host="dvwa"))
    assert any(d.rule_id == "sqlmap-scan" for d in dets)


def test_nikto_fingerprint():
    lines = [_line("juice", "juice-shop",
                   '10.20.0.10 - - "GET /admin HTTP/1.1" 404 1 "-" "Mozilla/5.00 (Nikto/2.5.0)"')]
    dets = run_detections(_events(lines, host="juice"))
    assert any(d.rule_id == "nikto-scan" for d in dets)


# --- negative / robustness --------------------------------------------------

def test_benign_logs_produce_no_detections():
    lines = [_line("dvwa", "systemd", "Started service.", i) for i in range(50)]
    lines += [_line("dvwa", "apache2",
                    '10.20.0.99 - - "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"', i)
              for i in range(50)]
    dets = run_detections(_events(lines, host="dvwa"))
    assert dets == []


def test_run_detections_accepts_generator():
    gen = (e for e in _events([_line("h", "sshd",
           f"Failed password for x from 1.2.3.4 port {i}", i) for i in range(6)]))
    dets = run_detections(gen)
    assert any(d.rule_id == "ssh-brute-force" for d in dets)


def test_custom_rule_subset():
    lines = [_line("dvwa", "sshd", f"Failed password from 1.2.3.4 port {i}", i)
             for i in range(10)]
    only_ssh = [r for r in DEFAULT_RULES if r.id == "ssh-brute-force"]
    dets = run_detections(_events(lines, host="dvwa"), rules=only_ssh)
    assert {d.rule_id for d in dets} == {"ssh-brute-force"}
