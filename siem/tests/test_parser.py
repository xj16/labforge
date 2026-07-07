"""Tests for the syslog line parser."""
from __future__ import annotations

from datetime import timezone

from labforge_siem.parser import Event, parse_line, parse_lines


def test_parses_structured_line():
    line = ("2026-07-06T14:03:11.482Z dvwa apache2: 10.20.0.10 - - "
            '"GET /?id=1 HTTP/1.1" 200 4512 "-" "sqlmap/1.8"')
    ev = parse_line(line)
    assert ev is not None
    assert ev.host == "dvwa"
    assert ev.tag == "apache2"
    assert ev.src_ip == "10.20.0.10"
    assert ev.timestamp is not None
    assert ev.timestamp.tzinfo == timezone.utc
    assert "sqlmap" in ev.text


def test_host_override_wins():
    line = "2026-07-06T14:03:11Z somehost sshd: hi from 10.20.0.9"
    ev = parse_line(line, host="dvwa")
    assert ev.host == "dvwa"  # collector files per host, so override is truth


def test_extracts_windows_event_id():
    line = ("2026-07-06T14:05:02Z victim labforge: EventID=4625 An account "
            "failed to log on. Source Network Address: 10.20.0.10")
    ev = parse_line(line)
    assert ev.event_id == 4625
    assert ev.src_ip == "10.20.0.10"


def test_blank_line_is_skipped():
    assert parse_line("") is None
    assert parse_line("   \n") is None


def test_unstructured_line_is_kept_not_dropped():
    ev = parse_line("this is not a syslog line at all", host="x")
    assert ev is not None
    assert ev.host == "x"
    assert ev.timestamp is None
    assert "not a syslog line" in ev.message


def test_parse_lines_skips_blanks():
    lines = ["", "2026-07-06T14:00:00Z a b: one", "   ", "2026-07-06T14:00:01Z a b: two"]
    events = list(parse_lines(lines))
    assert len(events) == 2
    assert all(isinstance(e, Event) for e in events)


def test_bad_timestamp_is_tolerated():
    ev = parse_line("not-a-date host tag: body", host="host")
    assert ev.timestamp is None
