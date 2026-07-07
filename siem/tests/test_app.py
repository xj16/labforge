"""End-to-end tests for the SIEM web UI over a real running server.

These are the integration tests over the most-advertised subsystem: the actual
HTTP server, its JSON API, and its rendered HTML — including a live
path-traversal attempt against the running service.
"""
from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from labforge_siem.app import make_handler


@pytest.fixture()
def server(log_root):
    handler = make_handler(log_root, syslog_port="5514")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url):
    with urlopen(url, timeout=5) as resp:
        return resp.status, resp.read().decode("utf-8"), resp.headers


def test_index_renders_and_shows_alert_banner(server):
    status, body, _ = _get(server + "/")
    assert status == 200
    assert "labforge SIEM" in body
    assert "active alert" in body.lower()  # the red banner fired on the corpus
    assert "dvwa" in body


def test_index_lists_saved_searches(server):
    _, body, _ = _get(server + "/")
    assert "Failed password" in body
    assert "sqlmap" in body


def test_healthz(server):
    status, body, headers = _get(server + "/healthz")
    assert status == 200
    assert headers.get("Content-Type") == "application/json"
    data = json.loads(body)
    assert data["status"] == "ok"
    assert data["hosts"] >= 5


def test_api_hosts_returns_json(server):
    status, body, headers = _get(server + "/api/hosts")
    assert status == 200
    assert headers.get("Content-Type") == "application/json"
    hosts = json.loads(body)
    names = {h["name"] for h in hosts}
    assert {"dvwa", "victim", "juice"} <= names


def test_api_detections_returns_findings(server):
    status, body, _ = _get(server + "/api/detections")
    assert status == 200
    dets = json.loads(body)
    rule_ids = {d["rule_id"] for d in dets}
    assert "rdp-brute-force" in rule_ids
    assert "sqlmap-scan" in rule_ids
    assert dets[0]["severity"] == "critical"  # sorted worst-first


def test_api_tail_returns_lines(server):
    status, body, _ = _get(server + "/api/tail/dvwa?n=20")
    assert status == 200
    data = json.loads(body)
    assert data["host"] == "dvwa"
    assert 0 < len(data["lines"]) <= 20


def test_api_tail_unknown_host_404(server):
    with pytest.raises(HTTPError) as exc:
        _get(server + "/api/tail/ghost")
    assert exc.value.code == 404


def test_host_page_renders(server):
    status, body, _ = _get(server + "/host/dvwa")
    assert status == 200
    assert "last" in body.lower()
    assert "Failed password" in body


def test_host_page_unknown_404(server):
    with pytest.raises(HTTPError) as exc:
        _get(server + "/host/ghost")
    assert exc.value.code == 404


def test_path_traversal_is_blocked_over_http(server):
    # A live attempt to escape the log root must 404, never leak a file.
    for evil in ("/host/..%2f..%2fetc%2fpasswd", "/api/tail/..%2f..%2fetc"):
        try:
            status, body, _ = _get(server + evil)
            assert status == 404
            assert "root:" not in body  # no /etc/passwd content ever
        except HTTPError as e:
            assert e.code == 404


def test_search_finds_attacks(server):
    status, body, _ = _get(server + "/search?q=sqlmap")
    assert status == 200
    assert "matches" in body
    assert "sqlmap" in body


def test_alerts_page_lists_detections(server):
    status, body, _ = _get(server + "/alerts")
    assert status == 200
    assert "brute force" in body.lower()
    assert "T1110" in body


def test_unknown_path_404(server):
    with pytest.raises(HTTPError) as exc:
        _get(server + "/nope")
    assert exc.value.code == 404


def test_security_header_present(server):
    _, _, headers = _get(server + "/")
    assert headers.get("X-Content-Type-Options") == "nosniff"
