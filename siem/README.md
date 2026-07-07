# labforge_siem — the SIEM viewer + detection engine

The real, tested core behind labforge's blue-team half. A tiny, **zero-runtime-
dependency** (Python stdlib only) package that:

- reads the per-host log files the rsyslog central collector writes,
- runs a small **detection ruleset** over them (brute force, port sweeps,
  sqlmap/nikto scans), and
- serves a read-only web dashboard + JSON API.

The exact same code powers three things, so **what CI tests is what ships**:

| Consumer | Entry point |
|----------|-------------|
| the live SIEM box | `run_logviewer.py` (a systemd unit runs it) |
| the flagship tests | `tests/` (pytest + coverage, run in CI) |
| the static portfolio demo | corpus baked in via `labforge_siem.corpus.export_json()` |

## Layout

```
siem/
├── labforge_siem/
│   ├── parser.py       normalize raw syslog lines into structured Events
│   ├── detections.py   the detection rules (pure, deterministic, testable)
│   ├── store.py        read per-host logs; path-traversal-safe file access
│   ├── app.py          the http.server web UI + JSON API
│   └── corpus.py       deterministic canned attack corpus (demo + tests)
├── run_logviewer.py    env-configured entrypoint (deployed to the SIEM box)
├── tests/              flagship test suite (parser/store/detections/HTTP)
└── tools/              coverage badge generator + freshness check
```

## Run the tests

```bash
cd siem
pip install -r requirements-dev.txt
coverage run -m pytest
coverage report            # 95%+ line+branch coverage
python tools/make_coverage_badge.py   # regenerate coverage.svg
```

## Run the viewer locally (no VMs)

```bash
cd siem
# seed a realistic corpus, then serve it:
LABFORGE_LOG_ROOT=/tmp/labforge-logs python -m labforge_siem.corpus --log-root /tmp/labforge-logs
LABFORGE_LOG_ROOT=/tmp/labforge-logs LABFORGE_WEB_PORT=8000 python run_logviewer.py
# open http://localhost:8000
```

## Configuration (environment)

| Variable | Default | Meaning |
|----------|---------|---------|
| `LABFORGE_LOG_ROOT` | `/opt/labforge-siem/logs` | directory the collector writes into |
| `LABFORGE_WEB_PORT` | `8000` | port the viewer binds |
| `LABFORGE_SYSLOG_PORT` | `5514` | collector port shown in the header |

## Detection rules

See [`docs/siem.md`](../docs/siem.md#built-in-detections) for the full table of
rules, their severities, and the MITRE ATT&CK techniques they map to.
