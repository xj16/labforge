"""labforge SIEM — a tiny, dependency-free, Splunk-style detection lab.

This package is the real, testable core behind the log viewer that the Ansible
``splunk`` role deploys onto the ``siem`` box. It uses ONLY the Python standard
library so it runs on any lab machine with ``python3`` and needs no internet.

Modules
-------
``parser``      normalize raw rsyslog lines into structured events
``detections``  attack-signature rules (nmap sweep, brute-force, sqlmap, nikto)
``store``       read the per-host log files the rsyslog collector writes
``app``         the read-only WSGI-free ``http.server`` web UI + JSON API

The same code powers three things, so what CI tests is what ships:

* the live SIEM viewer on the ``siem`` box (``run_logviewer.py``),
* the pytest suite in ``siem/tests`` (the flagship tests), and
* the static, in-browser portfolio demo (its corpus is generated from here).
"""
from __future__ import annotations

__version__ = "1.1.0"

from .detections import (  # noqa: F401
    DEFAULT_RULES,
    Detection,
    Rule,
    run_detections,
)
from .parser import Event, parse_line, parse_lines  # noqa: F401

__all__ = [
    "__version__",
    "Event",
    "parse_line",
    "parse_lines",
    "Rule",
    "Detection",
    "DEFAULT_RULES",
    "run_detections",
]
