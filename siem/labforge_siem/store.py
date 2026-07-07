"""Read the per-host log files the labforge rsyslog collector writes.

The collector writes ``LOG_ROOT/<host>/messages.log`` (one file per source
host). This module is the *only* thing that touches the filesystem, and every
public function validates the host name against a strict allow-list so a
crafted URL can never escape ``LOG_ROOT`` (path-traversal safe — see the
flagship tests).
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from .detections import Detection, run_detections
from .parser import parse_lines

HOST_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
DEFAULT_TAIL = 300


class LogStore:
    """A read-only view over the per-host log directory tree."""

    def __init__(self, log_root: str):
        # Resolve once so traversal checks compare against a real absolute base.
        self.log_root = os.path.abspath(log_root)

    # -- discovery -----------------------------------------------------------

    def list_hosts(self) -> List[dict]:
        """Return ``[{name, lines, bytes}]`` for every host with a log file."""
        hosts: List[dict] = []
        if not os.path.isdir(self.log_root):
            return hosts
        for name in sorted(os.listdir(self.log_root)):
            path = os.path.join(self.log_root, name, "messages.log")
            if os.path.isfile(path):
                try:
                    size = os.path.getsize(path)
                    with open(path, "rb") as fh:
                        lines = sum(1 for _ in fh)
                except OSError:
                    size, lines = 0, 0
                hosts.append({"name": name, "lines": lines, "bytes": size})
        return hosts

    def safe_host_path(self, name: str) -> Optional[str]:
        """Resolve a host name to its log path, refusing anything unexpected.

        Rejects names with path separators, ``..`` traversal, absolute paths,
        or anything that resolves outside ``LOG_ROOT``. This is the security
        boundary for the whole viewer.
        """
        if not name or not HOST_RE.match(name):
            return None
        candidate = os.path.normpath(os.path.join(self.log_root, name, "messages.log"))
        base = self.log_root + os.sep
        if not (candidate == self.log_root or candidate.startswith(base)):
            return None
        # Belt and braces: the resolved directory must be a direct child.
        if os.path.dirname(candidate) != os.path.join(self.log_root, name):
            return None
        return candidate if os.path.isfile(candidate) else None

    # -- reads ---------------------------------------------------------------

    def tail(self, path: str, n: int) -> List[str]:
        """Return the last ``n`` lines of a file without loading the whole thing."""
        if n <= 0:
            return []
        try:
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                end = fh.tell()
                block = 4096
                data = b""
                while end > 0 and data.count(b"\n") <= n:
                    step = min(block, end)
                    end -= step
                    fh.seek(end)
                    data = fh.read(step) + data
            text = data.decode("utf-8", "replace")
            return text.splitlines()[-n:]
        except OSError:
            return []

    def tail_host(self, name: str, n: int = DEFAULT_TAIL) -> Optional[List[str]]:
        """Tail a host by name, or ``None`` if the host is unknown/unsafe."""
        path = self.safe_host_path(name)
        if not path:
            return None
        return self.tail(path, n)

    def search_all(self, term: str, limit: int = 500) -> List[Tuple[str, str]]:
        """Case-insensitive grep across every host log. Returns ``(host, line)``."""
        results: List[Tuple[str, str]] = []
        if not term:
            return results
        needle = term.lower()
        for host in self.list_hosts():
            path = os.path.join(self.log_root, host["name"], "messages.log")
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if needle in line.lower():
                            results.append((host["name"], line.rstrip("\n")))
                            if len(results) >= limit:
                                return results
            except OSError:
                continue
        return results

    # -- detection -----------------------------------------------------------

    def all_events(self, per_host_limit: int = 5000):
        """Yield parsed events across every host (capped per host)."""
        for host in self.list_hosts():
            lines = self.tail_host(host["name"], per_host_limit) or []
            yield from parse_lines(lines, host=host["name"])

    def detections(self) -> List[Detection]:
        """Run the detection engine over everything currently collected."""
        return run_detections(self.all_events())
