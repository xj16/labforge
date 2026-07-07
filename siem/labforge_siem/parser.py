"""Parse the per-host syslog lines the labforge rsyslog collector writes.

The central collector (``10-labforge-collector.conf.j2``) writes one file per
source host with the ``LabforgeLine`` template::

    <rfc3339-timestamp> <hostname> <syslogtag><message>

for example::

    2026-07-06T14:03:11.482Z dvwa apache2: 10.20.0.10 - - "GET /?id=1 sqlmap/1.7"
    2026-07-06T14:05:02.001Z victim labforge: EventID=4625 An account failed to log on...

The Windows PowerShell forwarder ships RFC3164 packets that rsyslog rewrites
into the same shape, so a single parser handles every source. Parsing is
deliberately tolerant: an unrecognized line still yields an :class:`Event` with
the whole line as ``message`` so nothing is silently dropped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

# rsyslog date-rfc3339 e.g. 2026-07-06T14:03:11.482123+00:00 or ...Z
_RFC3339 = (
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
)
# hostname then an optional "tag:" then the free-form message.
_LINE_RE = re.compile(
    rf"^{_RFC3339}\s+(?P<host>[A-Za-z0-9_.-]+)\s+"
    r"(?:(?P<tag>[A-Za-z0-9_./\[\]:-]+?):\s*)?(?P<msg>.*)$"
)

# A dotted-quad IPv4 (good enough for the lab's 10.20.0.0/24 segment).
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Windows Security event id, as emitted by the PowerShell forwarder.
_EVENTID_RE = re.compile(r"\bEventID=(\d{3,5})\b")


@dataclass(frozen=True)
class Event:
    """A single normalized log line.

    Attributes
    ----------
    host:       the sending host (the SIEM's per-host index).
    message:    the free-form message body.
    timestamp:  parsed UTC datetime, or ``None`` if the line had no timestamp.
    tag:        the syslog tag / program (``apache2``, ``sshd``, ``labforge``…).
    src_ip:     first IPv4 found in the message, if any (the likely source).
    event_id:   Windows Security EventID, if the line carried one.
    raw:        the original line, untouched.
    """

    host: str
    message: str
    timestamp: Optional[datetime] = None
    tag: str = ""
    src_ip: Optional[str] = None
    event_id: Optional[int] = None
    raw: str = field(default="", repr=False)

    @property
    def text(self) -> str:
        """Everything searchable about the event, lower-cased."""
        return self.raw.lower()


def _parse_ts(value: str) -> Optional[datetime]:
    """Parse an rfc3339 timestamp into an aware UTC datetime, tolerantly."""
    if not value:
        return None
    v = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_line(line: str, *, host: Optional[str] = None) -> Optional[Event]:
    """Parse one raw log line into an :class:`Event`.

    ``host`` overrides the host parsed from the line — the collector already
    files logs per host, so callers pass the directory name to stay correct
    even when a message body happens to contain another hostname.

    Returns ``None`` only for blank lines.
    """
    stripped = line.rstrip("\n")
    if not stripped.strip():
        return None

    m = _LINE_RE.match(stripped)
    if m:
        ts = _parse_ts(m.group("ts"))
        parsed_host = host or m.group("host")
        tag = (m.group("tag") or "").strip()
        msg = m.group("msg")
    else:
        # Unstructured line: keep it rather than dropping it.
        ts = None
        parsed_host = host or "unknown"
        tag = ""
        msg = stripped

    ip_match = _IPV4_RE.search(msg)
    eid_match = _EVENTID_RE.search(msg)
    return Event(
        host=parsed_host,
        message=msg,
        timestamp=ts,
        tag=tag,
        src_ip=ip_match.group(0) if ip_match else None,
        event_id=int(eid_match.group(1)) if eid_match else None,
        raw=stripped,
    )


def parse_lines(lines: Iterable[str], *, host: Optional[str] = None) -> Iterator[Event]:
    """Parse an iterable of raw lines, skipping blanks."""
    for line in lines:
        ev = parse_line(line, host=host)
        if ev is not None:
            yield ev
