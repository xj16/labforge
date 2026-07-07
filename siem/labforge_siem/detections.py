"""labforge detection engine — turn raw logs into named attack findings.

This is the blue-team half the README promises: instead of telling the user to
manually grep for ``Failed password``, the SIEM ships a small ruleset that
recognizes the log *signature* of common lab attacks and surfaces them as
:class:`Detection` findings with a severity, the matching evidence, and a
MITRE ATT&CK technique id.

Every rule is pure and deterministic: it takes the parsed :class:`Event`
stream and returns findings. That makes the whole engine trivially testable
(see ``siem/tests``) and lets the static portfolio demo reuse the exact same
logic in the browser via a generated corpus.

Rules shipped
-------------
* **SSH brute force** — a threshold of ``Failed password`` from one source.
* **RDP/Windows brute force** — a burst of Windows ``EventID=4625`` failures.
* **nmap port sweep** — one source touching many distinct ports/targets fast.
* **sqlmap injection scan** — the tool's tell-tale ``sqlmap`` User-Agent.
* **nikto web scan** — the ``nikto`` scanner fingerprint.
* **Successful logon after brute force** — a 4625 storm followed by a 4624
  from the same source (a possible credential-stuffing success).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence

from .parser import Event

Severity = str  # "critical" | "high" | "medium" | "low" | "info"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Detection:
    """One fired detection.

    Attributes
    ----------
    rule_id:    stable machine id, e.g. ``rdp-brute-force``.
    title:      human title for the UI.
    severity:   critical|high|medium|low|info.
    technique:  MITRE ATT&CK id, e.g. ``T1110`` (brute force).
    host:       the targeted host the evidence came from.
    source:     the attacking source (IP) if one could be attributed.
    count:      number of contributing events.
    summary:    one-line description of what was seen.
    evidence:   a few representative raw lines.
    """

    rule_id: str
    title: str
    severity: Severity
    technique: str
    host: str
    source: Optional[str]
    count: int
    summary: str
    evidence: List[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        return _SEVERITY_ORDER.get(self.severity, 99)


@dataclass(frozen=True)
class Rule:
    """A named detection rule wrapping a pure detector function."""

    id: str
    title: str
    severity: Severity
    technique: str
    detect: Callable[[Sequence[Event]], List[Detection]]
    description: str = ""


# --- helpers ----------------------------------------------------------------

def _by_host(events: Sequence[Event]) -> dict[str, List[Event]]:
    grouped: dict[str, List[Event]] = defaultdict(list)
    for ev in events:
        grouped[ev.host].append(ev)
    return grouped


def _finding(rule: Rule, host: str, source: Optional[str], hits: Sequence[Event],
             summary: str) -> Detection:
    return Detection(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        technique=rule.technique,
        host=host,
        source=source,
        count=len(hits),
        summary=summary,
        evidence=[e.raw for e in hits[:4]],
    )


# --- individual detectors ---------------------------------------------------

SSH_BRUTE_THRESHOLD = 5
RDP_BRUTE_THRESHOLD = 5
SCAN_PORT_THRESHOLD = 15


def _detect_ssh_brute(events: Sequence[Event]) -> List[Detection]:
    out: List[Detection] = []
    for host, evs in _by_host(events).items():
        hits = [e for e in evs if "failed password" in e.text]
        if len(hits) < SSH_BRUTE_THRESHOLD:
            continue
        # Attribute to the most frequent source IP if we have one.
        srcs = Counter(e.src_ip for e in hits if e.src_ip)
        source = srcs.most_common(1)[0][0] if srcs else None
        out.append(
            _finding(
                RULES_BY_ID["ssh-brute-force"], host, source, hits,
                f"{len(hits)} failed SSH logins"
                + (f" from {source}" if source else "")
                + f" on {host} — likely password spraying / hydra.",
            )
        )
    return out


def _detect_rdp_brute(events: Sequence[Event]) -> List[Detection]:
    out: List[Detection] = []
    for host, evs in _by_host(events).items():
        hits = [e for e in evs if e.event_id == 4625]
        if len(hits) < RDP_BRUTE_THRESHOLD:
            continue
        srcs = Counter(e.src_ip for e in hits if e.src_ip)
        source = srcs.most_common(1)[0][0] if srcs else None
        out.append(
            _finding(
                RULES_BY_ID["rdp-brute-force"], host, source, hits,
                f"{len(hits)} Windows failed-logon (4625) events"
                + (f" from {source}" if source else "")
                + f" on {host} — RDP/SMB brute force.",
            )
        )
    return out


def _detect_logon_after_brute(events: Sequence[Event]) -> List[Detection]:
    """A 4624 success on a host that also saw a 4625 storm = possible hit."""
    out: List[Detection] = []
    for host, evs in _by_host(events).items():
        fails = [e for e in evs if e.event_id == 4625]
        wins = [e for e in evs if e.event_id == 4624]
        if len(fails) >= RDP_BRUTE_THRESHOLD and wins:
            srcs = Counter(e.src_ip for e in fails if e.src_ip)
            source = srcs.most_common(1)[0][0] if srcs else None
            out.append(
                _finding(
                    RULES_BY_ID["logon-after-brute"], host, source, wins,
                    f"Successful logon (4624) on {host} after "
                    f"{len(fails)} failures — possible brute-force success.",
                )
            )
    return out


def _detect_port_sweep(events: Sequence[Event]) -> List[Detection]:
    """A single source hitting many distinct ports/targets fast = nmap sweep.

    We look for firewall/connection lines that expose a destination port and
    count distinct ports per source. rsyslog kernel/nft lines look like
    ``... SRC=10.20.0.10 DST=10.20.0.32 ... DPT=445 ...``.
    """
    out: List[Detection] = []
    ports_by_src: dict[str, set[str]] = defaultdict(set)
    hits_by_src: dict[str, List[Event]] = defaultdict(list)
    for ev in events:
        text = ev.text
        if "dpt=" not in text and "syn-scan" not in text and "nmap" not in text:
            continue
        src = None
        for token in ev.raw.replace("\t", " ").split():
            if token.upper().startswith("SRC="):
                src = token.split("=", 1)[1]
            if token.upper().startswith("DPT="):
                port = token.split("=", 1)[1]
                if src:
                    ports_by_src[src].add(port)
        if src:
            hits_by_src[src].append(ev)
        elif "nmap" in text and ev.src_ip:
            hits_by_src[ev.src_ip].append(ev)
    for src, ports in ports_by_src.items():
        if len(ports) >= SCAN_PORT_THRESHOLD:
            hits = hits_by_src[src]
            host = hits[0].host if hits else "?"
            out.append(
                _finding(
                    RULES_BY_ID["port-sweep"], host, src, hits,
                    f"{src} probed {len(ports)} distinct ports — nmap-style "
                    f"port sweep against {host}.",
                )
            )
    return out


def _keyword_scanner(rule_id: str, needles: Sequence[str],
                     min_hits: int = 1) -> Callable[[Sequence[Event]], List[Detection]]:
    lowered = [n.lower() for n in needles]

    def detector(events: Sequence[Event]) -> List[Detection]:
        out: List[Detection] = []
        rule = RULES_BY_ID[rule_id]
        for host, evs in _by_host(events).items():
            hits = [e for e in evs if any(n in e.text for n in lowered)]
            if len(hits) < min_hits:
                continue
            srcs = Counter(e.src_ip for e in hits if e.src_ip)
            source = srcs.most_common(1)[0][0] if srcs else None
            out.append(
                _finding(
                    rule, host, source, hits,
                    f"{len(hits)} {rule.title.lower()} request(s)"
                    + (f" from {source}" if source else "")
                    + f" against {host}.",
                )
            )
        return out

    return detector


# --- rule registry ----------------------------------------------------------

DEFAULT_RULES: List[Rule] = [
    Rule(
        id="rdp-brute-force",
        title="RDP/Windows brute force",
        severity="high",
        technique="T1110",
        detect=_detect_rdp_brute,
        description="Burst of Windows EventID=4625 failed logons from one source.",
    ),
    Rule(
        id="ssh-brute-force",
        title="SSH brute force",
        severity="high",
        technique="T1110",
        detect=_detect_ssh_brute,
        description="Threshold of 'Failed password' events from one source.",
    ),
    Rule(
        id="logon-after-brute",
        title="Logon after brute force",
        severity="critical",
        technique="T1110",
        detect=_detect_logon_after_brute,
        description="A 4624 success on a host that just saw a 4625 storm.",
    ),
    Rule(
        id="port-sweep",
        title="nmap port sweep",
        severity="medium",
        technique="T1046",
        detect=_detect_port_sweep,
        description="One source touching many distinct ports quickly.",
    ),
    Rule(
        id="sqlmap-scan",
        title="sqlmap injection scan",
        severity="high",
        technique="T1190",
        detect=_keyword_scanner("sqlmap-scan", ["sqlmap"]),
        description="The sqlmap tool's tell-tale User-Agent hitting a target.",
    ),
    Rule(
        id="nikto-scan",
        title="nikto web scan",
        severity="medium",
        technique="T1595",
        detect=_keyword_scanner("nikto-scan", ["nikto"]),
        description="The nikto web scanner fingerprint in access logs.",
    ),
]

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in DEFAULT_RULES}


def run_detections(events: Iterable[Event],
                   rules: Optional[Sequence[Rule]] = None) -> List[Detection]:
    """Run every rule over ``events`` and return findings, worst first."""
    materialized = list(events)
    active = rules if rules is not None else DEFAULT_RULES
    findings: List[Detection] = []
    for rule in active:
        findings.extend(rule.detect(materialized))
    findings.sort(key=lambda d: (d.severity_rank, -d.count))
    return findings


# Convenience: saved searches surfaced as one-click buttons in the viewer.
SAVED_SEARCHES: List[dict] = [
    {"label": "Failed password", "q": "failed password"},
    {"label": "Windows 4625", "q": "eventid=4625"},
    {"label": "sqlmap", "q": "sqlmap"},
    {"label": "nikto", "q": "nikto"},
    {"label": "nmap sweep", "q": "dpt="},
    {"label": "labforge markers", "q": "labforge"},
]
