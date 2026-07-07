"""Generate a realistic, deterministic log corpus for the labforge SIEM.

This is the single source of truth for canned lab data. It writes the same
per-host ``messages.log`` files the real rsyslog collector produces, seeded with
a believable attack story:

* an **nmap** sweep from the attacker across the fleet,
* a **hydra** SSH brute-force against DVWA (many ``Failed password``),
* an **RDP/SMB brute force** against the Windows victim (a 4625 storm) that
  finally *succeeds* (a 4624),
* an **sqlmap** injection run against DVWA, and
* a **nikto** web scan against Juice Shop,

interleaved with benign background noise. Three consumers share it so the demo
never drifts from reality:

* ``make demo`` seeds a live viewer,
* the flagship tests assert the detection engine fires on it, and
* ``export_json`` bakes it into the static, in-browser portfolio demo.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List

ATTACKER = "10.20.0.10"
SIEM = "10.20.0.20"
JUICE = "10.20.0.31"
DVWA = "10.20.0.32"
VICTIM = "10.20.0.40"

_START = datetime(2026, 7, 6, 14, 0, 0, tzinfo=timezone.utc)


def _ts(offset_s: float) -> str:
    return (_START + timedelta(seconds=offset_s)).isoformat()


def _line(offset_s: float, host: str, tag: str, msg: str) -> str:
    return f"{_ts(offset_s)} {host} {tag}: {msg}"


def build_corpus() -> Dict[str, List[str]]:
    """Return ``{host: [raw log lines]}`` — deterministic, no randomness."""
    logs: Dict[str, List[str]] = {"attacker": [], "siem": [], "juice": [],
                                  "dvwa": [], "victim": []}

    # -- benign background -------------------------------------------------
    logs["siem"].append(_line(0, "siem", "labforge", "central collector online (tcp+udp 5514)"))
    logs["attacker"].append(_line(1, "attacker", "labforge", "attacker box provisioned; recon ready"))
    for i, host in enumerate(("juice", "dvwa", "victim")):
        logs[host].append(_line(2 + i, host, "systemd", "Started labforge target services."))

    # -- 1. nmap sweep from attacker across the segment --------------------
    t = 30
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993,
                  995, 1723, 3306, 3389, 5900, 8000, 8080, 8443]
    for host, dst in (("dvwa", DVWA), ("juice", JUICE), ("victim", VICTIM)):
        for j, port in enumerate(scan_ports):
            logs[host].append(_line(
                t, host, "kernel",
                f"[labforge-nft] SYN-scan IN=eth1 SRC={ATTACKER} DST={dst} "
                f"PROTO=TCP SPT=44321 DPT={port} WINDOW=1024 SYN",
            ))
            t += 0.05
    logs["attacker"].append(_line(t, "attacker", "nmap",
                                  f"nmap -sS -p- {DVWA} {JUICE} {VICTIM} : scan started"))

    # -- 2. hydra SSH brute force against DVWA -----------------------------
    t = 90
    users = ["admin", "root", "gordonb", "1337", "pablo", "smithy", "admin"]
    for i in range(24):
        u = users[i % len(users)]
        logs["dvwa"].append(_line(
            t, "dvwa", "sshd",
            f"Failed password for {u} from {ATTACKER} port {40000 + i} ssh2",
        ))
        t += 0.4
    logs["dvwa"].append(_line(t, "dvwa", "sshd",
                              f"Accepted password for gordonb from {ATTACKER} port 40099 ssh2"))

    # -- 3. sqlmap injection run against DVWA ------------------------------
    t = 140
    payloads = [
        "/vulnerabilities/sqli/?id=1%27&Submit=Submit",
        "/vulnerabilities/sqli/?id=1%27+AND+1%3D1--+-&Submit=Submit",
        "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2Cpassword+FROM+users--+-&Submit=Submit",
        "/vulnerabilities/sqli/?id=1%27+AND+SLEEP%285%29--+-&Submit=Submit",
    ]
    for i, p in enumerate(payloads):
        logs["dvwa"].append(_line(
            t, "dvwa", "apache2",
            f'{ATTACKER} - - "GET {p} HTTP/1.1" 200 4512 '
            f'"-" "sqlmap/1.8#stable (https://sqlmap.org)"',
        ))
        t += 0.3

    # -- 4. nikto web scan against Juice Shop ------------------------------
    t = 160
    nikto_paths = ["/admin", "/.git/config", "/robots.txt", "/server-status",
                   "/phpmyadmin/", "/.env", "/backup.zip", "/ftp"]
    for i, p in enumerate(nikto_paths):
        code = 404 if i % 2 else 200
        logs["juice"].append(_line(
            t, "juice", "juice-shop",
            f'{ATTACKER} - - "GET {p} HTTP/1.1" {code} 210 '
            f'"-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:map_codes)"',
        ))
        t += 0.25

    # -- 5. RDP/SMB brute force against the Windows victim -> success ------
    t = 200
    win_users = ["labuser", "administrator", "svc_backup", "guest", "labuser"]
    for i in range(18):
        u = win_users[i % len(win_users)]
        logs["victim"].append(_line(
            t, "victim", "labforge",
            f"EventID=4625 An account failed to log on. "
            f"Account: {u}  Source Network Address: {ATTACKER}  "
            f"Logon Type: 10 (RemoteInteractive)  Status: 0xC000006D",
        ))
        t += 0.5
    # the spray finally lands:
    logs["victim"].append(_line(
        t, "victim", "labforge",
        f"EventID=4624 An account was successfully logged on. "
        f"Account: labuser  Source Network Address: {ATTACKER}  "
        f"Logon Type: 10 (RemoteInteractive)",
    ))
    t += 0.5
    logs["victim"].append(_line(
        t, "victim", "labforge",
        f"EventID=4672 Special privileges assigned to new logon. "
        f"Account: labuser  Source Network Address: {ATTACKER}",
    ))

    # -- benign trailing noise ---------------------------------------------
    for host in ("juice", "dvwa"):
        logs[host].append(_line(300, host, "systemd", "labforge health check ok"))

    for host in logs:
        logs[host].sort()
    return logs


def write_corpus(log_root: str) -> Dict[str, int]:
    """Write the corpus under ``log_root/<host>/messages.log``. Returns line counts."""
    corpus = build_corpus()
    counts: Dict[str, int] = {}
    for host, lines in corpus.items():
        host_dir = os.path.join(log_root, host)
        os.makedirs(host_dir, exist_ok=True)
        with open(os.path.join(host_dir, "messages.log"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        counts[host] = len(lines)
    return counts


def export_json() -> dict:
    """Return a JSON-serializable bundle: corpus + host stats. For the static demo."""
    corpus = build_corpus()
    hosts = [
        {"name": h, "lines": len(lines),
         "bytes": sum(len(x) + 1 for x in lines)}
        for h, lines in sorted(corpus.items())
    ]
    return {"generated": _START.isoformat(), "hosts": hosts, "logs": corpus}


if __name__ == "__main__":  # pragma: no cover - manual/demo entrypoint
    import argparse

    ap = argparse.ArgumentParser(description="labforge SIEM corpus generator")
    ap.add_argument("--log-root", default=os.environ.get(
        "LABFORGE_LOG_ROOT", "/opt/labforge-siem/logs"))
    ap.add_argument("--json", action="store_true", help="print the JSON bundle")
    args = ap.parse_args()
    if args.json:
        print(json.dumps(export_json(), indent=2))
    else:
        counts = write_corpus(args.log_root)
        total = sum(counts.values())
        print(f"seeded {total} lines across {len(counts)} hosts into {args.log_root}")
        for host, n in sorted(counts.items()):
            print(f"  {host:10} {n:4} lines")
