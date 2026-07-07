# Centralized logging (the SIEM)

labforge ships a **free, Splunk-style** central log server on the `siem` box
(`10.20.0.20`). Every Linux target and the attacker forward their syslog to it;
the Windows victim forwards key Security events. This gives you the *blue-team*
half of the lab: watch your own attacks land in the logs and practice detection.

## Architecture

```
  attacker ─┐
  juice ────┤  rsyslog @@10.20.0.20:5514 (TCP, disk-buffered)
  dvwa ─────┤ ───────────────────────────────►  siem (rsyslog collector)
  fleet ────┘                                        │
  victim ───  UDP syslog (PowerShell forwarder) ─────┤
                                                      ▼
                                        /opt/labforge-siem/logs/<host>/messages.log
                                                      ▼
                                        log viewer  http://10.20.0.20:8000
```

- **Collector:** rsyslog on the SIEM listens on `5514` over **both TCP and
  UDP** and writes one file per source host (a Splunk "index per source" mental
  model). Linux clients use TCP with a disk-buffered queue; the Windows victim's
  pure-PowerShell forwarder ships over UDP — both land in the same per-host file.
- **Viewer + detection engine:** a dependency-free Python web app
  (`labforge_siem`, deployed to `/opt/labforge-siem/viewer`) at
  `http://10.20.0.20:8000` — host list, per-host tail, cross-host search, and a
  built-in **detection ruleset** (see below) that flags brute-force, port
  sweeps, sqlmap and nikto scans automatically.

## Using the viewer

Open <http://10.20.0.20:8000> from your host browser (host-only network is
reachable from the host). The dashboard shows a per-host grid, one-click **saved
searches**, and — the important part — an **alerts panel** that names attacks
automatically. When something high-severity fires, a red banner appears at the
top; click through to `/alerts` for the full list.

One-click saved searches (also work as free-text search):

| Search term         | Finds |
|---------------------|-------|
| `Failed password`   | SSH / login brute-force attempts |
| `EventID=4625`      | Windows failed logons (from the victim) |
| `sqlmap`            | sqlmap's default User-Agent hitting a target |
| `nikto`             | nikto web scans |
| `dpt=`              | nmap port-sweep firewall hits |
| `labforge`          | lab marker events + forwarder heartbeats |

The same data — and the detections — are available as JSON:

```bash
curl http://10.20.0.20:8000/api/hosts
curl 'http://10.20.0.20:8000/api/tail/dvwa?n=100'
curl http://10.20.0.20:8000/api/detections   # named findings, worst first
curl http://10.20.0.20:8000/healthz          # liveness probe
```

## Built-in detections

The viewer ships a small, pure-Python detection engine (`labforge_siem`) so the
blue-team half is a real **detection lab**, not just a log grep. Each rule
recognizes an attack's log *signature* and raises a finding with a severity and
a MITRE ATT&CK technique id:

| Rule | Severity | ATT&CK | Signature it matches |
|------|----------|--------|----------------------|
| RDP/Windows brute force | high | T1110 | ≥5 Windows `EventID=4625` from one source |
| SSH brute force | high | T1110 | ≥5 `Failed password` from one source |
| Logon after brute force | critical | T1110 | a `4624` success on a host that just saw a `4625` storm |
| nmap port sweep | medium | T1046 | one source touching ≥15 distinct `DPT=` ports |
| sqlmap injection scan | high | T1190 | the `sqlmap` User-Agent in access logs |
| nikto web scan | medium | T1595 | the `nikto` scanner fingerprint |

The exact same engine powers the [live browser demo](../demo/index.html) and is
covered by the flagship test suite (`siem/tests`), so what CI proves is what the
lab actually runs.

## Bring your own real Splunk (optional)

If you have a Splunk license (or the free trial), the collector port speaks
standard syslog, so a Splunk Universal Forwarder or `inputs.conf` TCP input
drops in cleanly. To run Splunk Enterprise *on the SIEM box* instead of the free
viewer:

1. Download the Splunk `.deb` on your host (the lab is offline by design).
2. Copy it to `/opt/labforge-siem/splunk.deb` on the `siem` box.
3. Set `splunk_use_real_splunk: true` in `ansible/roles/splunk/defaults/main.yml`
   (or via group_vars), then `vagrant provision`.

The role installs the package, enables boot-start, and accepts the license
non-interactively. Splunk Web then lives at `https://10.20.0.20:8000`.

## Detection practice

1. Run an attack from Kali (e.g. `hydra` against the Windows victim's RDP, or
   `sqlmap` against DVWA).
2. Watch it in [Wireshark](wireshark.md).
3. Find it in the SIEM viewer.
4. Write down what the *signature* of that attack looks like in the logs — that
   detection instinct is the real deliverable of the lab.
