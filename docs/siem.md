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

- **Collector:** rsyslog on the SIEM listens on TCP `5514` and writes one file
  per source host (a Splunk "index per source" mental model).
- **Viewer:** a dependency-free Python web app (`logviewer.py`) at
  `http://10.20.0.20:8000` — host list, per-host tail, and cross-host search.

## Using the viewer

Open <http://10.20.0.20:8000> from your host browser (host-only network is
reachable from the host). Try searches that surface attacks:

| Search term         | Finds |
|---------------------|-------|
| `Failed password`   | SSH / login brute-force attempts |
| `sqlmap`            | sqlmap's default User-Agent hitting a target |
| `nikto`             | nikto web scans |
| `EventID=4625`      | Windows failed logons (from the victim) |
| `labforge`          | lab marker events + forwarder heartbeats |

The same data is available as JSON:

```bash
curl http://10.20.0.20:8000/api/hosts
curl 'http://10.20.0.20:8000/api/tail/dvwa?n=100'
```

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
