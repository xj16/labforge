# Changelog

All notable changes to labforge are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-07-07

The "detection lab" release: the blue-team half graduates from a log viewer to
a real detection engine, gains a flagship test suite and a VM-free live demo,
and a correctness bug that silently swallowed all Windows events is fixed.

### Fixed
- **Windows Security events now actually reach the SIEM.** The Windows
  PowerShell forwarder ships syslog over **UDP** to port 5514, but the rsyslog
  central collector only loaded `imtcp` — so `4624`/`4625` events were dropped
  on the floor and the headline blue-team walkthrough step silently failed. The
  collector now binds **both TCP and UDP** on 5514
  (`10-labforge-collector.conf.j2`). Linux clients keep reliable TCP delivery;
  the Windows victim's UDP packets finally land.

### Added
- **Detection engine (`siem/labforge_siem`).** A tiny, zero-runtime-dependency
  (stdlib-only) Python package that parses the per-host logs and raises named,
  severity-ranked findings mapped to MITRE ATT&CK:
  - SSH brute force (`Failed password` threshold) — T1110
  - RDP/Windows brute force (`EventID=4625` burst) — T1110
  - Logon-after-brute (a `4624` success after a `4625` storm) — T1110, critical
  - nmap port sweep (many distinct destination ports from one source) — T1046
  - sqlmap injection scan (User-Agent fingerprint) — T1190
  - nikto web scan (scanner fingerprint) — T1595
- **Redesigned SIEM viewer.** Rebuilt on the new package with an alert banner,
  a dedicated `/alerts` page, one-click saved searches, a `/api/detections`
  JSON endpoint, a `/healthz` probe, and `X-Content-Type-Options: nosniff`. The
  Ansible `splunk` role now deploys the tested package (not a one-off template).
- **Flagship test suite + coverage gate.** 65 pytest tests over the parser,
  the path-traversal-safe store, every detection rule (including negative and
  threshold cases), and the live HTTP server (with a real path-traversal probe).
  ~95% line+branch coverage, gated in CI (`--fail-under=90`) with a committed,
  auto-generated coverage badge.
- **VM-free live demo (`demo/`).** A single self-contained HTML+JS page that
  runs the whole dashboard — host grid, per-host drilldown with highlighted
  attack evidence, cross-host search, an inline SVG severity chart, and the
  automatic detections — entirely in the browser. Its corpus and findings are
  generated from the real engine (`demo/build_demo.py`), and CI fails if the
  committed data drifts.
- **SVG architecture + attack-path diagram** (`docs/architecture.svg`) showing
  attacker → targets → SIEM, the host-only segment, the egress guard as a wall,
  and the attack/log flows. Embedded in the README.
- **Deterministic log corpus generator** (`labforge_siem.corpus`) that seeds a
  realistic attack story (nmap sweep → hydra → sqlmap → nikto → an RDP 4625
  storm that lands a 4624). Shared by the tests, the demo, and `make demo`.
- **`make` targets:** `test`, `coverage`, `demo`, `demo-build`, `verify`.

### Changed
- **Isolation verifier is now a real gate, and covers Windows.**
  `verify-isolation.sh` probes multiple egress vectors (TCP/443 to two IPs, DNS,
  ICMP) instead of a single curl, includes the Windows `victim` over a WinRM
  `Test-NetConnection` probe, emits a machine-readable `isolation-report.json`,
  and treats an inconclusive probe as a failure. `lab-up.sh` runs it
  automatically after convergence and refuses to declare success on any leak
  (skippable with `LABFORGE_SKIP_VERIFY=1`).
- **CI** gained a `siem-tests` job (pytest + coverage + badge freshness + demo
  freshness) alongside the existing lint / syntax / shellcheck / PSScriptAnalyzer
  jobs.
- Documentation updated throughout (`docs/siem.md` detection table, walkthrough
  steps 5–6) to reflect the TCP+UDP collector and the new detections.

### Removed
- The single-file `logviewer.py.j2` template, superseded by the deployed
  `labforge_siem` package.

## [1.0.0] — 2026-07-06

Initial release.

### Added
- One-command reproducible security homelab in Vagrant + VirtualBox, fully
  provisioned by Ansible (6 roles): a Kali attacker, OWASP Juice Shop and DVWA
  targets, an opt-in Windows 10 victim, a multi-distro fleet, and a free
  Splunk-style central log server.
- Isolation by construction: a single host-only network with no NAT, plus an
  `nftables` / Windows-Firewall egress guard, and a `verify-isolation.sh` check.
- Data-driven topology (`lab.yml`), convenience `Makefile` and helper scripts,
  Kali recon tooling (`scan-lab.sh`, `recon.rc`), and guided docs.
- CI: yamllint + ansible-lint + Ansible syntax check + ShellCheck +
  PSScriptAnalyzer.

[1.1.0]: https://github.com/xj16/labforge/releases/tag/v1.1.0
[1.0.0]: https://github.com/xj16/labforge/releases/tag/v1.0.0
