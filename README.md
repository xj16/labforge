# labforge

**One-command reproducible security homelab.** Infrastructure-as-code that spins
up an *isolated, host-only, no-internet* pentest lab in Vagrant + VirtualBox: a
Kali attacker box, deliberately-vulnerable OWASP web targets, a Windows victim, a
multi-distro Linux fleet, and a free Splunk-style centralized log server — all
provisioned by Ansible.

> ⚠️ **Strictly educational and defensive.** This lab is air-gapped and meant for
> practicing security skills on machines *you own*. **Read
> [ETHICS.md](ETHICS.md) before you run anything.**

```bash
git clone https://github.com/xj16/labforge && cd labforge
scripts/lab-up.sh --minimal      # attacker + siem + Juice Shop (fastest)
scripts/verify-isolation.sh      # prove it can't reach the internet
```

---

## Why

Learning offensive security responsibly needs a target range you own and can
break freely. Spinning one up by hand — Kali, vulnerable apps, a victim box, and
somewhere to watch the logs — is fiddly and easy to get *wrong* in dangerous
ways (a stray NAT interface and your "lab" is now scanning the internet).

labforge makes that range **reproducible, isolated by construction, and
disposable**: one command up, one command down, and an isolation checker that
fails loudly if anything leaks. It also pairs the red-team tooling with a
**blue-team** feedback loop — a centralized SIEM so you can watch your own
attacks land in the logs and learn detection.

## What you get

| Machine   | IP          | What it is |
|-----------|-------------|------------|
| attacker  | 10.20.0.10  | **Kali Linux** — Metasploit, Wireshark/tshark, Burp Suite, nmap, sqlmap, hydra, nikto, plus staged cheat-sheets and a recon helper |
| siem      | 10.20.0.20  | **Central logging / SIEM** — rsyslog collector + a dependency-free web log viewer (`:8000`); optional real-Splunk path |
| juice     | 10.20.0.31  | **OWASP Juice Shop** — the reference vulnerable web app (`:3000`) |
| dvwa      | 10.20.0.32  | **DVWA** on a LAMP stack — progressive difficulty (`admin`/`password`) |
| victim    | 10.20.0.40  | **Windows 10 victim** (opt-in) — SMB + RDP, weak accounts, Event-Log forwarding |
| deb/ubuntu/fedora/arch | 10.20.0.51-54 | **Multi-distro fleet** — Debian 12, Ubuntu 22.04, Fedora 39, Arch; baseline-hardened and forwarding logs |

Full address plan and diagram: [docs/topology.md](docs/topology.md).

## Features

- **One command up/down.** `scripts/lab-up.sh` (or `make up`) → the whole range;
  `vagrant destroy -f` → gone.
- **Isolated by construction.** Single VirtualBox host-only network, no NAT on
  lab NICs, plus an `nftables` / Windows-Firewall egress guard as defence-in-
  depth. `scripts/verify-isolation.sh` actively proves it.
- **Real provisioning, not a scaffold.** Idempotent Ansible roles install and
  configure every service for real (Metasploit DB init, Juice Shop as a systemd
  service, DVWA seeded end-to-end, rsyslog central collector, per-host log
  files, a working web log viewer).
- **Blue-team built in.** Every box forwards syslog to the SIEM; the Windows
  victim ships Security events (4624/4625/...) via a pure-PowerShell UDP syslog
  forwarder. Search your own attacks at `http://10.20.0.20:8000`.
- **Red-team ready.** Kali comes pre-loaded with a `scan-lab.sh` recon script, a
  Metasploit `recon.rc` resource file, non-root packet capture, and a target
  cheat-sheet.
- **Data-driven topology.** Edit `lab.yml`, not Ruby. Toggle the fleet, the
  Windows victim, or a minimal fast lab with env switches.
- **100% free & offline-capable.** No paid services, no API keys. Community
  Vagrant boxes and open-source tooling only. Optional real-Splunk path if you
  have your own license.

## Requirements

- [VirtualBox](https://www.virtualbox.org/) 7.x
- [Vagrant](https://www.vagrantup.com/) 2.3+
- ~8 GB free RAM for the minimal lab, ~16 GB for the full fleet, and disk for the
  boxes
- To provision from the host: Ansible (Linux/macOS/WSL). On Windows without WSL,
  use `ansible_local` — see [Provisioning on Windows](#provisioning-on-windows).

First `vagrant up` downloads the community boxes; after that it's cached.

## Quick start

```bash
# fastest: attacker + siem + Juice Shop
scripts/lab-up.sh --minimal

# the full range (targets + multi-distro fleet)
scripts/lab-up.sh

# add the Windows victim
scripts/lab-up.sh --windows

# what's running + where to click
scripts/lab-status.sh

# prove the lab is air-gapped (should report every box isolated)
scripts/verify-isolation.sh
```

Or via `make`: `make up`, `make minimal`, `make windows`, `make status`,
`make isolation`, `make destroy`.

Then:

- **SIEM log viewer** → <http://10.20.0.20:8000>
- **Juice Shop** → <http://10.20.0.31:3000>
- **DVWA** → <http://10.20.0.32/> (`admin` / `password`)
- **Attacker** → `vagrant ssh attacker`, then `cd ~/labforge && ./scan-lab.sh`

Walk the whole thing end-to-end in [docs/walkthrough.md](docs/walkthrough.md).

## How it works

```
Vagrantfile (reads lab.yml)
  └─ per-VM: host-only NIC on 10.20.0.0/24, no NAT, promisc for sniffing
  └─ shell bootstrap (ensure python3)
  └─ Ansible provisioner runs ansible/site.yml
         common       → baseline pkgs, /etc/hosts, nftables egress guard
         splunk       → rsyslog central collector + web log viewer (on siem)
         log_forwarder→ point every client's rsyslog at the SIEM
         kali         → offensive tooling, msfdb, capture rights, cheat-sheets
         juiceshop    → OWASP Juice Shop as a systemd service
         dvwa         → LAMP + DVWA, config templated, DB seeded
  Windows victim → windows/provision-victim.ps1 (SMB/RDP, weak users, syslog)
```

Provisioning order matters — the SIEM comes up before clients try to forward, so
`site.yml` sequences the plays accordingly.

### Provisioning on Windows

The default flow runs Ansible **from the host**, which needs a POSIX Ansible
(Linux, macOS, or WSL). If you're on native Windows without WSL, switch the
Vagrantfile's `config.vm.provision "ansible"` block to `ansible_local` (runs
Ansible *inside* a guest — no host Ansible required). The roles are unchanged;
only where the control node runs differs.

## Configuration

- **Topology:** `lab.yml` — subnet and per-host addresses (the single source of
  truth; mirrored in the Vagrantfile and the Ansible inventory).
- **Global vars:** `ansible/group_vars/all.yml` — SIEM host/port, isolation
  toggle, baseline packages.
- **Target vars:** `ansible/group_vars/targets_web.yml` — Juice Shop version,
  DVWA credentials and security level.
- **Env toggles:** `LABFORGE_MINIMAL`, `LABFORGE_FLEET`, `LABFORGE_WINDOWS`
  (see [docs/topology.md](docs/topology.md)).

## Documentation

- [ETHICS.md](ETHICS.md) — legal/ethics note. **Read first.**
- [docs/topology.md](docs/topology.md) — network map and address plan
- [docs/walkthrough.md](docs/walkthrough.md) — a guided first hour
- [docs/wireshark.md](docs/wireshark.md) — capturing lab traffic
- [docs/burp.md](docs/burp.md) — proxying targets through Burp Suite
- [docs/siem.md](docs/siem.md) — the centralized logging setup + real-Splunk path

## Tech stack

**Vagrant** + **VirtualBox** (IaC / virtualization) · **Ansible** (provisioning,
6 roles) · **Bash** & **PowerShell** (bootstrap, helpers, Windows victim) ·
**Kali Linux** with **Metasploit**, **Wireshark**, **Burp Suite** (red team) ·
**OWASP** Juice Shop & DVWA (targets) · **rsyslog** + Python stdlib web viewer,
**Splunk**-compatible (blue team) · **nftables** (isolation) · **GitHub Actions**
(ansible-lint + yamllint CI).

## Repository layout

```
labforge/
├── Vagrantfile              # data-driven multi-machine definition
├── lab.yml                  # topology source of truth
├── Makefile                 # convenience targets
├── ansible/
│   ├── site.yml             # top-level playbook
│   ├── ansible.cfg
│   ├── requirements.yml     # Galaxy collections
│   ├── inventory/hosts.ini
│   ├── group_vars/
│   └── roles/               # common, splunk, log_forwarder, kali, juiceshop, dvwa
├── windows/                 # Windows victim provisioner + syslog forwarder
├── scripts/                 # bootstrap, lab-up, lab-status, verify-isolation
└── docs/                    # topology, walkthrough, wireshark, burp, siem
```

## Contributing

Issues and PRs welcome — for **defensive/educational** improvements only (new
distros in the fleet, more Ansible hardening, detection content for the SIEM).
Exploits or anything intended to attack systems the operator doesn't own are out
of scope; see [ETHICS.md](ETHICS.md).

## License

[MIT](LICENSE) © 2026 xj16
