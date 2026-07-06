# Network topology

Everything sits on a single VirtualBox **host-only** network,
`10.20.0.0/24`. There is no NAT interface on the lab NICs, so the segment is
air-gapped from the internet (and an `nftables` / Windows Firewall egress guard
enforces that even if a route is added by accident).

```
                         VirtualBox host-only network  10.20.0.0/24
                         (promiscuous; sniffable from the attacker)
  ┌───────────────────────────────────────────────────────────────────────┐
  │                                                                         │
  │   .10  attacker   Kali Linux                                            │
  │        └ Metasploit · Wireshark/tshark · Burp · nmap · sqlmap · hydra   │
  │                                                                         │
  │   .20  siem       Central logs (rsyslog collector + web viewer :8000)   │
  │        ▲  ▲  ▲                                                          │
  │        │  │  └──────────────── syslog @@:5514 ─── fleet (.51-.54)        │
  │        │  └───────── syslog ─── dvwa  (.32)                              │
  │        └──────────── syslog ─── juice (.31)                             │
  │                                                                         │
  │   Deliberately-vulnerable targets                                       │
  │   .31  juice      OWASP Juice Shop  :3000                                │
  │   .32  dvwa       DVWA              :80    (admin/password)              │
  │   .40  victim     Windows 10        SMB/RDP   (opt-in; UDP syslog)       │
  │                                                                         │
  │   Multi-distro fleet (baseline + log forwarding)                        │
  │   .51 deb (Debian 12)  .52 ubuntu (22.04)  .53 fedora (39)  .54 arch     │
  │                                                                         │
  └───────────────────────────────────────────────────────────────────────┘
                                    ╳  no route to the internet  ╳
```

## Address plan

| Host     | IP          | Box                          | Role |
|----------|-------------|------------------------------|------|
| attacker | 10.20.0.10  | `kalilinux/rolling`          | Attacker workstation |
| siem     | 10.20.0.20  | `bento/ubuntu-22.04`         | Central logging / SIEM |
| juice    | 10.20.0.31  | `bento/ubuntu-22.04`         | OWASP Juice Shop |
| dvwa     | 10.20.0.32  | `bento/debian-12`            | DVWA |
| victim   | 10.20.0.40  | `gusztavvargadr/windows-10`  | Windows victim (opt-in) |
| deb      | 10.20.0.51  | `bento/debian-12`            | Fleet node |
| ubuntu   | 10.20.0.52  | `bento/ubuntu-22.04`         | Fleet node |
| fedora   | 10.20.0.53  | `bento/fedora-39`            | Fleet node |
| arch     | 10.20.0.54  | `archlinux/archlinux`        | Fleet node |

The address plan lives in **three** places kept in sync:
`lab.yml` (source of truth), the `Vagrantfile` machine catalogue, and
`ansible/inventory/hosts.ini`. Change `lab.yml` first.

## Toggles

The Vagrantfile reads three environment switches (wrapped by `scripts/lab-up.sh`):

| Env var             | Default | Effect |
|---------------------|---------|--------|
| `LABFORGE_MINIMAL`  | `0`     | `1` = only attacker + siem + juice |
| `LABFORGE_FLEET`    | `1`     | `0` = skip the multi-distro fleet |
| `LABFORGE_WINDOWS`  | `0`     | `1` = include the Windows victim |
