# Ethics, Legality & Safe-Use Policy

labforge exists to help people learn **defensive** and **offensive-for-defense**
security skills on infrastructure **they own**, in a lab that **cannot reach the
internet**. Read this before you run anything.

## The one rule

> **Only attack machines you own or are explicitly, in writing, authorized to
> test.** The vulnerable targets in this lab are yours. Everything else is
> off-limits.

Running the tools in this repo against systems you do not own or lack written
permission to test is illegal in most jurisdictions (e.g. the US Computer Fraud
and Abuse Act, the UK Computer Misuse Act, and equivalents worldwide) and can
lead to criminal charges. That is not what this project is for.

## Why this lab is safe

1. **No internet route.** Every VM sits on a single VirtualBox *host-only*
   network. There is no NAT interface on the lab NICs, so packets have nowhere
   to go except other lab machines.
2. **Belt-and-braces firewalling.** On top of the missing route, the `common`
   Ansible role installs an `nftables` egress guard (and the Windows victim gets
   an equivalent Windows Firewall rule) that DROPs anything trying to leave
   `10.20.0.0/24`.
3. **Verifiable.** `scripts/verify-isolation.sh` actively tries to reach the
   internet from every box and **fails loudly** if any of them succeeds. Run it
   before you start attacking.
4. **Throwaway.** `vagrant destroy -f` erases the whole thing. Nothing here is
   meant to persist or be exposed.

## Intentional weaknesses live here — keep them here

This lab deliberately contains vulnerable apps (Juice Shop, DVWA), weak
passwords, and open services. Those are **features** for learning — and exactly
why the lab must never touch a network you care about. Do not:

- port-forward a target to the internet or your LAN,
- reuse any credential from this repo (`admin/password`, `p@ssw0rd`,
  `Password1`, `Summer2026`, ...) anywhere real,
- copy a vulnerable VM out of the isolated network.

## Responsible disclosure

If you discover a genuine vulnerability in a third-party product while learning
here, report it responsibly to that vendor. Do not weaponize it.

## Scope of this project

labforge is **strictly educational and defensive**. It ships infrastructure-as-
code and documentation. It does not include, and will not accept contributions
of, exploits or tooling whose primary purpose is to attack systems the operator
does not own.

By using this repository you agree to use it lawfully and ethically.
