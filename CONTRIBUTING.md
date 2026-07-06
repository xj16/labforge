# Contributing to labforge

Thanks for your interest! labforge is a **defensive, educational** project. A few
ground rules keep it useful and safe.

## Scope

In scope:

- new distros for the multi-distro fleet,
- additional Ansible hardening / idempotency fixes,
- detection content and dashboards for the SIEM,
- documentation, walkthroughs, and quality-of-life scripts,
- portability fixes (e.g. `ansible_local` on native Windows).

Out of scope (will be closed):

- exploits, malware, or tooling whose primary purpose is to attack systems the
  operator does not own,
- anything that weakens the lab's network isolation by default,
- real credentials, licenses, or box binaries committed to the repo.

See [ETHICS.md](ETHICS.md).

## Development

The lab itself needs VirtualBox + Vagrant, but you can iterate on the IaC
without booting VMs:

```bash
# lint everything the way CI does
pip install ansible-lint yamllint
ansible-galaxy collection install -r ansible/requirements.yml
yamllint .
ansible-lint
ansible-playbook --syntax-check ansible/site.yml   # from ansible/
```

Shell scripts should pass `shellcheck`; PowerShell should pass
`Invoke-ScriptAnalyzer -Severity Error`.

## Pull requests

1. Keep changes focused and documented.
2. Run the linters above; CI runs the same checks.
3. Update the relevant `docs/` page if you change behaviour.
4. Never commit secrets, `.box` files, or `.vagrant/`.

## Reporting issues

Bugs, unclear docs, and "this didn't provision on distro X" reports are all
welcome. Please include your VirtualBox/Vagrant/Ansible versions and the failing
task output.
