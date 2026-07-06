#!/usr/bin/env bash
#
# bootstrap.sh — minimal, idempotent guest bootstrap run by Vagrant BEFORE
# Ansible takes over. Its only jobs:
#   1. make sure a Python interpreter exists (Ansible's hard requirement)
#   2. record which lab group this box belongs to (for local debugging)
#
# It intentionally does NOT install the internet-facing lab payloads — that is
# Ansible's job, and keeping this tiny means it works across Debian/Ubuntu/
# Fedora/Arch/Kali with one script.
#
set -euo pipefail

GROUP="${LABFORGE_GROUP:-unknown}"
echo "[labforge] bootstrapping host (group=${GROUP})"

# Detect the package manager and ensure python3 is present.
if command -v python3 >/dev/null 2>&1; then
  echo "[labforge] python3 already present: $(python3 --version 2>&1)"
elif command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends python3 python3-apt
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 python3-dnf
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm python
else
  echo "[labforge] ERROR: no known package manager to install python3" >&2
  exit 1
fi

# Leave a breadcrumb so 'vagrant ssh <box> -c "cat /etc/labforge-group"' works.
echo "${GROUP}" > /etc/labforge-group || true

echo "[labforge] bootstrap complete"
