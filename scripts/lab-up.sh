#!/usr/bin/env bash
#
# lab-up.sh — bring the labforge lab online with sensible defaults and a few
# preflight checks. Thin, friendly wrapper around `vagrant up`.
#
# Usage:
#   scripts/lab-up.sh              # attacker + siem + targets + fleet
#   scripts/lab-up.sh --minimal    # attacker + siem + juice only (fast)
#   scripts/lab-up.sh --windows    # also bring up the Windows victim
#   scripts/lab-up.sh --no-fleet   # skip the multi-distro fleet
#
set -euo pipefail
cd "$(dirname "$0")/.."

WIN=0
FLEET=1
MINIMAL=0

for arg in "$@"; do
  case "$arg" in
    --windows)  WIN=1 ;;
    --no-fleet) FLEET=0 ;;
    --minimal)  MINIMAL=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

echo "[labforge] preflight checks"
for tool in vagrant VBoxManage; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "  ERROR: '$tool' not found on PATH. Install VirtualBox + Vagrant first." >&2
    exit 1
  fi
done
echo "  vagrant : $(vagrant --version)"
echo "  vbox    : $(VBoxManage --version)"

export LABFORGE_WINDOWS="$WIN"
export LABFORGE_FLEET="$FLEET"
export LABFORGE_MINIMAL="$MINIMAL"

echo "[labforge] bringing the lab up (windows=$WIN fleet=$FLEET minimal=$MINIMAL)"
echo "[labforge] this pulls community boxes on first run; grab a coffee."
vagrant up

echo
echo "[labforge] lab is up. Try:"
echo "  scripts/lab-status.sh"
echo "  vagrant ssh attacker    # then: cd ~/labforge && ./scan-lab.sh"
echo "  open http://10.20.0.20:8000   # SIEM log viewer"
