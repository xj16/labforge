#!/usr/bin/env bash
#
# verify-isolation.sh — prove the lab is air-gapped.
#
# For each running Linux box, attempts to reach the internet. A HEALTHY lab
# FAILS every one of these checks (that's the point). Any success is a red flag
# that a NAT interface leaked in — investigate before doing anything offensive.
#
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

BOXES=(attacker siem juice dvwa deb ubuntu fedora arch)
FAILURES=0

echo "=== labforge isolation verification ==="
echo "A correctly-isolated lab should report NO internet reachability below."
echo

for box in "${BOXES[@]}"; do
  # Skip boxes that aren't up.
  if ! vagrant status "$box" 2>/dev/null | grep -q running; then
    printf "  %-8s : (not running, skipped)\n" "$box"
    continue
  fi

  # Try to reach a public host with a hard 5s timeout.
  if vagrant ssh "$box" -c \
       'timeout 5 curl -s -o /dev/null -m 5 https://1.1.1.1 && echo REACHED || echo BLOCKED' \
       2>/dev/null | grep -q REACHED; then
    printf "  %-8s : \033[31mLEAK — reached the internet!\033[0m\n" "$box"
    FAILURES=$((FAILURES + 1))
  else
    printf "  %-8s : \033[32misolated (internet blocked)\033[0m\n" "$box"
  fi
done

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "PASS: every running box is isolated. Safe to proceed."
  exit 0
else
  echo "FAIL: $FAILURES box(es) can reach the internet. Do NOT run attacks until fixed."
  exit 1
fi
