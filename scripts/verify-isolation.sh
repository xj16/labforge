#!/usr/bin/env bash
#
# verify-isolation.sh — prove the lab is air-gapped, and mean it.
#
# For each running box (Linux AND the Windows victim) this probes SEVERAL egress
# vectors — not just one curl. A HEALTHY lab FAILS every probe: no route to the
# internet by any path. Any success is a red flag that a NAT interface leaked in
# — stop and investigate before doing anything offensive.
#
# Probes per box:
#   * TCP/443 to two public IPs (1.1.1.1, 8.8.8.8)
#   * DNS resolution of a public name (8.8.8.8:53)
#   * ICMP ping to a public IP
# The Windows victim is probed over WinRM with Test-NetConnection so its
# air-gap — the box most people worry about — is actually proven, not assumed.
#
# Output:
#   * a colored per-box summary on stderr/stdout, and
#   * a machine-readable JSON report (default: isolation-report.json, override
#     with --json PATH or LABFORGE_ISO_REPORT). Consumed by `make verify`.
#
# Exit code is non-zero if ANY box reached the internet by ANY vector, so it is
# safe to use as a gate in CI or lab-up.sh.
#
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

LINUX_BOXES=(attacker siem juice dvwa deb ubuntu fedora arch)
WINDOWS_BOXES=(victim)
REPORT="${LABFORGE_ISO_REPORT:-isolation-report.json}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --json)
      shift
      REPORT="${1:-$REPORT}" ;;
    --json=*) REPORT="${1#--json=}" ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

FAILURES=0
CHECKED=0
JSON_BOXES=""

is_running() {
  vagrant status "$1" 2>/dev/null | grep -q running
}

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# Append one box result to the JSON accumulator.
record() {
  local name="$1" status="$2" detail="$3"
  local sep=""
  [ -n "$JSON_BOXES" ] && sep=","
  JSON_BOXES="${JSON_BOXES}${sep}{\"box\":\"$(json_escape "$name")\",\"status\":\"$status\",\"detail\":\"$(json_escape "$detail")\"}"
}

# The Linux egress probe: returns 0 (and prints which vector) if ANYTHING got
# out. All commands are hard-timed so a hung box can't stall the gate.
# SC2016: the $leak expansions are DELIBERATELY not expanded here — this whole
# string is shipped to the guest and evaluated there by `vagrant ssh -c`.
# shellcheck disable=SC2016
LINUX_PROBE='
leak=""
timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null && leak="tcp443:1.1.1.1"
[ -z "$leak" ] && { timeout 5 bash -c "exec 3<>/dev/tcp/8.8.8.8/443" 2>/dev/null && leak="tcp443:8.8.8.8"; }
[ -z "$leak" ] && { timeout 5 bash -c "exec 3<>/dev/udp/8.8.8.8/53; printf \"\\0\\0\\1\\0\\0\\1\\0\\0\\0\\0\\0\\0\" >&3" 2>/dev/null && leak="dns:8.8.8.8"; }
[ -z "$leak" ] && { timeout 5 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && leak="icmp:1.1.1.1"; }
if [ -n "$leak" ]; then echo "LEAK:$leak"; else echo "BLOCKED"; fi
'

# The Windows egress probe over WinRM/PowerShell.
read -r -d '' WIN_PROBE <<'PS' || true
$leak = $null
foreach ($ip in @("1.1.1.1","8.8.8.8")) {
  try { if ((Test-NetConnection -ComputerName $ip -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet)) { $leak = "tcp443:$ip"; break } } catch {}
}
if (-not $leak) { try { if ((Test-NetConnection -ComputerName 8.8.8.8 -Port 53 -WarningAction SilentlyContinue -InformationLevel Quiet)) { $leak = "dns:8.8.8.8" } } catch {} }
if (-not $leak) { try { if (Test-Connection -Count 1 -Quiet -ComputerName 1.1.1.1 -ErrorAction SilentlyContinue) { $leak = "icmp:1.1.1.1" } } catch {} }
if ($leak) { Write-Output "LEAK:$leak" } else { Write-Output "BLOCKED" }
PS

echo "=== labforge isolation verification ==="
echo "A correctly-isolated lab reports NO internet reachability below."
echo

probe_box() {
  local box="$1" kind="$2" out
  if ! is_running "$box"; then
    printf "  %-8s : (not running, skipped)\n" "$box"
    record "$box" "skipped" "not running"
    return
  fi
  CHECKED=$((CHECKED + 1))
  if [ "$kind" = "windows" ]; then
    out="$(vagrant winrm "$box" -c "$WIN_PROBE" 2>/dev/null \
          || vagrant powershell "$box" -c "$WIN_PROBE" 2>/dev/null)"
  else
    out="$(vagrant ssh "$box" -c "$LINUX_PROBE" 2>/dev/null)"
  fi

  if printf '%s' "$out" | grep -q "LEAK:"; then
    local vec; vec="$(printf '%s' "$out" | grep -o 'LEAK:[^[:space:]]*' | head -1 | cut -d: -f2-)"
    printf "  %-8s : \033[31mLEAK — reached the internet via %s\033[0m\n" "$box" "$vec"
    record "$box" "leak" "$vec"
    FAILURES=$((FAILURES + 1))
  elif printf '%s' "$out" | grep -q "BLOCKED"; then
    printf "  %-8s : \033[32misolated (all egress vectors blocked)\033[0m\n" "$box"
    record "$box" "isolated" "tcp443,dns,icmp all blocked"
  else
    # No clear answer (box unreachable / probe error). Treat as inconclusive,
    # but do NOT pass it off as isolated.
    printf "  %-8s : \033[33mUNKNOWN — could not run probe\033[0m\n" "$box"
    record "$box" "unknown" "probe produced no result"
    FAILURES=$((FAILURES + 1))
  fi
}

for box in "${LINUX_BOXES[@]}"; do probe_box "$box" linux; done
for box in "${WINDOWS_BOXES[@]}"; do probe_box "$box" windows; done

RESULT="pass"
[ "$FAILURES" -gt 0 ] && RESULT="fail"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$REPORT" <<JSON
{
  "tool": "verify-isolation.sh",
  "generated": "$TS",
  "result": "$RESULT",
  "checked": $CHECKED,
  "failures": $FAILURES,
  "boxes": [$JSON_BOXES]
}
JSON

echo
echo "JSON report → $REPORT"
if [ "$CHECKED" -eq 0 ]; then
  echo "NOTE: no boxes were running; nothing to verify."
  exit 0
fi
if [ "$FAILURES" -eq 0 ]; then
  echo "PASS: every running box is isolated. Safe to proceed."
  exit 0
else
  echo "FAIL: $FAILURES box(es) reachable or inconclusive. Do NOT run attacks until fixed."
  exit 1
fi
