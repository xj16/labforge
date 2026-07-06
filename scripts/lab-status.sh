#!/usr/bin/env bash
#
# lab-status.sh — show the state of every labforge machine and quick-hit URLs.
#
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== labforge machine status ==="
vagrant status || true

cat <<'EOF'

=== Endpoints (once provisioned) ===
  Attacker (Kali)     ssh: vagrant ssh attacker
  SIEM log viewer     http://10.20.0.20:8000
  OWASP Juice Shop    http://10.20.0.31:3000
  DVWA                http://10.20.0.32/         (admin / password)
  Windows victim      \\10.20.0.40\labshare      (opt-in)

=== Handy commands ===
  Recon from Kali     vagrant ssh attacker -c 'cd ~/labforge && ./scan-lab.sh'
  Verify isolation    scripts/verify-isolation.sh
  Tear it all down    vagrant destroy -f
EOF
