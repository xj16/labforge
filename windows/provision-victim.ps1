<#
.SYNOPSIS
    labforge Windows victim provisioner.

.DESCRIPTION
    Configures the OPT-IN Windows 10 victim inside the isolated host-only lab:
      * sets a predictable hostname
      * enables SMB + RDP so the box is reachable from the Kali attacker
      * creates deliberately-weak local accounts for password-attack practice
      * forwards the Windows Event Log to the labforge SIEM via NXLog-style
        syslog when available, else stages a scheduled task that ships events
      * DISABLES any route off the host-only segment (isolation safety rail)

    This is intentionally insecure. It is safe ONLY because the lab has no route
    to the internet. Never run it on a machine that touches a real network.

.NOTES
    Invoked by Vagrant's shell provisioner:
        provision-victim.ps1 -SiemIp 10.20.0.20
#>
[CmdletBinding()]
param(
    [string]$SiemIp = "10.20.0.20",
    [int]$SiemPort = 5514,
    [string]$Hostname = "victim"
)

$ErrorActionPreference = "Stop"
Write-Host "[labforge] provisioning Windows victim -> SIEM $SiemIp`:$SiemPort"

# ---------------------------------------------------------------------------
# 1. Hostname
# ---------------------------------------------------------------------------
if ($env:COMPUTERNAME -ne $Hostname.ToUpper()) {
    Write-Host "[labforge] renaming host to $Hostname (effective next boot)"
    Rename-Computer -NewName $Hostname -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 2. Reachable services for the attacker: SMB + RDP
# ---------------------------------------------------------------------------
Write-Host "[labforge] enabling SMB and RDP"
# RDP on
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' -Value 0 -ErrorAction SilentlyContinue
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue

# A world-readable share to practice SMB enumeration against.
$sharePath = "C:\labforge-share"
New-Item -ItemType Directory -Path $sharePath -Force | Out-Null
"labforge SMB practice share. Enumerate me from Kali with smbclient/enum4linux." |
    Out-File -FilePath (Join-Path $sharePath "README.txt") -Encoding utf8
if (-not (Get-SmbShare -Name "labshare" -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name "labshare" -Path $sharePath -FullAccess "Everyone" -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 3. Deliberately-weak local accounts (password-attack practice)
# ---------------------------------------------------------------------------
Write-Host "[labforge] creating weak practice accounts"
$weakUsers = @(
    @{ Name = "labuser";  Pass = "Password1" },
    @{ Name = "svc_backup"; Pass = "Summer2026" }
)
foreach ($u in $weakUsers) {
    if (-not (Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue)) {
        $sec = ConvertTo-SecureString $u.Pass -AsPlainText -Force
        New-LocalUser -Name $u.Name -Password $sec -PasswordNeverExpires `
            -AccountNeverExpires -Description "labforge practice account" | Out-Null
        Add-LocalGroupMember -Group "Users" -Member $u.Name -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# 4. Event-log forwarding to the SIEM
# ---------------------------------------------------------------------------
Write-Host "[labforge] configuring event-log forwarding to $SiemIp"
# Enable rich Security auditing so failed logons show up for the blue-team view.
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null

# Ship events as syslog. If NXLog is present we use it; otherwise a scheduled
# task tails the Security log and pushes new failed-logon events over UDP.
$forwarder = Join-Path $PSScriptRoot "eventlog-to-syslog.ps1"
if (Test-Path $forwarder) {
    Write-Host "[labforge] installing scheduled syslog forwarder"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$forwarder`" -SiemIp $SiemIp -SiemPort $SiemPort"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "labforge-syslog" -Action $action -Trigger $trigger `
        -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName "labforge-syslog" -ErrorAction SilentlyContinue
} else {
    Write-Warning "[labforge] eventlog-to-syslog.ps1 not found; skipping forwarder"
}

# ---------------------------------------------------------------------------
# 5. Isolation safety rail — block egress off the lab subnet
# ---------------------------------------------------------------------------
Write-Host "[labforge] applying egress isolation firewall rule"
$labSubnet = "10.20.0.0/24"
New-NetFirewallRule -DisplayName "labforge-block-egress" -Direction Outbound `
    -Action Block -RemoteAddress "Any" -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "labforge-allow-lab" -Direction Outbound `
    -Action Allow -RemoteAddress $labSubnet -ErrorAction SilentlyContinue | Out-Null

Write-Host "[labforge] Windows victim provisioning complete."
Write-Host "[labforge]   SMB share : \\$Hostname\labshare"
Write-Host "[labforge]   Weak users: labuser / svc_backup (see repo docs)"
