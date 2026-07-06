<#
.SYNOPSIS
    labforge dependency-free Windows Event Log -> syslog forwarder.

.DESCRIPTION
    Polls the Security event log for new records and ships them to the labforge
    SIEM as RFC3164 syslog over UDP. Pure PowerShell + .NET sockets — no NXLog,
    no Winlogbeat, no internet. Meant for the isolated lab so the blue-team
    log viewer sees Windows failed-logon (4625) and logon (4624) events.

.PARAMETER SiemIp
    IP of the labforge SIEM.

.PARAMETER SiemPort
    UDP syslog port on the SIEM (default 5514).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SiemIp,
    [int]$SiemPort = 5514,
    [int]$PollSeconds = 15
)

$ErrorActionPreference = "Continue"

# Syslog facility*8 + severity. 16=local0, 6=info -> 134.
$priority = 134
$hostname = $env:COMPUTERNAME
$udp = New-Object System.Net.Sockets.UdpClient
$udp.Connect($SiemIp, $SiemPort)

function Send-Syslog {
    param([string]$Message)
    $stamp = (Get-Date).ToString("MMM dd HH:mm:ss")
    $packet = "<$priority>$stamp $hostname labforge: $Message"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($packet)
    [void]$udp.Send($bytes, $bytes.Length)
}

Send-Syslog "windows event forwarder online on $hostname -> $SiemIp`:$SiemPort"

# Track the last record id we forwarded so we don't resend on each poll.
$lastRecordId = 0
$eventIds = 4624, 4625, 4634, 4672   # logon, failed logon, logoff, privileged

while ($true) {
    try {
        $filter = @{ LogName = 'Security'; Id = $eventIds }
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordId -gt $lastRecordId } |
            Sort-Object RecordId
        foreach ($e in $events) {
            $line = "EventID={0} {1}" -f $e.Id, ($e.Message -replace "`r?`n", " ")
            if ($line.Length -gt 900) { $line = $line.Substring(0, 900) }
            Send-Syslog $line
            $lastRecordId = $e.RecordId
        }
    }
    catch {
        Send-Syslog ("forwarder error: {0}" -f $_.Exception.Message)
    }
    Start-Sleep -Seconds $PollSeconds
}
