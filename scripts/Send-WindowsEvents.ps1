<#
.SYNOPSIS
    Reads Windows event logs and the Windows Firewall log, formats them as
    security events, and sends them to the Security Event Correlator API.

.DESCRIPTION
    Covers rules:
      ssh_brute_force              — Event 4625 (failed logon)
      privilege_escalation         — Event 4624 (successful logon) + Event 4672 (special privileges)
      sensitive_file_access        — Event 4663 (file access — requires Audit Object Access policy)
      port_scan                    — Event 5156 (WFP allowed connection) or Windows Firewall log

    Audit policy requirements (run as Administrator to enable):
      File access:    auditpol /set /subcategory:"File System" /success:enable
      Network conns:  auditpol /set /subcategory:"Filtering Platform Connection" /success:enable

.PARAMETER ApiUrl
    Base URL of the Security Event Correlator API.
    Defaults to the SEC_API_URL environment variable, then http://localhost:8000.

.PARAMETER ApiKey
    API key for authentication.
    Defaults to the SEC_API_KEY environment variable.

.PARAMETER Source
    Name tag applied to every event. Defaults to the machine hostname ($env:COMPUTERNAME).

.PARAMETER HoursBack
    How many hours of log history to process. Default: 24.

.PARAMETER BatchSize
    Number of events per API request. Default: 50.

.EXAMPLE
    $env:SEC_API_KEY = "your-api-key"
    .\scripts\Send-WindowsEvents.ps1

.EXAMPLE
    .\scripts\Send-WindowsEvents.ps1 `
        -ApiUrl  http://192.168.1.50:8000 `
        -ApiKey  "your-api-key" `
        -HoursBack 6
#>

[CmdletBinding()]
param(
    [string] $ApiUrl    = $(if ($env:SEC_API_URL)  { $env:SEC_API_URL  } else { "http://localhost:8000" }),
    [string] $ApiKey    = $(if ($env:SEC_API_KEY)  { $env:SEC_API_KEY  } else { "" }),
    [string] $Source    = $env:COMPUTERNAME,
    [int]    $HoursBack = 24,
    [int]    $BatchSize = 50
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Error "ApiKey is required. Set -ApiKey or the SEC_API_KEY environment variable."
    exit 1
}

$StartTime = (Get-Date).AddHours(-$HoursBack)
Write-Host "Security Event Correlator — Windows event sender" -ForegroundColor Cyan
Write-Host "Source   : $Source"
Write-Host "API      : $ApiUrl"
Write-Host "Looking back $HoursBack hour(s) from $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Write-Host ""

# ── Helpers ───────────────────────────────────────────────────────────────────

function ConvertTo-IsoUtc([datetime] $dt) {
    return $dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Get-XmlField([xml] $EventXml, [string] $FieldName) {
    $node = $EventXml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }
    return if ($node) { $node.'#text' } else { "" }
}

function Send-Batch([array] $Events) {
    if ($Events.Count -eq 0) { return 0 }

    # Remove null-valued keys so the API doesn't receive null user fields.
    $clean = $Events | ForEach-Object {
        $e = @{}
        $_.GetEnumerator() | Where-Object { $null -ne $_.Value } | ForEach-Object { $e[$_.Key] = $_.Value }
        $e
    }
    $payload = ConvertTo-Json $clean -Depth 5 -Compress

    try {
        $response = Invoke-RestMethod `
            -Uri         "$ApiUrl/v1/events/ingest" `
            -Method      POST `
            -ContentType "application/json" `
            -Headers     @{ "X-API-Key" = $ApiKey } `
            -Body        ([System.Text.Encoding]::UTF8.GetBytes($payload))
        return [int]$response.events_ingested
    }
    catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { "N/A" }
        Write-Warning "Batch failed (HTTP $code): $($_.Exception.Message)"
        return 0
    }
}

function Send-AllEvents([System.Collections.Generic.List[hashtable]] $Events) {
    $total   = 0
    $batches = [math]::Ceiling($Events.Count / $BatchSize)
    for ($i = 0; $i -lt $Events.Count; $i += $BatchSize) {
        $end   = [math]::Min($i + $BatchSize - 1, $Events.Count - 1)
        $batch = $Events[$i..$end]
        $sent  = Send-Batch $batch
        $total += $sent
        Write-Verbose "Batch $([math]::Floor($i / $BatchSize) + 1)/$batches : $sent/$($batch.Count) ingested"
    }
    return $total
}

$AllEvents = [System.Collections.Generic.List[hashtable]]::new()

# Helper: skip machine accounts (end with $) and well-known noise accounts.
function IsUserNoise([string] $user) {
    return ($user -match '\$$') -or
           ($user -in @("ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE", "SYSTEM", ""))
}

# ── 1. Failed logons (Event 4625) → login_attempt / failed ───────────────────
# Covers: ssh_brute_force rule
# Source: Windows Security log — always available, no policy change needed.

Write-Host "Parsing Security log: Event 4625 (failed logon)..."
try {
    $evts = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4625; StartTime = $StartTime } `
                         -ErrorAction SilentlyContinue
    $count = 0
    foreach ($evt in $evts) {
        $xml  = [xml]$evt.ToXml()
        $user = Get-XmlField $xml "TargetUserName"
        $ip   = Get-XmlField $xml "IpAddress"
        $port = Get-XmlField $xml "IpPort"
        $type = Get-XmlField $xml "LogonType"

        if (IsUserNoise $user) { continue }

        $details = @{ logon_type = $type }
        if ($ip   -and $ip   -notin @("-", "::1", "127.0.0.1")) { $details["ip"]   = $ip }
        if ($port -and $port -notin @("-", "0"))                  { $details["port"] = [int]$port }

        $AllEvents.Add(@{
            timestamp  = ConvertTo-IsoUtc $evt.TimeCreated
            source     = $Source
            event_type = "login_attempt"
            severity   = "medium"
            user       = $user
            action     = "failed"
            resource   = "/logon"
            details    = $details
            raw_log    = $evt.Message
        })
        $count++
    }
    Write-Host "  Found: $count failed logon events"
}
catch {
    Write-Warning "  Could not read Event 4625 — run as Administrator."
}

# ── 2. Successful logons (Event 4624) → login_attempt / succeeded ─────────────
# Covers: context for privilege_escalation_after_login rule.
# Only network (type 3) and remote interactive / RDP (type 10) logons are
# interesting for attack detection; interactive console logons are too noisy.

Write-Host "Parsing Security log: Event 4624 (successful logon, network/RDP only)..."
try {
    $evts = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4624; StartTime = $StartTime } `
                         -ErrorAction SilentlyContinue
    $count = 0
    foreach ($evt in $evts) {
        $xml  = [xml]$evt.ToXml()
        $user = Get-XmlField $xml "TargetUserName"
        $ip   = Get-XmlField $xml "IpAddress"
        $port = Get-XmlField $xml "IpPort"
        $type = Get-XmlField $xml "LogonType"

        if ($type -notin @("3", "10")) { continue }    # network / RDP only
        if (IsUserNoise $user)         { continue }

        $details = @{ logon_type = $type }
        if ($ip   -and $ip   -notin @("-", "::1", "127.0.0.1")) { $details["ip"]   = $ip }
        if ($port -and $port -notin @("-", "0"))                  { $details["port"] = [int]$port }

        $AllEvents.Add(@{
            timestamp  = ConvertTo-IsoUtc $evt.TimeCreated
            source     = $Source
            event_type = "login_attempt"
            severity   = "low"
            user       = $user
            action     = "succeeded"
            resource   = "/logon"
            details    = $details
            raw_log    = $evt.Message
        })
        $count++
    }
    Write-Host "  Found: $count successful logon events"
}
catch {
    Write-Warning "  Could not read Event 4624 — run as Administrator."
}

# ── 3. Special privileges (Event 4672) → privilege_change ────────────────────
# Covers: privilege_escalation_after_login rule.
# Fires when an account with admin-level privileges logs on. Combined with a
# recent successful logon, the rule engine flags this as post-login escalation.

Write-Host "Parsing Security log: Event 4672 (special privileges assigned)..."
try {
    $evts = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4672; StartTime = $StartTime } `
                         -ErrorAction SilentlyContinue
    $count = 0
    foreach ($evt in $evts) {
        $xml    = [xml]$evt.ToXml()
        $user   = Get-XmlField $xml "SubjectUserName"
        $privs  = (Get-XmlField $xml "PrivilegeList") -replace '\s+', ' '

        if (IsUserNoise $user) { continue }

        $AllEvents.Add(@{
            timestamp  = ConvertTo-IsoUtc $evt.TimeCreated
            source     = $Source
            event_type = "privilege_change"
            severity   = "high"
            user       = $user
            action     = "succeeded"
            resource   = "special_privileges"
            details    = @{ privileges = $privs.Trim() }
            raw_log    = $evt.Message
        })
        $count++
    }
    Write-Host "  Found: $count special-privilege events"
}
catch {
    Write-Warning "  Could not read Event 4672 — run as Administrator."
}

# ── 4. File access (Event 4663) → sensitive_file_access ──────────────────────
# Covers: sensitive_file_access rule.
# Requires Audit Object Access to be enabled:
#   auditpol /set /subcategory:"File System" /success:enable
# AND a SACL on the files/folders you want to monitor.

Write-Host "Parsing Security log: Event 4663 (file access)..."
$SensitivePatterns = @(
    # Linux-style paths (relevant if WSL or MSYS2 is in use)
    "passwd", "shadow", "\.ssh",
    # Windows credential stores
    "\SAM", "\SYSTEM", "\SECURITY", "ntds.dit",
    # Private key material
    "id_rsa", "id_ed25519", "\.bash_history", "authorized_keys"
)
try {
    $evts = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4663; StartTime = $StartTime } `
                         -ErrorAction SilentlyContinue
    $count = 0
    foreach ($evt in $evts) {
        $xml     = [xml]$evt.ToXml()
        $user    = Get-XmlField $xml "SubjectUserName"
        $objName = Get-XmlField $xml "ObjectName"
        $proc    = Get-XmlField $xml "ProcessName"

        if ([string]::IsNullOrWhiteSpace($objName)) { continue }
        if (IsUserNoise $user)                       { continue }

        $isSensitive = $SensitivePatterns | Where-Object { $objName -like "*$_*" }
        if (-not $isSensitive) { continue }

        $AllEvents.Add(@{
            timestamp  = ConvertTo-IsoUtc $evt.TimeCreated
            source     = $Source
            event_type = "file_access"
            severity   = "high"
            user       = $user
            action     = "succeeded"
            resource   = $objName
            details    = @{ process = $proc }
            raw_log    = $evt.Message
        })
        $count++
    }
    Write-Host "  Found: $count sensitive file-access events"
}
catch {
    Write-Host "  Event 4663 not available — enable with:" -ForegroundColor Yellow
    Write-Host "    auditpol /set /subcategory:`"File System`" /success:enable" -ForegroundColor Yellow
}

# ── 5. Network connections (Event 5156) → network_connection ─────────────────
# Covers: port_scan rule.
# Requires Windows Filtering Platform auditing:
#   auditpol /set /subcategory:"Filtering Platform Connection" /success:enable

Write-Host "Parsing Security log: Event 5156 (WFP network connection)..."
try {
    $evts = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 5156; StartTime = $StartTime } `
                         -ErrorAction SilentlyContinue
    $count = 0
    foreach ($evt in $evts) {
        $xml     = [xml]$evt.ToXml()
        $srcIp   = Get-XmlField $xml "SourceAddress"
        $dstIp   = Get-XmlField $xml "DestAddress"
        $dstPort = Get-XmlField $xml "DestPort"
        $proto   = Get-XmlField $xml "Protocol"
        $app     = Get-XmlField $xml "Application"

        # Skip loopback
        if ($srcIp -in @("127.0.0.1", "::1") -and $dstIp -in @("127.0.0.1", "::1")) { continue }

        $details = @{ src_ip = $srcIp; dst_ip = $dstIp; protocol = $proto; process = $app }
        if ($dstPort -match '^\d+$') { $details["destination_port"] = [int]$dstPort }

        $AllEvents.Add(@{
            timestamp  = ConvertTo-IsoUtc $evt.TimeCreated
            source     = $Source
            event_type = "network_connection"
            severity   = "low"
            user       = $null
            action     = "succeeded"
            resource   = "${dstIp}:${dstPort}"
            details    = $details
            raw_log    = $evt.Message
        })
        $count++
    }
    Write-Host "  Found: $count network-connection events"
}
catch {
    Write-Host "  Event 5156 not available — enable with:" -ForegroundColor Yellow
    Write-Host "    auditpol /set /subcategory:`"Filtering Platform Connection`" /success:enable" -ForegroundColor Yellow
}

# ── 5b. Windows Firewall log (fallback for network_connection) ────────────────
# The firewall log file is easier to access than Event 5156 and requires no
# audit policy change; it just needs the log to be enabled in Windows Defender
# Firewall Advanced Settings → Properties → Logging.

$FwLog = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
if (Test-Path $FwLog) {
    Write-Host "Parsing Windows Firewall log ($FwLog)..."
    $count = 0
    try {
        Get-Content $FwLog -ErrorAction SilentlyContinue |
            Where-Object { $_ -notmatch "^#" } |
            ForEach-Object {
                # Fields: date time action protocol src-ip dst-ip src-port dst-port ...
                $parts = $_ -split "\s+"
                if ($parts.Count -lt 8) { return }

                $dateStr = "$($parts[0]) $($parts[1])"
                try   { $ts = [datetime]::Parse($dateStr) } catch { return }
                if ($ts -lt $StartTime) { return }

                $action  = $parts[2]
                $proto   = $parts[3]
                $srcIp   = $parts[4]
                $dstIp   = $parts[5]
                $dstPort = $parts[7]

                $details = @{ src_ip = $srcIp; dst_ip = $dstIp; protocol = $proto }
                if ($dstPort -match '^\d+$') { $details["destination_port"] = [int]$dstPort }

                $AllEvents.Add(@{
                    timestamp  = ConvertTo-IsoUtc $ts
                    source     = $Source
                    event_type = "network_connection"
                    severity   = "low"
                    user       = $null
                    action     = if ($action -eq "ALLOW") { "succeeded" } else { "failed" }
                    resource   = "${dstIp}:${dstPort}"
                    details    = $details
                })
                $count++
            }
        Write-Host "  Found: $count firewall log entries"
    }
    catch {
        Write-Warning "  Could not read firewall log: $_"
    }
}
else {
    Write-Host "  Firewall log not found at $FwLog" -ForegroundColor Yellow
    Write-Host "  Enable in: Windows Defender Firewall → Advanced Settings → Properties → Logging" -ForegroundColor Yellow
}

# ── Send all events ───────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Total events parsed: $($AllEvents.Count)"

if ($AllEvents.Count -eq 0) {
    Write-Warning "No events found. Check you are running as Administrator and the time range is correct."
    exit 0
}

# Sort chronologically so the rules engine sees events in arrival order.
$sorted = [System.Collections.Generic.List[hashtable]]($AllEvents | Sort-Object { [datetime]$_.timestamp })

Write-Host "Sending to $ApiUrl ..."
$ingested = Send-AllEvents $sorted

$color = if ($ingested -gt 0) { "Green" } else { "Red" }
Write-Host "Ingested: $ingested / $($AllEvents.Count) events accepted by API" -ForegroundColor $color
