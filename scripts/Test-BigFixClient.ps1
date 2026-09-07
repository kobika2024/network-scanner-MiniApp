<#
.SYNOPSIS
    Scans a list of IP addresses / hostnames and reports whether the BigFix
    (IBM BES) Client is installed on each one.

.DESCRIPTION
    Reads targets (one IP address or hostname per line) from a text file and,
    for each target, determines whether the BigFix Client is present using a
    layered check:

      1. Ping reachability (ICMP).
      2. Remote service query for "BESClient" via WMI/CIM (requires admin
         rights on the target - local admin or domain admin credentials).
         This is the authoritative check: Installed / Not Installed.
      3. If the WMI/CIM query cannot be performed (no rights, RPC blocked,
         WinRM/DCOM unavailable, etc.) the script falls back to a TCP probe
         of port 52311, the BigFix Client's default listening port, and
         reports a best-effort "Likely Installed" / "Unknown" verdict.

    Results are printed to the console and exported to a CSV report.

.PARAMETER InputFile
    Path to a .txt file containing one IP address or hostname per line.
    Blank lines and lines starting with '#' are ignored.

.PARAMETER OutputFile
    Path to the CSV report to create. Defaults to BigFixScanResults.csv in
    the current directory.

.PARAMETER Credential
    Credential used for the remote WMI/CIM service query. If omitted, and
    -NoCredentialPrompt is not specified, a graphical username/password
    window pops up at the start of the script to collect it.

.PARAMETER NoCredentialPrompt
    Skip the graphical credential prompt and run the WMI/CIM query under
    the current user's context (or with -Credential, if supplied).

.PARAMETER TimeoutSeconds
    Timeout, in seconds, applied to the ping check, the CIM query and the
    port probe. Default is 3.

.EXAMPLE
    .\Test-BigFixClient.ps1 -InputFile .\servers.txt

.EXAMPLE
    .\Test-BigFixClient.ps1 -InputFile .\servers.txt -OutputFile .\report.csv -NoCredentialPrompt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputFile,

    [string]$OutputFile = ".\BigFixScanResults.csv",

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$NoCredentialPrompt,

    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 3
)

$BigFixServiceName = 'BESClient'
$BigFixClientPort = 52311

if (-not $Credential -and -not $NoCredentialPrompt) {
    $Credential = Get-Credential -Message 'Enter credentials for the remote BigFix Client (WMI) check' -Title 'BigFix Client Scanner'
    if (-not $Credential) {
        Write-Warning 'No credentials supplied - continuing under the current user context.'
    }
}

function Test-BigFixPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutSec)

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $waited = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)
        if (-not $waited) { return $false }
        $client.EndConnect($asyncResult)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Get-BigFixServiceInfo {
    param([string]$ComputerName, [int]$TimeoutSec, [System.Management.Automation.PSCredential]$Cred)

    $cimParams = @{
        ClassName         = 'Win32_Service'
        Filter            = "Name='$BigFixServiceName'"
        ComputerName      = $ComputerName
        OperationTimeoutSec = $TimeoutSec
        ErrorAction       = 'Stop'
    }
    if ($Cred) { $cimParams['Credential'] = $Cred }

    return Get-CimInstance @cimParams
}

$targets = Get-Content -Path $InputFile |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') }

if (-not $targets) {
    Write-Warning "No targets found in '$InputFile'."
    return
}

$results = New-Object System.Collections.Generic.List[object]
$total = $targets.Count
$index = 0

foreach ($target in $targets) {
    $index++
    Write-Progress -Activity 'Scanning for BigFix Client' -Status $target -PercentComplete (($index / $total) * 100)

    $reachable = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue

    $installed = 'Unknown'
    $serviceState = ''
    $startMode = ''
    $method = ''
    $errorMessage = ''

    try {
        $service = Get-BigFixServiceInfo -ComputerName $target -TimeoutSec $TimeoutSeconds -Cred $Credential
        $method = 'WMI/CIM Service Query'
        if ($service) {
            $installed = 'Yes'
            $serviceState = $service.State
            $startMode = $service.StartMode
        }
        else {
            $installed = 'No'
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $portOpen = Test-BigFixPort -ComputerName $target -Port $BigFixClientPort -TimeoutSec $TimeoutSeconds
        if ($portOpen) {
            $installed = 'Likely Yes (port 52311 open, not confirmed)'
            $method = 'TCP Port Probe (fallback)'
        }
        elseif ($reachable) {
            $installed = 'Unknown (no admin access to host)'
            $method = 'TCP Port Probe (fallback)'
        }
        else {
            $installed = 'Unreachable'
            $method = 'Ping'
        }
    }

    $results.Add([PSCustomObject]@{
        Target          = $target
        Reachable       = $reachable
        BigFixInstalled = $installed
        ServiceState    = $serviceState
        StartMode       = $startMode
        CheckMethod     = $method
        Error           = $errorMessage
    })
}

Write-Progress -Activity 'Scanning for BigFix Client' -Completed

$results | Format-Table -AutoSize

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "`nReport saved to: $OutputFile" -ForegroundColor Green

$summary = $results | Group-Object BigFixInstalled | Select-Object Name, Count
Write-Host "`nSummary:" -ForegroundColor Cyan
$summary | Format-Table -AutoSize
