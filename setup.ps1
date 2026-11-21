param(
    [Parameter(Position = 0)][string]$MacIp,
    [switch]$PairAgain,
    [switch]$OpenFirewall
)

$ErrorActionPreference = 'Stop'
try {
    $address = $null
    if (-not [Net.IPAddress]::TryParse($MacIp, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -cne $MacIp) {
        throw 'Usage: setup.cmd MAC_IP [-PairAgain] [-OpenFirewall]'
    }
    $bytes = $address.GetAddressBytes()
    if (-not ($bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -in (16..31)) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or ($bytes[0] -eq 100 -and $bytes[1] -in (64..127)) -or
        $MacIp -eq '127.0.0.1')) { throw 'Use the private IPv4 address of the Mac.' }

    $node = (Get-Command node.exe -CommandType Application | Select-Object -First 1).Source
    if ([int](& $node -p 'parseInt(process.versions.node,10)') -lt 22) { throw 'WinLink requires Node.js 22 or later.' }
    Set-Location -LiteralPath $PSScriptRoot
    if (-not (Test-Path -LiteralPath 'node_modules\selfsigned\package.json')) {
        & npm.cmd ci --omit=dev --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'Could not install the WinLink dependency.' }
    }

    $state = Join-Path $env:LOCALAPPDATA 'WinLink'
    $marker = Join-Path $state 'firewall-https.txt'
    $firewall = "$MacIp $node"
    $current = if (Test-Path -LiteralPath $marker) { Get-Content -LiteralPath $marker -Raw }
    if ($MacIp -ne '127.0.0.1' -and ($OpenFirewall -or $current -cne $firewall)) {
        $escapedNode = $node.Replace("'", "''")
        $script = @"
`$ErrorActionPreference = 'Stop'
try {
    `$rule = Get-NetFirewallRule -Name 'WinLink-HTTPS-In' -ErrorAction SilentlyContinue
    if (`$rule) {
        Set-NetFirewallRule -Name 'WinLink-HTTPS-In' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 48766 -RemoteAddress '$MacIp' -Program '$escapedNode' -Profile Any -Enabled True
    } else {
        New-NetFirewallRule -Name 'WinLink-HTTPS-In' -DisplayName 'WinLink HTTPS from the Mac' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 48766 -RemoteAddress '$MacIp' -Program '$escapedNode' -Profile Any | Out-Null
    }
    exit 0
} catch {
    Write-Host `$_.Exception.Message
    exit 1
}
"@
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
        $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw 'Could not configure the WinLink HTTPS firewall rule.' }
        New-Item -ItemType Directory -Path $state -Force | Out-Null
        [IO.File]::WriteAllText($marker, $firewall)
    }

    $arguments = @((Join-Path $PSScriptRoot 'windows\agent.mjs'), $MacIp)
    if ($PairAgain) { $arguments += '--pair-again' }
    & $node @arguments
    exit $LASTEXITCODE
} catch {
    [Console]::Error.WriteLine("WinLink: $($_.Exception.Message)")
    exit 1
}
