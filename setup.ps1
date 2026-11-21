param(
    [Parameter(Position = 0)][string]$MacIp,
    [ValidateSet('Install', 'Status', 'Rollback')][string]$Mode = 'Install',
    [string]$CallerSid
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$stateRoot = Join-Path $env:ProgramData 'WinLink'
$original = Join-Path $stateRoot 'original'
$pending = Join-Path $stateRoot 'pending'
$sshRoot = Join-Path $env:ProgramData 'ssh'
$configPath = Join-Path $sshRoot 'sshd_config'
$keysPath = Join-Path $sshRoot 'winlink_authorized_keys'
$sshBin = Join-Path $env:WINDIR 'System32\OpenSSH'
$defaultRule = 'OpenSSH-Server-In-TCP'
$managedRule = 'WinLink-OpenSSH-In'
$capability = 'OpenSSH.Server~~~~0.0.1.0'
$marker = '# Managed by WinLink'

function Test-PrivateAddress([string]$Value) {
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $address.ToString() -cne $Value) { return $false }
    $bytes = $address.GetAddressBytes()
    return $bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -in (16..31)) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
}

function Test-SameSubnet([string]$Local, [string]$Peer, [int]$PrefixLength) {
    $left = [Net.IPAddress]::Parse($Local).GetAddressBytes()
    $right = [Net.IPAddress]::Parse($Peer).GetAddressBytes()
    for ($index = 0; $index -lt 4 -and $PrefixLength -gt 0; $index++) {
        $bits = [Math]::Min($PrefixLength, 8)
        $mask = 256 - [int][Math]::Pow(2, 8 - $bits)
        if (($left[$index] -band $mask) -ne ($right[$index] -band $mask)) { return $false }
        $PrefixLength -= $bits
    }
    return $true
}

function Convert-PublicKey([string]$Line) {
    $match = [regex]::Match($Line.Trim(), '^ssh-ed25519 ([A-Za-z0-9+/]{68})(?:[ \t]+[^\r\n]*)?$')
    if (-not $match.Success) { throw 'Invalid OpenSSH Ed25519 public key.' }
    $wire = [Convert]::FromBase64String($match.Groups[1].Value)
    if ([BitConverter]::ToString($wire, 0, 19) -cne '00-00-00-0B-73-73-68-2D-65-64-32-35-35-31-39-00-00-00-20') {
        throw 'Invalid OpenSSH Ed25519 public key.'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $fingerprint = [Convert]::ToBase64String($sha.ComputeHash($wire))
        $code = $fingerprint.Substring(0, 16) -replace '(.{4})(?=.)', '$1-'
        return @{ Line = 'ssh-ed25519 ' + $match.Groups[1].Value; Code = $code }
    } finally { $sha.Dispose() }
}

function Write-Utf8([string]$Path, [string]$Value) {
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Set-FileFrom([string]$Source, [string]$Destination) {
    $stage = $Destination + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::Copy($Source, $stage)
        if (Test-Path -LiteralPath $Destination) {
            [IO.File]::Replace($stage, $Destination, [NullString]::Value)
        } else {
            [IO.File]::Move($stage, $Destination)
        }
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force }
    }
}

function Invoke-Native([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File exited with code $LASTEXITCODE." }
}

function Set-SetupDirectory {
    if (Test-Path -LiteralPath $stateRoot) {
        $item = Get-Item -LiteralPath $stateRoot -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'WinLink setup directory is a reparse point.'
        }
        $acl = Get-Acl -LiteralPath $stateRoot
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18', 'S-1-5-32-544') -or -not $acl.AreAccessRulesProtected) {
            throw 'WinLink setup directory has unexpected permissions.'
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and
                $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
                throw 'WinLink setup directory has unexpected permissions.'
            }
        }
        return
    }
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security.SetOwner($admins)
    foreach ($sid in @($admins, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    [IO.Directory]::CreateDirectory($stateRoot, $security) | Out-Null
}

function Remove-ManagedFirewallRule {
    $rule = Get-NetFirewallRule -Name $managedRule -ErrorAction SilentlyContinue
    if ($rule) { $rule | Remove-NetFirewallRule }
}

function Add-ManagedFirewallRule([string]$Peer, [string]$Adapter) {
    New-NetFirewallRule -Name $managedRule -DisplayName 'WinLink SSH from the paired Mac' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress $Peer `
        -InterfaceAlias $Adapter -Profile Any -Program (Join-Path $sshBin 'sshd.exe') | Out-Null
}

function Save-Snapshot([string]$Directory) {
    $stage = $Directory + '-' + [guid]::NewGuid().ToString('N')
    New-Item -ItemType Directory -Path $stage | Out-Null
    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'"
        $rule = Get-NetFirewallRule -Name $defaultRule -ErrorAction SilentlyContinue
        $activeRule = Get-NetFirewallRule -Name $managedRule -ErrorAction SilentlyContinue
        $peer = $null
        $adapter = $null
        if ($activeRule) {
            $peer = [string]($activeRule | Get-NetFirewallAddressFilter).RemoteAddress
            $adapter = [string]($activeRule | Get-NetFirewallInterfaceFilter).InterfaceAlias
        }
        foreach ($file in @($configPath, $keysPath)) {
            if (Test-Path -LiteralPath $file) { Copy-Item -LiteralPath $file -Destination $stage }
        }
        $mode = 'Disabled'
        $running = $false
        if ($service) {
            $mode = switch ($service.StartMode) { 'Auto' { 'Automatic' }; 'Manual' { 'Manual' }; default { 'Disabled' } }
            $running = $service.State -eq 'Running'
        }
        Write-Utf8 (Join-Path $stage 'state.json') (@{
            Startup = $mode; Running = $running; DefaultEnabled = $null -ne $rule -and [string]$rule.Enabled -eq 'True'
            MacIp = $peer; Adapter = $adapter
        } | ConvertTo-Json -Compress)
        [IO.Directory]::Move($stage, $Directory)
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
}

function Restore-Snapshot([string]$Directory) {
    $state = Get-Content -LiteralPath (Join-Path $Directory 'state.json') -Raw | ConvertFrom-Json
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') { Stop-Service -Name sshd -Force }

    Remove-ManagedFirewallRule
    foreach ($file in @($configPath, $keysPath)) {
        $saved = Join-Path $Directory ([IO.Path]::GetFileName($file))
        if (Test-Path -LiteralPath $saved) { Set-FileFrom $saved $file }
        elseif (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    }

    $rule = Get-NetFirewallRule -Name $defaultRule -ErrorAction SilentlyContinue
    if ($rule) {
        if ($state.DefaultEnabled) { $rule | Enable-NetFirewallRule }
        else { $rule | Disable-NetFirewallRule }
    }
    if ($state.MacIp) { Add-ManagedFirewallRule $state.MacIp $state.Adapter }
    if ($service) {
        Set-Service -Name sshd -StartupType $state.Startup
        if ($state.Running) { Start-Service -Name sshd }
    }
}

function Get-PairingJson([string]$Method, [string]$Path, [hashtable]$Data = @{}) {
    $url = [uri]("http://${MacIp}:48765" + $Path)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $url)
    try {
        if ($Method -eq 'POST') {
            $request.Content = [Net.Http.StringContent]::new(($Data | ConvertTo-Json -Compress), [Text.Encoding]::UTF8, 'application/json')
        }
        $response = $pairClient.SendAsync($request).GetAwaiter().GetResult()
        try {
            [void]$response.EnsureSuccessStatusCode()
            return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
        } finally { $response.Dispose() }
    } finally { $request.Dispose() }
}

function Show-Status {
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($service) { $service | Format-Table Name, Status, StartType }
    else { Write-Host 'OpenSSH Server is not installed.' }
    Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue |
        Format-Table LocalAddress, LocalPort, OwningProcess
    $rule = Get-NetFirewallRule -Name $managedRule -ErrorAction SilentlyContinue
    if ($rule) {
        $rule | Format-Table Name, Enabled, Profile
        $rule | Get-NetFirewallAddressFilter | Format-Table RemoteAddress
    }
    Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 8 -ErrorAction SilentlyContinue |
        Format-List TimeCreated, LevelDisplayName, Message
}

function Install-WinLink {
    $user = Get-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new($CallerSid))
    if (-not $user.Enabled) { throw 'The selected Windows account is disabled.' }
    $admins = Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    if ($CallerSid -in @($admins | ForEach-Object { $_.SID.Value })) {
        throw 'Sign in to your standard Windows account before running setup.'
    }
    $username = $user.Name.ToLowerInvariant()
    if ($username -notmatch '^[\p{L}\p{N}_. -]{1,20}$' -or $username.StartsWith('-') -or $username.Trim() -cne $username) {
        throw 'This Windows account name cannot be used with WinLink.'
    }

    $networks = @(Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred |
        Where-Object { (Test-PrivateAddress $_.IPAddress) -and
            (Test-SameSubnet $_.IPAddress $MacIp $_.PrefixLength) -and $_.IPAddress -ne $MacIp })
    if ($networks.Count -ne 1) { throw 'Connect both computers to the same Wi-Fi. Only one Windows adapter should reach the Mac IP.' }
    $network = $networks[0]

    foreach ($path in @($sshRoot, $configPath, $keysPath, (Join-Path $sshRoot 'ssh_host_ed25519_key'))) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Unexpected reparse point in OpenSSH setup: $path"
        }
    }
    $owned = Test-Path -LiteralPath $original
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $owned -and ($service -and $service.Status -ne 'Stopped')) {
        throw 'OpenSSH is already running with its own setup. Stop it locally before a fresh WinLink install.'
    }
    if (Test-Path -LiteralPath $configPath) {
        $config = [IO.File]::ReadAllText($configPath)
        $template = Join-Path $sshBin 'sshd_config_default'
        $factory = (Test-Path -LiteralPath $template) -and $config.Trim() -ceq [IO.File]::ReadAllText($template).Trim()
        if (-not ($factory -or ($owned -and $config.StartsWith($marker)))) {
            throw 'Existing OpenSSH configuration is customized. WinLink setup stopped so you can preserve it.'
        }
    }
    if (-not $owned -and ((Test-Path -LiteralPath $keysPath) -or
        (Get-NetFirewallRule -Name $managedRule -ErrorAction SilentlyContinue))) {
        throw 'An existing WinLink key file or firewall rule has no backup. Inspect the previous setup first.'
    }

    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = $false
    $pairClient = [Net.Http.HttpClient]::new($handler)
    $pairClient.Timeout = [TimeSpan]::FromSeconds(5)
    $pairClient.MaxResponseContentBufferSize = 4096
    $stage = Join-Path $stateRoot ([guid]::NewGuid().ToString('N'))
    $pollPath = $null
    try {
        try { $pair = Get-PairingJson 'GET' '/pair/v1' }
        catch { throw "Could not reach the Mac. Run winlink pair on the Mac and check its Wi-Fi or firewall. $($_.Exception.Message)" }
        $nonce = [Guid]::Empty
        if (-not [Guid]::TryParseExact([string]$pair.nonce, 'D', [ref]$nonce)) { throw 'Invalid pairing session.' }
        $clientKey = Convert-PublicKey $pair.clientKey
        Write-Host "Mac key code: $($clientKey.Code)"
        if ((Read-Host 'Does the Mac key code match both screens? [y/N]') -notmatch '^y(es)?$') {
            throw 'Pairing cancelled. No Mac key was installed.'
        }

        Save-Snapshot $pending
        if (-not $owned) { Save-Snapshot $original }
        New-Item -ItemType Directory -Path $stage | Out-Null
        if ((Get-WindowsCapability -Online -Name $capability).State -ne 'Installed') {
            Write-Host 'Installing Windows OpenSSH Server...'
            $install = Add-WindowsCapability -Online -Name $capability
            if ($install.RestartNeeded -or (Get-WindowsCapability -Online -Name $capability).State -ne 'Installed') {
                throw 'Restart Windows if requested, then run the same setup command again. Check Windows Update if installation is unavailable.'
            }
        }
        $rule = Get-NetFirewallRule -Name $defaultRule -ErrorAction SilentlyContinue
        if ($rule) { $rule | Disable-NetFirewallRule }

        if (-not (Test-Path -LiteralPath $sshRoot)) {
            New-Item -ItemType Directory -Path $sshRoot | Out-Null
            Invoke-Native (Join-Path $env:WINDIR 'System32\icacls.exe') @(
                $sshRoot, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)(F)',
                '*S-1-5-32-544:(OI)(CI)(F)', '*S-1-5-11:(RX)')
        }
        Invoke-Native (Join-Path $sshBin 'ssh-keygen.exe') @('-A')
        $hostKey = Convert-PublicKey (Get-Content -LiteralPath (Join-Path $sshRoot 'ssh_host_ed25519_key.pub') -Raw)
        $pollPath = '/pair/v1/' + $nonce.ToString('D')
        Write-Host "Windows key code: $($hostKey.Code)"
        $null = Get-PairingJson 'POST' '/pair/v1' @{ nonce = $nonce.ToString('D'); user = $username; hostKey = $hostKey.Line }
        $deadline = [DateTime]::UtcNow.AddMinutes(3)
        do {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Windows key confirmation timed out.' }
            $approval = Get-PairingJson 'GET' $pollPath
            if ($approval.phase -eq 'verify') { Start-Sleep -Milliseconds 700 }
        } while ($approval.phase -eq 'verify')
        if ($approval.phase -ne 'approved') { throw 'The Mac did not approve the Windows key.' }

        $stagedConfig = Join-Path $stage 'sshd_config'
        $stagedKeys = Join-Path $stage 'winlink_authorized_keys'
        Write-Utf8 $stagedKeys ('from="' + $MacIp + '" ' + $clientKey.Line + "`r`n")
        $absoluteKeyFile = $keysPath.Replace('\', '/')
        $absoluteHostKey = (Join-Path $sshRoot 'ssh_host_ed25519_key').Replace('\', '/')
        Write-Utf8 $stagedConfig @"
$marker
Port 22
AddressFamily inet
HostKey "$absoluteHostKey"
AuthorizedKeysFile "$absoluteKeyFile"
AllowUsers "$username"
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
AllowAgentForwarding no
AllowTcpForwarding no
LogLevel VERBOSE
Subsystem sftp internal-sftp
"@
        Invoke-Native (Join-Path $sshBin 'sshd.exe') @('-t', '-f', $stagedConfig)
        if ((Get-Service -Name sshd).Status -ne 'Stopped') { Stop-Service -Name sshd -Force }
        Set-FileFrom $stagedConfig $configPath
        Set-FileFrom $stagedKeys $keysPath
        Invoke-Native (Join-Path $env:WINDIR 'System32\icacls.exe') @(
            $keysPath, '/inheritance:r', '/grant:r', '*S-1-5-18:(F)', '*S-1-5-32-544:(F)', ('*' + $CallerSid + ':(R)'))
        Invoke-Native (Join-Path $env:WINDIR 'System32\icacls.exe') @($keysPath, '/setowner', '*S-1-5-32-544')
        Remove-ManagedFirewallRule
        Add-ManagedFirewallRule $MacIp $network.InterfaceAlias
        Set-Service -Name sshd -StartupType Automatic
        Start-Service -Name sshd

        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'"
        $isListening = $false
        for ($attempt = 0; $attempt -lt 10 -and -not $isListening; $attempt++) {
            $isListening = [bool](Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.OwningProcess -eq $service.ProcessId })
            if (-not $isListening) { Start-Sleep -Milliseconds 300 }
        }
        if (-not $isListening) { throw 'OpenSSH started without a listener on TCP port 22.' }

        $null = Get-PairingJson 'POST' "$pollPath/ready"
        Remove-Item -LiteralPath $pending -Recurse -Force
        Write-Host "WinLink ready at $($network.IPAddress):22 for $username."
    } catch {
        if ($pollPath) {
            try { $null = Get-PairingJson 'POST' "$pollPath/failed" } catch { }
        }
        if (Test-Path -LiteralPath $pending) {
            Restore-Snapshot $pending
            Remove-Item -LiteralPath $pending -Recurse -Force
            if (-not $owned -and (Test-Path -LiteralPath $original)) { Remove-Item -LiteralPath $original -Recurse -Force }
        }
        throw
    } finally {
        $pairClient.Dispose()
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
}

try {
    if ($Mode -eq 'Status') { Show-Status; exit 0 }
    if ($Mode -eq 'Install' -and -not (Test-PrivateAddress $MacIp)) {
        throw 'Run winlink pair on the Mac, then run setup.cmd MAC_IP on this PC.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $CallerSid) {
        if ($Mode -eq 'Install' -and 'S-1-5-32-544' -in @($identity.Groups | ForEach-Object { $_.Value })) {
            throw 'Run setup from the standard Windows account you want to access.'
        }
        $CallerSid = $identity.User.Value
    }
    if ($CallerSid -notmatch '^S-1-5-21-(?:\d+-){3}\d+$' -and $Mode -eq 'Install') {
        throw 'Run setup from a local Windows user account.'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $params = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'),
            '-Mode', $Mode, '-CallerSid', $CallerSid)
        if ($MacIp) { $params += @('-MacIp', $MacIp) }
        $elevated = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList $params -Wait -PassThru
        exit $elevated.ExitCode
    }

    Set-SetupDirectory
    $lockFile = [IO.File]::Open((Join-Path $stateRoot 'setup.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    try {
        if (Test-Path -LiteralPath $pending) {
            Restore-Snapshot $pending
            Remove-Item -LiteralPath $pending -Recurse -Force
        }
        if ($Mode -eq 'Rollback') {
            if (Test-Path -LiteralPath $original) {
                Restore-Snapshot $original
                Remove-Item -LiteralPath $original -Recurse -Force
                Write-Host 'WinLink settings were rolled back.'
            } else { Write-Host 'No WinLink settings to roll back.' }
        } else {
            Install-WinLink
        }
    } finally { $lockFile.Dispose() }
} catch {
    [Console]::Error.WriteLine("WinLink: $($_.Exception.Message)")
    if ($CallerSid -and -not [Console]::IsInputRedirected) { [void](Read-Host 'Press Enter to close') }
    exit 1
}
