param([switch]$SmokeOpenSSH)

$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'setup.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }

$names = @('Test-PrivateAddress', 'Test-SameSubnet', 'Convert-PublicKey', 'Write-Utf8', 'Set-FileFrom', 'New-KeyFileAcl',
    'Invoke-Native', 'Get-ManagedSshdConfig', 'Initialize-SshdHostKey', 'Start-ManagedSshd')
$definitions = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names
}, $false)
foreach ($definition in $definitions) { . ([ScriptBlock]::Create($definition.Extent.Text)) }

if (-not (Test-PrivateAddress '192.168.1.12') -or (Test-PrivateAddress '172.32.1.1') -or
    (Test-PrivateAddress '192.168.01.12') -or (Test-PrivateAddress '::1')) {
    throw 'Private IPv4 filtering failed.'
}
if (-not (Test-SameSubnet '192.168.1.12' '192.168.1.199' 24) -or
    (Test-SameSubnet '192.168.1.12' '192.168.1.199' 25) -or
    (Test-SameSubnet '192.168.1.12' '192.168.2.12' 24)) {
    throw 'Subnet matching failed.'
}

$key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
$parsed = Convert-PublicKey "$key comment"
if ($parsed.Line -cne $key -or $parsed.Code -cne 'kmYc-vdi2-GkPe-WxB6') {
    throw "Unexpected key code: $($parsed.Code)"
}

if ($env:OS -eq 'Windows_NT') {
    $sidType = [Security.Principal.SecurityIdentifier]
    $adminAcl = New-KeyFileAcl
    $adminRules = @($adminAcl.GetAccessRules($true, $true, $sidType))
    if (-not $adminAcl.AreAccessRulesProtected -or $adminRules.Count -ne 2 -or
        $adminAcl.GetOwner($sidType).Value -ne 'S-1-5-32-544' -or
        @($adminRules | Where-Object { $_.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') }).Count) {
        throw 'Administrator key file ACL must allow only SYSTEM and Administrators.'
    }
    $sid = 'S-1-5-21-1-2-3-1000'
    $standardAcl = New-KeyFileAcl $sid
    $standardRules = @($standardAcl.GetAccessRules($true, $true, $sidType))
    $userRule = $standardRules | Where-Object { $_.IdentityReference.Value -eq $sid }
    if ($standardRules.Count -ne 3 -or -not $userRule -or
        ($userRule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)) {
        throw 'Standard accounts must have read-only access to their key file.'
    }
}

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('winlink-test-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $source = Join-Path $temporary 'source'
    $target = Join-Path $temporary 'target'
    Write-Utf8 $source 'first'
    Set-FileFrom $source $target
    Write-Utf8 $source 'second'
    Set-FileFrom $source $target
    if ([IO.File]::ReadAllText($target) -cne 'second') { throw 'Atomic file replacement failed.' }
    if ($env:OS -eq 'Windows_NT') {
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Set-Acl -LiteralPath $target -AclObject $standardAcl
            Set-Acl -LiteralPath $target -AclObject $adminAcl
            $installedRules = @((Get-Acl -LiteralPath $target).GetAccessRules($true, $true, $sidType))
            if ($installedRules.Count -ne 2 -or $sid -in @($installedRules | ForEach-Object { $_.IdentityReference.Value })) {
                throw 'Removing a previous standard-account key file ACL failed.'
            }
        }
    }
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
Write-Host 'Windows setup script checks passed.'

if ($SmokeOpenSSH) {
    $sshRoot = Join-Path $env:ProgramData 'ssh'
    $sshBin = Join-Path $env:WINDIR 'System32\OpenSSH'
    $configPath = Join-Path $sshRoot 'sshd_config'
    $keysPath = Join-Path $sshRoot 'winlink_smoke_authorized_keys'
    $marker = '# WinLink service startup smoke test'
    $capability = 'OpenSSH.Server~~~~0.0.1.0'
    if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
        Add-WindowsCapability -Online -Name $capability | Out-Null
    }
    $service = Get-Service -Name sshd
    $previousMode = $service.StartType
    $wasRunning = $service.Status -eq 'Running'
    if (Test-Path -LiteralPath $keysPath) { throw 'WinLink smoke key file already exists.' }

    $socket = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $socket.Start()
        $port = $socket.LocalEndpoint.Port
    } finally { $socket.Stop() }

    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('winlink-sshd-test-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $temporary | Out-Null
    $backup = Join-Path $temporary 'original_config'
    $staged = Join-Path $temporary 'sshd_config'
    $stagedKeys = Join-Path $temporary 'authorized_keys'
    $hadConfig = Test-Path -LiteralPath $configPath
    if ($hadConfig) { Copy-Item -LiteralPath $configPath -Destination $backup }
    try {
        if ($wasRunning) { Stop-Service -Name sshd -Force }
        Initialize-SshdHostKey
        $configuration = (Get-ManagedSshdConfig 'winlink-smoke') -replace '(?m)^Port 22\r?$', "Port $port`nListenAddress 127.0.0.1"
        Write-Utf8 $staged $configuration
        Write-Utf8 $stagedKeys $key
        Invoke-Native (Join-Path $sshBin 'sshd.exe') @('-t', '-f', $staged)
        Set-FileFrom $staged $configPath
        Set-FileFrom $stagedKeys $keysPath
        Set-Acl -LiteralPath $keysPath -AclObject (New-KeyFileAcl)
        Invoke-Native (Join-Path $sshBin 'sshd.exe') @('-t', '-f', $configPath)
        Set-Service -Name sshd -StartupType Manual
        Start-ManagedSshd $port
        Write-Host 'The Windows OpenSSH service started with the WinLink configuration.'
    } finally {
        if ((Get-Service -Name sshd).Status -ne 'Stopped') { Stop-Service -Name sshd -Force }
        if (Test-Path -LiteralPath $keysPath) { Remove-Item -LiteralPath $keysPath -Force }
        if ($hadConfig) { Set-FileFrom $backup $configPath }
        elseif (Test-Path -LiteralPath $configPath) { Remove-Item -LiteralPath $configPath -Force }
        Set-Service -Name sshd -StartupType $previousMode
        if ($wasRunning) { Start-Service -Name sshd }
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}
