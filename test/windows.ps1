$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'setup.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }

$names = @('Test-PrivateAddress', 'Test-SameSubnet', 'Convert-PublicKey', 'Write-Utf8', 'Set-FileFrom', 'New-KeyFileAcl')
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
