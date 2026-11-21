$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'setup.ps1'
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }

$names = @('Test-PrivateAddress', 'Test-SameSubnet', 'Convert-PublicKey', 'Write-Utf8', 'Set-FileFrom')
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
} finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
Write-Host 'Windows setup script checks passed.'
