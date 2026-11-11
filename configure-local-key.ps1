$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
Write-Host 'Your submitted scan jobs send code and test results to SiliconFlow and incur API charges.'
Write-Host 'The software USD 0.50 estimate is not a provider-side hard spending cap.'
$consent = Read-Host 'Type YES to enable paid scans submitted by you'
if ($consent -ne 'YES') { exit }
$secureKey = Read-Host 'SiliconFlow API Key (hidden)' -AsSecureString
$keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try {
    $plainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)
    if ([string]::IsNullOrWhiteSpace($plainKey)) { throw 'Empty API Key' }
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'secrets/llm-key.txt'), $plainKey.Trim(), [Text.UTF8Encoding]::new($false))
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer)
    $plainKey = $null
}
$localConfig = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '.local.env'))
$localConfig = $localConfig -replace '(?m)^ENABLE_SCANS=.*$', 'ENABLE_SCANS=true'
[IO.File]::WriteAllText((Join-Path $PSScriptRoot '.local.env'), $localConfig, [Text.UTF8Encoding]::new($false))
docker compose --env-file .local.env -f compose.local.yaml up -d --force-recreate api worker
if ($LASTEXITCODE -ne 0) { throw 'Container startup failed' }
Write-Host 'Enabled. Open http://127.0.0.1:8080/docs . No scan has been submitted automatically.'
