$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$probe = "import service`nwith service.database() as c: print(c.execute('SELECT count(*) FROM jobs WHERE status IN (?,?)',('running','cancel_requested')).fetchone()[0])"
while ($true) {
    $result = & docker exec strix-local-api-1 python -c $probe 2>$null
    if ($LASTEXITCODE -eq 0 -and "$result".Trim() -eq '0') { break }
    Start-Sleep -Seconds 2
}
& docker compose --env-file .local.env -f compose.local.yaml up -d --no-deps worker *> (Join-Path $PSScriptRoot 'worker-upgrade.log')
exit $LASTEXITCODE

