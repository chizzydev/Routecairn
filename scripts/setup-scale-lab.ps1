$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot -Parent
$labRoot = Join-Path $repository '.routecairn-scale-lab'
$toolRoot = Join-Path $labRoot 'tools'
New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
function Get-VerifiedArchive($Url, $Name, $Sha256) {
    $destination = Join-Path $toolRoot $Name
    if (-not (Test-Path -LiteralPath $destination)) { Invoke-WebRequest -Uri $Url -OutFile $destination }
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Sha256) { throw "Archive checksum rejected: $Name" }
    return $destination
}
$postgresArchive = Get-VerifiedArchive 'https://get.enterprisedb.com/postgresql/postgresql-17.11-3-windows-x64-binaries.zip' 'postgresql.zip' '4b8db0930c38f6ef845db919551dedda3b6b845aeb0927b3d79a6e8e9e4537cf'
if (-not (Test-Path -LiteralPath (Join-Path $toolRoot 'postgresql/pgsql/bin/postgres.exe'))) { Expand-Archive -LiteralPath $postgresArchive -DestinationPath (Join-Path $toolRoot 'postgresql') }
$goArchive = Get-VerifiedArchive 'https://go.dev/dl/go1.25.1.windows-amd64.zip' 'go.zip' '4a974de310e7ee1d523d2fcedb114ba5fa75408c98eb3652023e55ccf3fa7cab'
if (-not (Test-Path -LiteralPath (Join-Path $toolRoot 'go/bin/go.exe'))) { Expand-Archive -LiteralPath $goArchive -DestinationPath $toolRoot }
$collectorArchive = Get-VerifiedArchive 'https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.135.0/otelcol-contrib_0.135.0_windows_amd64.tar.gz' 'otel.tar.gz' '1f62ac108461aa381a8af298115f59c7e6400f3501f9ce359268641c01f44d35'
if (-not (Test-Path -LiteralPath (Join-Path $toolRoot 'otelcol-contrib.exe'))) { tar -xzf $collectorArchive -C $toolRoot; if ($LASTEXITCODE -ne 0) { throw 'Collector extraction failed' } }
# Keep Go caches and Python packages confined to the disposable lab.
$env:GOBIN = $toolRoot
$env:GOPATH = Join-Path $labRoot 'go-cache'
$env:GOCACHE = Join-Path $labRoot 'go-build-cache'
& (Join-Path $toolRoot 'go/bin/go.exe') install -trimpath github.com/minio/minio@v0.0.0-20250907161309-07c3a429bfed
if ($LASTEXITCODE -ne 0) { throw 'Pinned MinIO source build failed' }
python -m pip install --target (Join-Path $labRoot 'python') 'moto[server]==5.1.12'
if ($LASTEXITCODE -ne 0) { throw 'Moto installation failed' }
Write-Output 'Native scale lab tools ready. Acceptance creates fresh loopback services and stops them after execution.'
