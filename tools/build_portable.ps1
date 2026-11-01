$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $buildVersion = python -c "from ksr import __version__; print(__version__)"
    if ($LASTEXITCODE -ne 0 -or $buildVersion -notmatch '^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?$') { throw 'Could not determine version' }
    $buildDist = [IO.Path]::GetFullPath((Join-Path $projectRoot "dist/build-$buildVersion"))
    $distRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot 'dist')) + [IO.Path]::DirectorySeparatorChar
    if (-not $buildDist.StartsWith($distRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Build output escaped workspace' }
    $guiDirectory = Join-Path $buildDist 'KSR'
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    python -m ksr build-pack
    if ($LASTEXITCODE -ne 0) { throw 'Rule build failed' }
    python -m PyInstaller --noconfirm --clean --onedir --windowed --name KSR --distpath $buildDist --collect-data ksr tools/ksr_launcher.py
    if ($LASTEXITCODE -ne 0) { throw 'Portable build failed' }
    python -m PyInstaller --noconfirm --clean --onedir --console --name KSR-cli --distpath $buildDist --collect-data ksr tools/ksr_launcher.py
    if ($LASTEXITCODE -ne 0) { throw 'CLI build failed' }
    Copy-Item -LiteralPath (Join-Path $buildDist 'KSR-cli/KSR-cli.exe') -Destination (Join-Path $guiDirectory 'KSR-cli.exe')
    (Get-Content -LiteralPath ksr/README.md -Raw).Replace('(../docs/', '(docs/') | Set-Content -LiteralPath (Join-Path $guiDirectory 'README.md') -Encoding utf8
    Copy-Item -LiteralPath ksr/LICENSE -Destination (Join-Path $guiDirectory 'LICENSE')
    New-Item -ItemType Directory -Path (Join-Path $guiDirectory 'docs') -Force | Out-Null
    Copy-Item -LiteralPath docs/LIMITATIONS.md -Destination (Join-Path $guiDirectory 'docs/LIMITATIONS.md')
    Copy-Item -LiteralPath docs/PROVENANCE.md -Destination (Join-Path $guiDirectory 'docs/PROVENANCE.md')
    python tools/collect_licenses.py $guiDirectory
    if ($LASTEXITCODE -ne 0) { throw 'License collection failed' }
    $archivePath = "dist/KSR-$buildVersion-windows-x64.zip"
    Compress-Archive -Path $guiDirectory -DestinationPath $archivePath -Force
    Get-FileHash -Algorithm SHA256 $archivePath
} finally { Pop-Location }
