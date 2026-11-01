$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    python -m ksr build-pack
    if ($LASTEXITCODE -ne 0) { throw 'Rule build failed' }
    python -m PyInstaller --noconfirm --clean --onedir --console --name KSR --collect-data ksr tools/ksr_launcher.py
    if ($LASTEXITCODE -ne 0) { throw 'Portable build failed' }
    (Get-Content -LiteralPath ksr/README.md -Raw).Replace('(../docs/', '(docs/') | Set-Content -LiteralPath dist/KSR/README.md -Encoding utf8
    Copy-Item -LiteralPath ksr/LICENSE -Destination dist/KSR/LICENSE
    New-Item -ItemType Directory -Path dist/KSR/docs -Force | Out-Null
    Copy-Item -LiteralPath docs/LIMITATIONS.md -Destination dist/KSR/docs/LIMITATIONS.md
    Copy-Item -LiteralPath docs/PROVENANCE.md -Destination dist/KSR/docs/PROVENANCE.md
    python tools/collect_licenses.py dist/KSR
    if ($LASTEXITCODE -ne 0) { throw 'License collection failed' }
    $buildVersion = python -c "from ksr import __version__; print(__version__)"
    if ($LASTEXITCODE -ne 0) { throw 'Could not determine version' }
    $archivePath = "dist/KSR-$buildVersion-windows-x64.zip"
    Compress-Archive -Path dist/KSR -DestinationPath $archivePath -Force
    Get-FileHash -Algorithm SHA256 $archivePath
} finally { Pop-Location }
