$ErrorActionPreference = 'Stop'
$env:EDUSECURE_SECURE_COOKIES = 'true'
python scripts/init_keys.py
if (-not (Test-Path 'frontend/dist/index.html')) { Push-Location frontend; npm run build; Pop-Location }
python scripts/serve_https.py
