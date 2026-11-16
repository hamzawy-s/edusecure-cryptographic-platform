$ErrorActionPreference = 'Stop'
$env:EDUSECURE_SECURE_COOKIES = 'false'
python scripts/init_keys.py
$api = Start-Process -FilePath 'python' -ArgumentList @('-m','uvicorn','backend.app.main:app','--host','127.0.0.1','--port','8000') -WorkingDirectory (Get-Location).Path -WindowStyle Hidden -PassThru
try { Push-Location frontend; npm run dev; Pop-Location }
finally { if ($api -and -not $api.HasExited) { Stop-Process -Id $api.Id } }
