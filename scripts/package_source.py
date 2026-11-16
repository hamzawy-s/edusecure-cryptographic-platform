from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1];DEST=ROOT/'submission'/'EduSecure-source.zip'
INCLUDE=['README.md','.env.example','.gitignore','requirements.txt','backend','frontend','scripts','documentation','submission/reports','submission/evidence']
SKIP_DIRS={'.git','node_modules','__pycache__','.pytest_cache','.venv','keys','certificates','storage','temporary'}
SKIP_NAMES={'edusecure.db','EduSecure-source.zip'}
DEST.parent.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(DEST,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=8) as z:
    for rel in INCLUDE:
        base=ROOT/rel
        if not base.exists(): continue
        candidates=[base] if base.is_file() else (p for p in base.rglob('*') if p.is_file())
        for path in candidates:
            relative=path.relative_to(ROOT)
            if any(part in SKIP_DIRS for part in relative.parts) or path.name in SKIP_NAMES: continue
            if path.suffix in {'.pyc','.pyo','.verified'} or path.name.endswith('.db'): continue
            z.write(path,relative.as_posix())
print(DEST)
