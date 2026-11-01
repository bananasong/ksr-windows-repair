"""Build a publishable source tree by allowlist; never copy local research or user data."""
from pathlib import Path
import hashlib
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ksr import __version__
destination = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "release/ksr-windows-repair"
if destination == ROOT or ROOT not in destination.parents:
    raise SystemExit("The staging tree must be a child of this workspace")
destination.mkdir(parents=True, exist_ok=True)
allowed = ["pyproject.toml", ".gitignore", ".gitattributes", ".github/workflows/windows.yml",
           "docs/LIMITATIONS.md", "docs/PROVENANCE.md", "tools/ksr_launcher.py",
           "tools/build_portable.ps1", "tools/collect_licenses.py", "tools/export_source.py"]
for folder in ("ksr", "tests"):
    for path in (ROOT / folder).rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and (path.suffix in {
                ".py", ".json", ".ksrp", ".html", ".css", ".js", ".cmd"} or path.name in {"LICENSE", "README.md"}):
            allowed.append(path.relative_to(ROOT).as_posix())
for name in sorted(set(allowed)):
    path = destination / name
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / name, path)
(destination / "README.md").write_text((ROOT / "ksr/README.md").read_text(encoding="utf-8").replace(
    "(../docs/", "(docs/"), encoding="utf-8")
shutil.copy2(ROOT / "ksr/LICENSE", destination / "LICENSE")
files = [destination / name for name in sorted(set(allowed))] + [destination / "README.md", destination / "LICENSE"]
for path in files:
    if path.suffix.lower() in {".lua", ".dll", ".exe", ".reg", ".dmp"}:
        raise SystemExit("Non-product artifact rejected: " + str(path))
manifest = "\n".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(destination).as_posix()}" for p in files) + "\n"
(destination / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")
files.append(destination / "MANIFEST.sha256")
archive = ROOT / f"dist/KSR-{__version__}-source.zip"
archive.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as stream:
    for path in files:
        stream.write(path, f"KSR-{__version__}/" + path.relative_to(destination).as_posix())
print(f"Staged {len(files)} files: {destination}")
print(f"Source archive: {archive}")
