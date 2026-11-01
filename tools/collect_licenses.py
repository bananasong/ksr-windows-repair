"""Copy licenses of the Python runtime and PyInstaller bootloader into a portable build."""
from pathlib import Path
import importlib.metadata
import shutil
import sys

destination = Path(sys.argv[1]) / "licenses"
destination.mkdir(parents=True, exist_ok=True)
python_license = Path(sys.base_prefix) / "LICENSE.txt"
if not python_license.is_file():
    raise SystemExit("Python runtime license was not found")
shutil.copy2(python_license, destination / "Python-LICENSE.txt")
distribution = importlib.metadata.distribution("pyinstaller")
licenses = [distribution.locate_file(f) for f in distribution.files or [] if str(f).endswith("licenses/COPYING.txt")]
if not licenses:
    raise SystemExit("PyInstaller license was not found")
shutil.copy2(licenses[0], destination / "PyInstaller-COPYING.txt")
