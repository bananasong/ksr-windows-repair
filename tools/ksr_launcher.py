"""PyInstaller entry: opening the binary without arguments opens the application."""
import sys
from ksr.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["ui"]))
