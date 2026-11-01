"""GUI and CLI entries share behavior; windowed builds have no standard streams."""
import os
from pathlib import Path
import sys
import uuid


def configure_output():
    if sys.stdout is not None and sys.stderr is not None:
        return None
    base = Path(os.environ.get('KSR_STATE_DIR') or Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'KSR')
    folder = base / 'logs'; folder.mkdir(parents=True, exist_ok=True)
    path = folder / ('gui-' + uuid.uuid4().hex + '.log')
    stream = path.open('a', encoding='utf-8', buffering=1)
    if sys.stdout is None: sys.stdout = stream
    if sys.stderr is None: sys.stderr = stream
    return path


def show_startup_error(log):
    import ctypes
    ctypes.windll.user32.MessageBoxW(None, '图形界面启动失败。\n日志：' + str(log or '无法写入日志'), 'KSR 启动失败', 0x10)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    log = None
    try:
        log = configure_output()
        from ksr.__main__ import main as cli_main
        result = cli_main(arguments or ['ui', '--browser'])
        if result and (not arguments or arguments[0] == 'ui'):
            show_startup_error(log)
        return result
    except Exception:
        import traceback
        message = traceback.format_exc()
        if sys.stderr is not None:
            sys.stderr.write(message); sys.stderr.flush()
        if not arguments or arguments[0] == 'ui':
            show_startup_error(log)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
