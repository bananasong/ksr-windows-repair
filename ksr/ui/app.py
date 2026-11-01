"""启动图形界面。

窗口不在 Python 里画，而是用系统自带的 Chromium 内核以 ``--app`` 模式打开本地页面。
这么选的理由：

* 原程序的界面本来就是 WebView2（样本目录里有 ``webview2loader.dll``、``kdvipgui.dll``），
  用本地页面复刻，CSS 布局能一比一还原，也比 tkinter 好维护得多。
* ``--app`` 模式是独立无地址栏窗口，看起来就是一个桌面程序。
* 不需要 PySide/PyQt/webview 之类上百 MB 的依赖，Edge 在 Win10/11 上必然存在。
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import webbrowser

from . import server


def _wait_for_ui(state, startup_timeout=120, client_timeout=120):
    """Chromium may hand off a window and immediately exit its launch process."""
    started = previous = time.monotonic()
    while True:
        now = time.monotonic()
        # Allow the page to renew its lease after machine sleep / process suspension.
        if now - previous > 15 and state.last_client_seen is not None:
            state.touch_client()
        previous = now
        seen = state.last_client_seen
        if (seen is None and now - started >= startup_timeout) or (seen is not None and now - seen >= client_timeout):
            return
        time.sleep(0.4)


def _find_browser() -> str | None:
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local = os.environ.get("LocalAppData", "")
    cands = [
        os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe"),
        os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
        os.path.join(pf, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(pf86, r"Google\Chrome\Application\chrome.exe"),
        os.path.join(local, r"Google\Chrome\Application\chrome.exe"),
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def run(cfg, width: int = 1120, height: int = 780, browser_only: bool = False,
        serve_only: bool = False) -> int:
    httpd, state = server.make_server(cfg)
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/?t={state.token}"

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    exe = None if (browser_only or serve_only) else _find_browser()
    print(f"KSR 界面已启动：{url}", flush=True)
    print(f"规则包：{len(cfg.rules)} 条脚本 / {len(cfg.groups)} 个分组", flush=True)
    if state.env.get("warnings"):
        for x in state.env["warnings"]:
            print(f"  注意：{x}", flush=True)

    profile = None
    try:
        if serve_only:
            print("仅提供本地服务，未打开窗口。Ctrl+C 退出。", flush=True)
            while True:
                time.sleep(1)
        if exe:
            profile = tempfile.mkdtemp(prefix="ksr-webview-")
            args = [
                exe,
                f"--app={url}",
                f"--window-size={width},{height}",
                f"--user-data-dir={profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-features=Translate,MediaRouter",
                "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding",
                "--disable-backgrounding-occluded-windows",
            ]
            subprocess.Popen(args)
            print("关闭窗口后后台将在约两分钟内退出；Ctrl+C 可立即退出。", flush=True)
            _wait_for_ui(state)
        else:
            if not webbrowser.open(url, new=1, autoraise=True):
                raise RuntimeError('系统默认浏览器未能打开，请检查默认浏览器设置')
            print("已在默认浏览器中打开；关闭页面后后台约两分钟退出。", flush=True)
            _wait_for_ui(state)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=2)
        if profile:
            target = Path(profile).resolve()
            if target.parent == Path(tempfile.gettempdir()).resolve() and target.name.startswith('ksr-webview-'):
                shutil.rmtree(target, ignore_errors=True)
    return 0
