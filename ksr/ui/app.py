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
import subprocess
import tempfile
import threading
import time
import webbrowser

from . import server


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

    try:
        if serve_only:
            print("仅提供本地服务，未打开窗口。Ctrl+C 退出。", flush=True)
            while True:
                time.sleep(1)
        if exe:
            profile = os.path.join(tempfile.gettempdir(), "ksr-webview-profile")
            os.makedirs(profile, exist_ok=True)
            args = [
                exe,
                f"--app={url}",
                f"--window-size={width},{height}",
                f"--user-data-dir={profile}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-features=Translate,MediaRouter",
                "--disable-background-timer-throttling",
            ]
            proc = subprocess.Popen(args)
            print("按 Ctrl+C 或关闭窗口退出。", flush=True)
            while proc.poll() is None:
                time.sleep(0.4)
        else:
            webbrowser.open(url)
            print("已在默认浏览器中打开（Ctrl+C 退出）。", flush=True)
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
    return 0
