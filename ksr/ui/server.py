"""界面服务层：本地 HTTP + NDJSON 流式接口。

设计取舍：
* 只用标准库（``http.server``），不引入 Flask/Electron —— 与 KSR 引擎「零依赖」
  的定位一致，clone 下来就能跑。
* 只绑 ``127.0.0.1``，并给每次会话发一个随机 token；所有 ``/api/*`` 都校验它，
  防止本机其他网页跨站触发「一键优化」这种会写系统的动作。
* 扫描与修复都用 NDJSON 逐行推送进度，界面拿到一条就画一条，
  不必等整轮跑完（原程序也是按脚本逐条回填进度的）。
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .. import __version__, engine, win32api as w

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

# 左栏导航。groups 为 None 表示「综合检测」——聚合全部脚本。
NAV = [
    {"id": "all",     "label": "综合检测",     "icon": "scan",     "groups": None},
    {"id": "dll",     "label": "DLL 文件",     "icon": "dll",      "groups": ["dll"]},
    {"id": "runtime", "label": "常用运行库",   "icon": "runtime",  "groups": ["runtime"]},
    {"id": "sysopt",  "label": "系统优化",     "icon": "optimize",
     # 前 11 组 = ksduicfgz.dat 里 <solution id="5072" title="系统优化"> 的 11 个 item，
     # 顺序照抄原配置；后面几组是本项目补充的系统故障检测，一并归到本页展示。
     "groups": ["sysopt_svc", "sysopt_sysset", "sysopt_priv", "sysopt_taskbar",
                "sysopt_deskicon", "sysopt_menu", "sysopt_explorer", "sysopt_udisk",
                "sysopt_camera", "sysopt_gpu", "sysopt_mouse",
                "svc", "sys", "crash", "desk", "udisk"]},
    {"id": "audio",   "label": "电脑声音",     "icon": "audio",    "groups": ["audio"]},
    {"id": "game",    "label": "游戏必备组件", "icon": "game",     "groups": ["game"]},
    {"id": "slow",    "label": "电脑卡慢",     "icon": "slow",     "groups": ["perf", "slow_boot"]},
    {"id": "print",   "label": "打印机问题",   "icon": "printer",  "groups": ["print"]},
    {"id": "manual",  "label": "手动修复",     "icon": "manual",   "groups": ["manual"]},
]

NAV_BY_ID = {n["id"]: n for n in NAV}


class State:
    """单个进程内的会话状态。"""

    def __init__(self, cfg):
        self.cfg = cfg
        self.token = secrets.token_urlsafe(16)
        self.lock = threading.Lock()
        self.last: dict[str, dict] = {}      # group -> 该组最近一次扫描结果
        self.env: dict = {}
        self.last_client_seen: float | None = None

    def touch_client(self):
        self.last_client_seen = time.monotonic()

    def groups_for(self, nav_id: str) -> list[str]:
        nav = NAV_BY_ID.get(nav_id) or NAV_BY_ID["all"]
        return list(nav["groups"]) if nav["groups"] else list(self.cfg.sequence)

    def counts(self) -> dict[str, dict]:
        """每个导航项的条目数（= 参与检测的脚本数）。"""
        out = {}
        for nav in NAV:
            gs = nav["groups"] or list(self.cfg.sequence)
            n = sum(1 for r in self.cfg.rules.values() if r.group in gs)
            out[nav["id"]] = {"items": n}
        return out


def _finding_payload(f) -> dict:
    return f.to_dict()


class Handler(BaseHTTPRequestHandler):
    state: State = None  # 由 make_server 注入
    server_version = "KSR-UI/1.0"

    # ------------------------------------------------------------ 基础工具
    def log_message(self, fmt, *args):  # 静默，避免刷控制台
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return self.wfile

    def _emit(self, wf, obj):
        wf.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
        wf.flush()

    def _authed(self) -> bool:
        tok = self.headers.get("X-KSR-Token", "")
        expected = f"127.0.0.1:{self.server.server_address[1]}"
        origin = self.headers.get("Origin")
        if (secrets.compare_digest(tok, self.state.token) and self.headers.get("Host") == expected
                and (not origin or origin == "http://" + expected)):
            self.state.touch_client()
            return True
        self._json({"error": "token 无效"}, 403)
        return False

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > 65536:
                raise ValueError("请求大小超限")
            value = json.loads(self.rfile.read(n) or b"{}")
            return value if isinstance(value, dict) else {}
        except (ValueError, json.JSONDecodeError):
            return {}

    # ------------------------------------------------------------ 路由
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path == "/favicon.ico":
            return self._send(204, b"", "image/x-icon")
        if path == "/" or path == "/index.html":
            return self._index()
        if path in ("/app.css", "/app.js"):
            return self._static(path.lstrip("/"))
        if path == "/api/bootstrap":
            if not self._authed():
                return
            return self._json(self._bootstrap())
        if path == '/api/heartbeat':
            if not self._authed():
                return
            return self._json({'ok': True})
        if path == "/api/history":
            if not self._authed():
                return
            from ..journal import history
            return self._json(history())
        if path == "/api/scan":
            if not self._authed():
                return
            nav = (parse_qs(u.query).get("nav") or ["all"])[0]
            return self._scan(nav)
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path in ("/api/diagnose", "/api/undo", "/api/dotnet/plan", "/api/dotnet/install"):
            if not self._authed():
                return
            body = self._body()
            try:
                with self.state.lock:
                    if u.path == "/api/diagnose":
                        from ..diagnose import inspect
                        return self._json(inspect(body.get("path", "")))
                    if u.path.startswith('/api/dotnet/'):
                        from .. import dotnet
                        path, architecture, directory = body.get('path', ''), body.get('architecture'), body.get('install_dir')
                        if u.path.endswith('/plan'):
                            result = dotnet.plan_for_app(path, architecture, directory, 'private' if directory else 'system')
                        else:
                            if body.get('confirm') is not True:
                                raise ValueError('需明确确认后才能安装')
                            if not isinstance(body.get('expected_packages'), list):
                                raise ValueError('请先生成并确认安装计划')
                            result = dotnet.install_for_app(path, architecture, directory, body['expected_packages'])
                        return self._json(result)
                    from ..journal import undo
                    return self._json(undo(body.get("id", "")))
            except (OSError, ValueError, TypeError) as exc:
                return self._json({"error": str(exc)}, 400)
        if u.path == "/api/fix":
            if not self._authed():
                return
            return self._fix(self._body())
        if u.path == "/api/open":
            if not self._authed():
                return
            url = (self._body() or {}).get("url", "")
            if url.startswith(("https://", "http://")):
                webbrowser.open(url)
                return self._json({"ok": True})
            return self._json({"ok": False, "error": "只允许 http(s) 链接"}, 400)
        self._json({"error": "not found"}, 404)

    # ------------------------------------------------------------ 静态资源
    def _static(self, name: str):
        p = os.path.join(WEB_DIR, name)
        if not os.path.isfile(p):
            return self._json({"error": "missing " + name}, 404)
        ctype = {"index.html": "text/html; charset=utf-8",
                 "app.css": "text/css; charset=utf-8",
                 "app.js": "application/javascript; charset=utf-8"}[name]
        with open(p, "rb") as f:
            self._send(200, f.read(), ctype)

    def _index(self):
        """首页：先把全量扫描跑完，把结果内联进 HTML 再回。

        好处是打开窗口时界面已经是「检测完成」的状态，不会先闪一下空列表；
        代价是首屏多等约一秒。让页面自己去扫也能做，但那样每次打开都要
        经历一次空窗，体验更差。
        """
        st = self.state
        if (parse_qs(urlparse(self.path).query).get("t") or [""])[0] != st.token:
            return self._json({"error": "请使用启动器提供的会话链接"}, 403)
        st.touch_client()
        if self.headers.get("Host") != f"127.0.0.1:{self.server.server_address[1]}":
            return self._json({"error": "Host 无效"}, 403)
        with st.lock:
            eng = engine.Engine(st.cfg, dry_run=True)
            env = eng.run_global()
            st.env = {"admin": env["admin"], "os": env["os"],
                      "cpu": env["cpu"], "warnings": env["warnings"]}
            scan = eng.run_scan()
            findings = [f.to_dict() for f in scan["findings"]]
            preload = {
                "findings": findings,
                "passed": scan["passed"],
                "scanned": scan["scanned"],
                "elapsed_ms": scan["elapsed_ms"],
            }
        with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as f:
            html = f.read()
        inject = ("<script>window.__KSR_PRELOAD__ = "
                  + json.dumps(preload, ensure_ascii=False).replace("<", "\\u003c")
                  + ";</script>\n")
        html = html.replace('<script src="/app.js"></script>',
                            inject + '<script src="/app.js"></script>')
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    # ------------------------------------------------------------ 业务
    def _bootstrap(self) -> dict:
        st = self.state
        nav = []
        for n in NAV:
            gs = n["groups"] or list(st.cfg.sequence)
            types = [st.cfg.group_of(g).get("title", g) for g in gs]
            nav.append({**n, "items": sum(1 for r in st.cfg.rules.values()
                                          if r.group in gs), "titles": types})
        return {
            "version": __version__,
            "token": st.token,
            "nav": nav,
            # 分组元数据：界面上「系统优化」的两组标题直接取自这里
            "groups": [{"id": g["id"], "title": g.get("title", g["id"]),
                        "desc": g.get("desc", ""), "order": g.get("order", 999)}
                       for g in st.cfg.groups.values()],
            "env": st.env,
            "rulepack": {"scripts": len(st.cfg.rules), "groups": len(st.cfg.groups),
                         "build": st.cfg.build},
        }

    def _scan(self, nav_id: str):
        st = self.state
        with st.lock:
            groups = st.groups_for(nav_id)
            eng = engine.Engine(st.cfg, dry_run=True)
            wf = self._stream()
            env = eng.run_global()
            st.env = {"admin": env["admin"], "os": env["os"],
                      "cpu": env["cpu"], "warnings": env["warnings"]}
            total = sum(1 for r in st.cfg.rules.values() if r.group in groups)
            self._emit(wf, {"type": "start", "nav": nav_id, "total": total})

            def on_group(stat):
                self._emit(wf, {"type": "group", "id": stat["id"],
                                "title": stat["title"], "scanned": stat["scanned"],
                                "found": stat["found"],
                                "elapsed_ms": stat["elapsed_ms"]})

            scan = eng.run_scan(groups=groups, on_group=on_group)
            findings = [_finding_payload(f) for f in scan["findings"]]
            for gid in groups:
                st.last[gid] = {"findings": [x for x in findings if x["group"] == gid],
                                "passed": [p for p in scan["passed"] if p["group"] == gid]}
            self._emit(wf, {
                "type": "done",
                "nav": nav_id,
                "scanned": scan["scanned"],
                "elapsed_ms": scan["elapsed_ms"],
                "findings": findings,
                "passed": scan["passed"],
                "groups": [{"id": g, "title": st.cfg.group_of(g).get("title", g)}
                           for g in groups],
            })

    def _fix(self, body: dict):
        st = self.state
        uuids = body.get("uuids") or []
        if not isinstance(uuids, list) or not uuids or len(uuids) > len(st.cfg.rules) or any(
                not isinstance(u, str) or u not in st.cfg.rules for u in uuids):
            return self._json({"error": "需要有效且非空的规则列表"}, 400)
        uuids = list(dict.fromkeys(uuids))
        with st.lock:
            wf = self._stream()
            eng = engine.Engine(st.cfg, dry_run=False, include_optional=True)
            rules = [st.cfg.rules[u] for u in uuids if u in st.cfg.rules]
            self._emit(wf, {"type": "start", "total": len(rules)})
            done, failed, pending_reboot, unverified = 0, [], [], []
            for rule in rules:
                self._emit(wf, {"type": "begin", "uuid": rule.uuid,
                                "title": rule.title})
                f = eng.run_rule(rule)
                if f is None:
                    self._emit(wf, {"type": "item", "uuid": rule.uuid, "title": rule.title,
                                    "ok": False, "status": "not_needed", "message": "当前已通过或不适用，未执行修复"})
                    continue
                eng.run_fix([f])
                ok = bool(f.fix_ok)
                done += 1 if ok else 0
                if not ok:
                    target = (pending_reboot if f.fix_status == "pending_reboot"
                              else failed if f.fix_status == "failed" else unverified)
                    target.append({"uuid": rule.uuid, "title": rule.title,
                                   "message": f.fix_message, "status": f.fix_status})
                self._emit(wf, {"type": "item", "uuid": rule.uuid,
                                "title": rule.title, "ok": ok,
                                "message": f.fix_message,
                                "status": f.fix_status, "journal_id": f.journal_id,
                                "needs_reboot": f.to_dict()["needs_reboot"],
                                "installer_exit_codes": list(f.installer_exit_codes),
                                "verify": f.verify_detail})
            self._emit(wf, {"type": "done", "ok_count": done,
                            "failed": failed, "pending_reboot": pending_reboot,
                            "unverified": unverified, "total": len(rules)})


def make_server(cfg) -> tuple[ThreadingHTTPServer, State]:
    state = State(cfg)
    eng = engine.Engine(cfg, dry_run=True)
    state.env = eng.run_global()
    session_handler = type("SessionHandler", (Handler,), {"state": state})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), session_handler)
    httpd.daemon_threads = True
    return httpd, state
