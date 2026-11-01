"""命令行入口：python -m ksr <scan|fix|list|doctor|build-pack>"""

from __future__ import annotations

import argparse
import json
import os
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

from . import __version__, build_pack, engine, report
from . import win32api as w

PKG = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.dirname(PKG)
PACK = os.path.join(PKG, "rules", "pack.ksrp")

C = {"r": "\033[31m", "y": "\033[33m", "b": "\033[36m", "g": "\033[32m",
     "d": "\033[90m", "0": "\033[0m", "w": "\033[1m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}

SEV_LBL = {"error": "异常", "warn": "优化", "info": "建议"}


def ensure_pack(force=False) -> str:
    os.environ.setdefault("KSR_HOME", HOME)
    if force or not os.path.exists(PACK):
        info = build_pack.main(PKG)
        print(f"{C['d']}已构建规则包：{info['path']}（{info['scripts']} 条脚本 / "
              f"{info['groups']} 个分组，{info['bytes']} 字节）{C['0']}")
    return PACK


def load_cfg(force=False):
    path = ensure_pack(force)
    return engine.load(path)


# ---------------------------------------------------------------- 命令

def cmd_scan(args):
    cfg = load_cfg(args.build_pack)
    if args.group:
        for g in args.group:
            if g not in cfg.groups:
                sys.exit(f"未知分组 {g}，可用：{', '.join(cfg.sequence)}")
    eng = engine.Engine(cfg, dry_run=not args.fix)
    env = eng.run_global()
    for x in env["warnings"]:
        print(f"{C['y']}! {x}{C['0']}")
    scan = eng.run_scan(groups=args.group, uuids=args.uuid)

    if args.json:
        print(json.dumps({
            "env": env,
            "scanned": scan["scanned"],
            "elapsed_ms": scan["elapsed_ms"],
            "groups": scan["groups"],
            "findings": [f.to_dict() for f in scan["findings"]],
            "telemetry": eng.telemetry,
        }, ensure_ascii=False, indent=2))
    else:
        _print_scan(scan, cfg)

    if args.html:
        doc = report.render(scan, env, cfg, dry_run=not args.fix)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(doc)
        print(f"\n{C['g']}报告已生成：{args.html}{C['0']}")
    return 0


def _print_scan(scan, cfg):
    print(f"\n{C['w']}======== KSR 系统异常修复 v{__version__} start to run scan script ========{C['0']}")
    last_group = None
    for f in scan["findings"]:
        if f.rule.group != last_group:
            g = cfg.group_of(f.rule.group)
            print(f"\n{C['b']}[{g.get('title', f.rule.group)}]{C['0']} {C['d']}{g.get('desc','')}{C['0']}")
            last_group = f.rule.group
        color = {"error": C["r"], "warn": C["y"], "info": C["b"]}[f.sev]
        label = "检测未完成" if f.status == "unavailable" else SEV_LBL[f.sev]
        print(f"  {color}●{C['0']} {f.display_title}  {C['d']}[{label}]{C['0']}")
        print(f"    {f.detail}")
        if f.rule.fix:
            print(f"    {C['d']}修复：{f.rule.fix['api']}  ·  脚本 {f.rule.uuid[:8]}{C['0']}")
    n = len(scan["findings"])
    if n == 0:
        print(f"\n{C['g']}本轮未发现需要处理的问题{C['0']}；不适用项目不代表检测通过")
    else:
        cnt = {s: sum(1 for f in scan["findings"] if f.sev == s)
               for s in ("error", "warn", "info")}
        print(f"\n{C['w']}共检出 {n} 项{C['0']}：异常 {cnt['error']} · 优化 {cnt['warn']} · "
              f"建议 {cnt['info']}    （{scan['scanned']} 条脚本，{scan['elapsed_ms']} ms）")


def cmd_fix(args):
    if not args.yes and not args.dry_run:
        sys.exit(f"{C['y']}修复会真实修改系统（服务/注册表/文件）。确认请加 --yes；"
                 f"只看计划请用 --dry-run{C['0']}")
    cfg = load_cfg(args.build_pack)
    eng = engine.Engine(cfg, dry_run=args.dry_run, include_optional=args.include_optional)
    env = eng.run_global()
    for x in env["warnings"]:
        print(f"{C['y']}! {x}{C['0']}")
    scan = eng.run_scan(groups=args.group, uuids=args.uuid)
    findings = scan["findings"]
    if not findings:
        print(f"\n{C['g']}以下检测项已最优{C['0']}，无需修复")
        return 0
    _print_scan(scan, cfg)
    print(f"\n{C['w']}======== start to run fix script ========{C['0']}")
    eng.run_fix(findings)
    okc = sum(1 for f in findings if f.fix_ok)
    failc = sum(1 for f in findings if f.fix_status == "failed")
    pending = sum(1 for f in findings if f.fix_status in {"pending_reboot", "unverified"})
    planc = sum(1 for f in findings if f.fix_ok is None and f.rule.fix)
    manual = sum(1 for f in findings if f.fix_ok is None and not f.rule.fix)
    for f in findings:
        if f.fix_ok is None and f.rule.fix:
            mark, col = "计划", C["y"]
        elif f.fix_ok is None:
            mark, col = "手动", C["d"]
        elif f.fix_status == "pending_reboot":
            mark, col = "待重启验证", C["y"]
        elif f.fix_status == "unverified":
            mark, col = "尚未验证", C["y"]
        elif f.fix_ok:
            mark, col = "已修复", C["g"]
        else:
            mark, col = "失败", C["r"]
        print(f"  {col}{mark}{C['0']} {f.rule.title} — {f.fix_message}")
        if f.verify_detail:
            print(f"    {C['d']}复检：{f.verify_detail}{C['0']}")
    print(f"\n{C['w']}修复结果{C['0']}：已验证 {okc} · 失败 {failc} · 待验证 {pending} · 计划 {planc} · 手动 {manual}")
    if any(f.rule.needs_reboot and f.fix_ok for f in findings):
        print(f"{C['y']}部分修复项将在重启电脑后生效{C['0']}")
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2))
    return 2 if failc else 3 if pending else 0


def cmd_diagnose(args):
    from .diagnose import inspect
    print(json.dumps(inspect(args.path), ensure_ascii=False, indent=2))
    return 0


def cmd_history(args):
    from .journal import history
    print(json.dumps(history(), ensure_ascii=False, indent=2))
    return 0


def cmd_undo(args):
    from .journal import undo
    if not args.yes:
        raise SystemExit("撤销会恢复已记录的配置，请使用 --yes 确认")
    print(json.dumps(undo(args.id), ensure_ascii=False, indent=2))
    return 0


def cmd_list(args):
    cfg = load_cfg(args.build_pack)
    for gid in cfg.sequence:
        rules = [r for r in cfg.rules.values() if r.group == gid]
        if args.group and gid not in args.group:
            continue
        g = cfg.group_of(gid)
        print(f"\n{C['b']}{g.get('title', gid)}{C['0']}  {C['d']}{gid} · {len(rules)} 条{C['0']}")
        for r in rules:
            fix = r.fix["api"] if r.fix else "—"
            print(f"  {r.uuid[:8]}  {SEV_LBL[r.severity]}  {r.title:<24} "
                  f"{C['d']}check={r.check['api']}  fix={fix}{C['0']}")
    return 0


def cmd_doctor(args):
    cfg = load_cfg(args.build_pack)
    print(f"{C['w']}KSR {__version__}{C['0']}")
    print(f"  python      {sys.version.split()[0]}  ({sys.executable})")
    print(f"  admin       {w.is_admin()}")
    print(f"  systemroot  {w.system_root()}")
    print(f"  cpu         {os.cpu_count()}")
    print(f"  rulepack    {PACK}")
    print(f"  scripts     {len(cfg.rules)}   groups {len(cfg.groups)}   build {cfg.build}")
    from . import api as apilayer
    print(f"  apis        check={len(apilayer.CHECKS)}  fix={len(apilayer.FIXES)}")
    try:
        p = engine.packmod.read_pack(PACK)
        print(f"  container   magic ok · crc {p['crc']:#010x} · "
              f"sections {sum(1 for e in p['sections'] if e[1])}")
    except Exception as exc:  # noqa: BLE001
        print(f"  container   {C['r']}FAIL {exc}{C['0']}")
    missing = [n for n in ("Spooler", "Audiosrv", "Winmgmt")
               if w.service_query(n) is None]
    print(f"  服务探测    {'ok' if not missing else '缺少 ' + ','.join(missing)}")
    return 0


def cmd_ui(args):
    from .ui import app as uiapp

    try:
        cfg = load_cfg(args.build_pack)
        return uiapp.run(cfg, width=args.width, height=args.height,
                         browser_only=args.browser, serve_only=args.no_window)
    except KeyboardInterrupt:
        return 0
    except Exception:  # noqa: BLE001
        # 双击启动时控制台可能一闪就没了，所以把栈落到文件里，事后还能查。
        import datetime
        import traceback

        tb = traceback.format_exc()
        try:
            with open(os.path.join(PKG, "ksr-ui-error.log"), "a",
                      encoding="utf-8") as f:
                f.write(f"\n===== {datetime.datetime.now():%Y-%m-%d %H:%M:%S} =====\n")
                f.write(f"argv: {sys.argv}\n")
                f.write(f"cwd : {os.getcwd()}\n")
                f.write(tb)
        except OSError:
            pass
        print(tb, file=sys.stderr)
        return 1


def cmd_build(args):
    info = build_pack.main(PKG)
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ksr", description="系统异常修复引擎（逆向重实现）")
    ap.add_argument("--version", action="version", version=f"ksr {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--group", action="append", help="只跑指定分组，可多次")
        p.add_argument("--uuid", action="append", help="只跑指定脚本 UUID 前缀，可多次")
        p.add_argument("--json", action="store_true")
        p.add_argument("--build-pack", action="store_true", help="强制重建规则包")

    s = sub.add_parser("scan", help="只扫描，不改系统")
    common(s)
    s.add_argument("--html", help="输出 HTML 报告路径")
    s.add_argument("--fix", action="store_true", help="扫描后立即修复")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="扫描并修复")
    common(f)
    f.add_argument("--yes", action="store_true", help="确认执行真实修复")
    f.add_argument("--dry-run", action="store_true", help="只打印修复计划")
    f.add_argument("--include-optional", action="store_true", help="包含可选操作，建议配合 --uuid 逐项选择")
    f.set_defaults(func=cmd_fix)

    diagnose = sub.add_parser("diagnose", help="静态分析指定 EXE/DLL 的依赖及 .NET 运行时配置")
    diagnose.add_argument("path")
    diagnose.add_argument("--json", action="store_true")
    diagnose.set_defaults(func=cmd_diagnose)
    history = sub.add_parser("history", help="查看本地修复记录")
    history.add_argument("--json", action="store_true")
    history.set_defaults(func=cmd_history)
    undo = sub.add_parser("undo", help="撤销指定记录中的注册表/服务/文件变更")
    undo.add_argument("id")
    undo.add_argument("--yes", action="store_true")
    undo.set_defaults(func=cmd_undo)

    l = sub.add_parser("list", help="列出脚本")
    l.add_argument("--group", action="append")
    l.add_argument("--build-pack", action="store_true")
    l.set_defaults(func=cmd_list)

    d = sub.add_parser("doctor", help="自检")
    d.add_argument("--build-pack", action="store_true")
    d.set_defaults(func=cmd_doctor)

    b = sub.add_parser("build-pack", help="重建规则包")
    b.set_defaults(func=cmd_build)

    ui = sub.add_parser("ui", help="打开图形界面")
    ui.add_argument("--build-pack", action="store_true", help="强制重建规则包")
    ui.add_argument("--browser", action="store_true",
                    help="用默认浏览器打开，不开独立窗口")
    ui.add_argument("--no-window", action="store_true",
                    help="只提供本地服务并打印地址，不打开任何窗口")
    ui.add_argument("--width", type=int, default=1120)
    ui.add_argument("--height", type=int, default=780)
    ui.set_defaults(func=cmd_ui)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
