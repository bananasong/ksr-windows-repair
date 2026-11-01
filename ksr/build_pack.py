"""规则包构建器：生成 rules/pack.json 与 rules/pack.ksrp。

每条规则的 UUID 由 (group,title) 派生（uuid5），保证多次构建稳定 —— 对应原程序
“脚本按 UUID 寻址”的约束（RunOneScriptByUuid / ConfigManager::GetScriptUuid）。
"""

from __future__ import annotations

import json
import os
import uuid as uuidlib

from . import catalog
from . import pack as packmod

NS = uuidlib.UUID("6f3a1c2e-0000-4a00-9000-000000000001")

GROUPS = [
    {"id": "dll", "order": 10, "title": "DLL 文件", "icon": "fixsysdll",
     "desc": "系统 DLL 缺失或损坏，会导致软件与游戏无法启动"},
    {"id": "runtime", "order": 20, "title": "常用运行库", "icon": "fixvcnet",
     "desc": "VC++ / MSXML / .NET 等运行库损坏或未装全，软件会提示缺少 DLL"},
    # 「系统优化」= solution 5072 的 11 个 item，标题/顺序全部照抄
    # ksduicfgz.dat 解密出来的界面配置，不自行命名。
    {"id": "sysopt_svc", "order": 25, "title": "优化服务设置，提升系统稳定性",
     "icon": "fixservices",
     "desc": "优化系统服务项，解决电脑问题"},
    {"id": "sysopt_sysset", "order": 26, "title": "优化系统设置，提升系统稳定性",
     "icon": "fixsysdll", "desc": "当桌面异常时，可勾选进行优化"},
    {"id": "sysopt_priv", "order": 27, "title": "优化系统权限设置，提升隐私保护",
     "icon": "fixsoftdll", "desc": "一键关闭系统隐私权限，保护个人信息安全"},
    {"id": "sysopt_taskbar", "order": 28, "title": "优化任务栏设置，使用更便捷",
     "icon": "fixtaskbar", "desc": "优化任务栏图标，提升电脑运行速度"},
    {"id": "sysopt_deskicon", "order": 29, "title": "优化桌面图标设置，让桌面更美观",
     "icon": "fixdesktop", "desc": "显示核心功能图标，提升电脑使用效率"},
    {"id": "sysopt_menu", "order": 30, "title": "优化右键菜单设置，提升右键速度",
     "icon": "fixsrcmenu", "desc": "优化菜单样式，提升电脑使用效率"},
    {"id": "sysopt_explorer", "order": 31, "title": "优化文件设置，提升浏览效率",
     "icon": "fixfileset", "desc": "优化资源管理器设置，提升办公效率"},
    {"id": "sysopt_udisk", "order": 32, "title": "优化U盘设置，保护数据安全",
     "icon": "fixudisk",
     "desc": "移动设备接入电脑自动运行移动设备的程序，容易让电脑感染病毒"},
    {"id": "sysopt_camera", "order": 33, "title": "检查摄像头系统默认设置是否正常",
     "icon": "fixcamera", "desc": "可能导致设备错误码19，建议修复"},
    {"id": "sysopt_gpu", "order": 34, "title": "检查显卡系统默认设置是否正常",
     "icon": "fixgpu", "desc": "可能导致设备错误码19，建议修复"},
    {"id": "sysopt_mouse", "order": 35, "title": "检查鼠标系统默认设置是否正常",
     "icon": "fixmouse", "desc": "可能导致设备错误码19，建议修复"},
    # 7A8F687A 属于 solution 5068「电脑卡慢」的第一个 item
    {"id": "slow_boot", "order": 61, "title": "开机时系统服务优化",
     "icon": "pcslow", "desc": "优化开机时加载的系统服务与资源分配策略"},
    {"id": "svc", "order": 30, "title": "系统服务", "icon": "fixservices",
     "desc": "关键服务被禁用或未运行，会直接导致对应功能失效"},
    {"id": "audio", "order": 40, "title": "电脑声音", "icon": "fixaudio",
     "desc": "异常项会导致您的电脑没有声音，影响电脑使用"},
    {"id": "print", "order": 50, "title": "打印机问题", "icon": "fixprinter",
     "desc": "异常项可能会影响您的打印机正常使用，请尽快修复"},
    {"id": "perf", "order": 60, "title": "电脑卡慢", "icon": "pcslow",
     "desc": "优化后可显著提升电脑运行速度与稳定性"},
    {"id": "desk", "order": 70, "title": "桌面与文件关联", "icon": "fixdesktop",
     "desc": "桌面、任务栏、文件关联异常会影响日常操作"},
    {"id": "crash", "order": 80, "title": "蓝屏与崩溃", "icon": "dllsystem",
     "desc": "转储与错误报告配置异常时，蓝屏原因无法定位"},
    {"id": "sys", "order": 90, "title": "系统综合", "icon": "sys",
     "desc": "系统时间、网络栈、权限等基础项"},
    {"id": "game", "order": 100, "title": "游戏必备组件", "icon": "fixgamedll",
     "desc": "游戏运行依赖的图形、音频与物理引擎组件"},
    {"id": "manual", "order": 110, "title": "手动修复", "icon": "manualrepair",
     "desc": "需要官方安装包或人工确认，程序不代劳"},
    {"id": "udisk", "order": 120, "title": "U 盘与外设", "icon": "fixudisk",
     "desc": "可移动磁盘写入策略与设备状态"},
]

SYS32 = r"%SystemRoot%\System32"

# (group, title, severity, impact, check_api, check_args, fix_api, fix_args,
#  needs_admin, needs_reboot, tags)
RULES = [
    # ---------------- dll
    ("dll", "VC++ 运行库缺失", "error", "大量软件与游戏会提示缺少 dll 无法启动",
     "vcrt.present", {}, None, None, False, False, ["fixvcnet", "vcfix"]),
    ("dll", "DirectX 组件缺失", "error", "游戏画面卡顿、花屏或无法启动",
     "dx.present", {}, None, None, False, False, ["fixdirectx"]),
    ("dll", "UCRT 通用运行库缺失", "error", "新版软件启动即报 0xc000007b",
     "files.present", {"names": ["ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll"],
                       "arch": 64}, None, None, False, False, ["fixdll", "dllfix"]),
    ("dll", "API Set 转发层缺失", "warn", "系统组件互相调用失败，出现莫名错误码",
     "files.present", {"names": ["api-ms-win-core-synch-l1-2-0.dll",
                                 "api-ms-win-core-console-l1-1-0.dll"],
                       "arch": 64},
     "files.restore", {"src_dir": r"%KSR_HOME%\payload", "dst_dir": SYS32,
                       "names": ["api-ms-win-core-synch-l1-2-0.dll",
                                 "api-ms-win-core-console-l1-1-0.dll"]},
     True, True, ["dllsystem", "fixsysdll"]),
    ("dll", "D3D 编译器缺失", "warn", "部分游戏与播放器渲染失败",
     "files.present", {"names": ["d3dcompiler_47.dll"]}, None, None,
     False, False, ["fixdirectx", "gamefix"]),
    ("dll", "游戏音频运行库缺失", "info", "老游戏无声音或启动报错",
     "files.present", {"names": ["openal32.dll"]},
     "files.restore", {"src_dir": r"%KSR_HOME%\payload", "dst_dir": SYS32,
                       "names": ["openal32.dll"]},
     True, True, ["fixgamedll", "gamefix"]),

    # ---------------- svc
    ("svc", "打印后台处理程序未运行", "error", "打印机完全不可用",
     "svc.state", {"name": "Spooler", "expect": "running"},
     "svc.start", {"name": "Spooler"}, True, False, ["fixprinter", "fixservices"]),
    ("svc", "音频服务未运行", "error", "电脑没有声音",
     "svc.state", {"name": "Audiosrv", "expect": "running"},
     "svc.start", {"name": "Audiosrv"}, True, False, ["fixaudio", "sound"]),
    ("svc", "音频端点服务未运行", "error", "音频设备列表为空，扬声器不可用",
     "svc.state", {"name": "AudioEndpointBuilder", "expect": "running"},
     "svc.start", {"name": "AudioEndpointBuilder"}, True, False, ["fixaudio"]),
    ("svc", "WMI 服务被禁用", "warn", "系统信息查询与部分软件安装失败",
     "svc.start_type", {"name": "Winmgmt", "forbid": ["disabled"]},
     "svc.set_start", {"name": "Winmgmt", "start_type": "auto"}, True, False,
     ["fixservices", "sys"]),
    ("svc", "错误报告服务被禁用", "info", "崩溃信息无法收集，问题难以定位",
     "svc.start_type", {"name": "WerSvc", "forbid": ["disabled"]},
     "svc.set_start", {"name": "WerSvc", "start_type": "manual"}, True, False,
     ["fixservices"]),
    ("svc", "Windows Search 未运行", "info", "开始菜单与资源管理器搜索变慢",
     "svc.state", {"name": "WSearch", "expect": "running"},
     "svc.start", {"name": "WSearch"}, True, False, ["seachfix"]),
    ("svc", "核心系统服务异常", "warn", "系统功能缺失或反复报错",
     "svc.all", {"items": [
         {"name": "Themes", "start_type": "auto"},
         {"name": "Dnscache", "state": "running"},
         {"name": "nsi", "state": "running"},
     ]},
     "svc.set_start", {"name": "Themes", "start_type": "auto"}, True, False,
     ["fixservices", "sys"]),

    # ---------------- audio
    ("audio", "无可用的音频输出设备", "error", "电脑没有声音，无法播放任何音频",
     "audio.endpoints", {}, "audio.restart", {}, True, False, ["fixaudio", "sound"]),
    ("audio", "音频相关服务异常", "warn", "声音时有时无或设备识别失败",
     "audio.services", {}, "audio.restart", {}, True, False, ["fixaudioreg", "sound"]),

    # ---------------- print
    ("print", "系统未安装打印机", "info", "无法使用任何打印功能",
     "print.exists", {}, None, None, False, False, ["fixprinter"]),
    ("print", "打印队列积压", "warn", "打印任务卡住，后续任务无法提交",
     "print.queue", {"max_jobs": 0}, "print.clear_queue", {}, True, False,
     ["fixprinter", "printer"]),

    # ---------------- perf
    ("perf", "开机启动项过多", "warn", "开机变慢、进桌面后长时间卡顿",
     "startup.count", {"max": 12}, None, None, False, False, ["pcslow"]),
    ("perf", "临时文件占用过大", "warn", "C 盘空间被挤占，系统响应变慢",
     "fs.size_lt", {"path": r"%TEMP%", "max_mb": 2048},
     "fs.clean", {"path": r"%TEMP%", "patterns": ["*"], "older_days": 3,
                  "max_files": 3000}, False, False, ["pcslow"]),
    ("perf", "系统临时目录占用过大", "info", "C 盘空间不足，更新与安装失败",
     "fs.size_lt", {"path": r"%SystemRoot%\Temp", "max_mb": 3072},
     "fs.clean", {"path": r"%SystemRoot%\Temp", "patterns": ["*"], "older_days": 7,
                  "max_files": 3000}, True, False, ["pcslow"]),
    ("perf", "进程异常占用 CPU", "warn", "操作卡顿、反应迟缓、风扇狂转",
     "proc.cpu_hogs", {"threshold": 85, "interval": 0.6}, None, None,
     True, False, ["pcslow"]),
    ("perf", "系统盘剩余空间不足", "warn", "系统更新失败、虚拟内存不足",
     "disk.free", {"drive": "%SystemDrive%\\", "min_gb": 10}, None, None,
     False, False, ["pcslow", "sys"]),

    # ---------------- desk
    ("desk", "Winlogon 外壳配置被篡改", "error", "开机后进不了桌面，只有黑屏或命令行",
     "shell.config", {},
     "reg.set", {"hive": "HKLM",
                 "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                 "name": "Shell", "type": "REG_SZ", "value": "explorer.exe"},
     True, True, ["fixdesktop", "fixtaskbar"]),
    ("desk", ".exe 文件关联异常", "error", "双击任何程序都无法运行",
     "assoc.exe", {},
     "assoc.repair", {"ext": ".exe", "progid": "exefile", "command": "\"%1\" %*"},
     True, False, ["fixfileset"]),
    ("desk", ".lnk 快捷方式关联异常", "warn", "桌面快捷方式双击无反应",
     "assoc.lnk", {},
     "assoc.repair", {"ext": ".lnk", "progid": "lnkfile"}, True, False,
     ["fixfileset", "fixdesktop"]),
    ("desk", "资源管理器未运行", "error", "桌面空白、任务栏消失",
     "explorer.alive", {}, "explorer.restart", {}, False, False,
     ["fixdesktop", "fixtaskbar", "fixsrcmenu"]),

    # ---------------- crash
    ("crash", "内存转储被关闭", "warn", "蓝屏后无 dump 文件，无法定位原因",
     "dump.config", {}, "dump.set", {"mode": 7}, True, True, ["dllsystem", "kdump"]),
    ("crash", "错误报告配置异常", "info", "崩溃信息无法上报与本地留存",
     "wer.config", {},
     "svc.set_start", {"name": "WerSvc", "start_type": "manual"}, True, False,
     ["kdump", "syslogrule"]),
    ("crash", "WMI 存储库异常", "warn", "系统信息查询报错，部分软件安装失败",
     "wmi.repo", {"max_mb": 2048}, "svc.restart", {"name": "Winmgmt"},
     True, False, ["sys", "fixservices"]),

    # ---------------- sys
    ("sys", "系统时间异常", "error", "证书校验失败、网站打不开、文件时间错乱",
     "time.sane", {}, None, None, True, False, ["sys"]),
    ("sys", "网络协议栈目录为空", "error", "无法联网，所有网络请求失败",
     "net.winsock", {}, None, None, True, True, ["sys"]),
    ("sys", "C 盘根目录 ACL 异常", "warn", "软件安装、临时文件写入失败",
     "fs.writable", {"path": "%SystemDrive%\\", "admin_only": True},
     None, None, True, False, ["sys", "manualrepair"]),
    ("sys", "修复资源包不完整", "info", "缺失的 DLL 无法自动恢复",
     "payload.check", {"dir": r"%KSR_HOME%\payload", "must": []}, None, None,
     False, False, ["dllfix", "manualrepair"]),

    # ---------------- udisk
    ("udisk", "可移动磁盘被设为只读", "warn", "U 盘无法写入文件",
     "reg.value", {"hive": "HKLM",
                   "key": r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
                   "name": "WriteProtect", "expect": "0", "missing_ok": True},
     "reg.set", {"hive": "HKLM",
                 "key": r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
                 "name": "WriteProtect", "type": "REG_DWORD", "value": 0},
     True, True, ["fixudisk"]),

    # ---------------- runtime：常用运行库
    # 说明：清单类分类（vc_legacy / ucrt / msxml_* / script_host / media_foundation）
    # 由文件末尾的 CAT_GROUP 表自动生成，这里只放需要专门探测逻辑的项。
    ("runtime", "VC++ 2015-2022 运行库 (x64)", "error",
     "当前绝大多数 Windows 软件与游戏都依赖它，缺失时提示 vcruntime140 相关错误",
     "vcredist.probe", {"major": 14, "arch": "x64"},
     "vcredist.install", {"gen": 14, "arch": "x64"}, True, False,
     ["vcfix", "fixvcnet"]),
    ("runtime", "VC++ 2015-2022 运行库 (x86)", "error",
     "32 位软件与游戏依赖；64 位系统上也经常缺失，导致老软件无法启动",
     "vcredist.probe", {"major": 14, "arch": "x86"},
     "vcredist.install", {"gen": 14, "arch": "x86"}, True, False,
     ["vcfix", "fixvcnet"]),
    ("runtime", "VC++ 2013 运行库", "warn",
     "2013 年编译的软件与游戏依赖",
     "vcredist.probe", {"major": 12},
     "vcredist.install", {"gen": 12}, True, False, ["vcfix"]),
    ("runtime", "VC++ 2012 运行库", "warn",
     "2012 年编译的软件与游戏依赖",
     "vcredist.probe", {"major": 11},
     "vcredist.install", {"gen": 11}, True, False, ["vcfix"]),
    ("runtime", "VC++ 2010 运行库", "warn",
     "2010 年编译的行业软件与老游戏依赖",
     "vcredist.probe", {"major": 10},
     "vcredist.install", {"gen": 10}, True, False, ["vcfix"]),
    ("runtime", ".NET Framework 4.8", "warn",
     "大量桌面软件与游戏启动器的运行前提",
     "dotnet.version", {"min_release": 528040}, None, None, False, False, ["dotnet"]),

    # ---------------- game：游戏必备组件
    ("game", "DirectX 9 兼容层", "warn",
     "大型游戏与 3D 软件运行黑屏或闪退时，多半是这一层不完整",
     "dx.runtime", {}, "directx.install", {}, True, True, ["fixdirectx"]),

    # ---------------- manual：需要人工触发的修复
    ("manual", "重新注册核心 COM 组件", "error",
     "重装运行库后仍报错时，通常是 COM 注册信息损坏，重新注册即可",
     "regsvr.state", {}, "regsvr.run", {}, True, False, ["fixsysdll", "regsvr"]),
    ("manual", "重新注册 Shell / 压缩文件夹组件", "info",
     "资源管理器右键菜单、压缩文件夹功能异常时的兜底修复",
     "regsvr.state", {"dlls": ["shell32.dll", "zipfldr.dll"]},
     "regsvr.run", {"dlls": ["shell32.dll", "zipfldr.dll"]}, True, False,
     ["regsvr"]),
    ("manual", "重新安装 MSXML 4.0 解析器", "warn",
     "微软已停止随系统分发，需到官网下载 MSXML 4.0 SP3 安装包手动安装",
     "dll.catalog", {"cat": "msxml_legacy"}, None, None, False, False, ["msxml"],
     "https://www.microsoft.com/en-us/download/details.aspx?id=19662"),
]

# 清单分类 -> 分组归属。每个分类只出现在一个分组里，避免同一问题在界面上报两次。
# vc14 故意不入表：它由 vcredist.probe 用「注册表 + 文件」双证据覆盖，更准。
CAT_GROUP = {
    # DLL 文件
    "dx_core": "dll", "dx9_d3dx": "dll", "dx10_d3dx": "dll",
    "ole_shell": "dll", "vcomp": "dll", "mfc_atl": "dll",
    # 常用运行库
    "ucrt": "runtime", "vc80": "runtime", "vc90": "runtime",
    "vc_legacy": "runtime", "msxml_core": "runtime",
    "script_host": "runtime", "media_foundation": "runtime",
    # 游戏必备组件
    "d3dcompiler": "game", "xinput": "game", "xaudio": "game",
    "game_extra": "game",
}

# 自动修复只挂在「装的包确实能补上这些文件」的分类上。
# mfc71~mfc90 属于 VC++ 2003/2005/2008 时代，最新 vcredist 补不上；
# VC++ 2008 的官方安装包地址已失效。这些一律保持手动，不放空按钮。
_NO_AUTOFIX = {"vc_legacy", "vc90", "mfc_atl"}

# vcredist.install 的默认参数（gen 对应 VC_GENERATIONS 的版本号）
CAT_FIX_ARGS = {
    "ucrt": {"gen": 14, "arch": "x64"},
    "vcomp": {"gen": 14, "arch": "x64"},
    "vc80": {"gen": 8, "arch": "x86"},
}

for _cat in catalog.CATALOG:
    _grp = CAT_GROUP.get(_cat["id"])
    if not _grp:
        continue
    _fapi = None if _cat["id"] in _NO_AUTOFIX else _cat.get("fix")
    if _fapi == "vcredist.install":
        _fargs = CAT_FIX_ARGS.get(_cat["id"], {"gen": 14, "arch": "x64"})
    elif _fapi:
        _fargs = {}
    else:
        _fargs = None
    RULES.append((
        _grp, _cat["title"], "warn", _cat["purpose"],
        "dll.catalog", {"cat": _cat["id"], **({"arch": "x86"} if _cat["id"] == "vc80" else {})},
        _fapi, _fargs, bool(_fapi), False,
        ["dllcatalog"],
    ))



def _sysopt_rows() -> list:
    """把 sysopt.ITEMS 展开成 RULES 同构的行。

    这批规则对应原版分类号 id=2201（系统优化），检测逻辑见 sysopt.py 的逐条注释。
    """
    from . import sysopt as so

    rows = []
    for it in so.ITEMS:
        has_fix = bool(it.get("fix"))
        reversible = {"reg_set", "reg_multi_set", "reg_or_set", "svc_set", "svcs_set", "lang_set", "edge_bg_off"}
        if (it.get("fix") or {}).get("t") not in reversible or (it.get("fix_extra") and it["fix_extra"].get("t") not in reversible):
            has_fix = False
        if it["item"] in {"camera19", "gpu19", "mouse19"}:
            # A class filter can be a legitimate OEM driver. Never rewrite it automatically.
            continue
        rows.append((
            it["group"], it["title"], "warn", it.get("impact", ""),
            "sysopt.probe", {"item": it["item"]},
            "sysopt.fix" if has_fix else None,
            {"item": it["item"]} if has_fix else None,
            bool(it.get("needs_admin")), False,
            ["sysopt", it["item"]],
        ))
    return rows


def build() -> dict:
    scripts = []
    for row in list(RULES) + _sysopt_rows():
        (group, title, sev, impact, capi, cargs, fapi, fargs,
         admin, reboot, tags) = row[:11]
        if capi == "files.present":
            cargs = dict(cargs)
            cargs["names"] = [name for name in cargs["names"] if not name.lower().startswith(("api-", "ext-"))]
            if not cargs["names"]:
                continue
        link = row[11] if len(row) > 11 else ""
        uid = str(uuidlib.uuid5(NS, f"{group}/{title}"))
        rec = {
            "uuid": uid,
            "group": group,
            "title": title,
            "severity": sev,
            "impact": impact,
            "check": {"api": capi, "args": cargs},
            "tags": tags,
            "needs_admin": admin,
            "needs_reboot": reboot,
            "optional": group.startswith("sysopt_") or group in {"slow_boot", "manual"} or sev == "info"
                        or capi in {"vcredist.probe", "vcrt.present", "dx.runtime", "dx.present", "dotnet.version", "dll.catalog"}
                        or fapi in {"fs.clean", "print.clear_queue", "explorer.restart", "proc.kill", "regsvr.run"},
        }
        if link:
            rec["link"] = link
        if fapi == "files.restore":
            # Product distributions do not ship or inject arbitrary system DLL payloads.
            fapi = None
        if capi == "dll.catalog" and (cargs.get("cat") in {"dx_core", "ucrt", "vcomp", "d3dcompiler", "xinput", "xaudio"}):
            fapi = None
        if fapi:
            rec["fix"] = {"api": fapi, "args": fargs}
            rec["verify"] = {"api": capi, "args": cargs}
        scripts.append(rec)
    return {"schema": "ksr.rulepack/1", "groups": GROUPS, "scripts": scripts}


def main(root: str) -> dict:
    p = build()
    jpath = os.path.join(root, "rules", "pack.json")
    kpath = os.path.join(root, "rules", "pack.ksrp")
    os.makedirs(os.path.dirname(jpath), exist_ok=True)
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(p, f, ensure_ascii=False, indent=2)
    info = packmod.write_pack(kpath, p, build="20261101120000")
    info["json"] = jpath
    return info


if __name__ == "__main__":
    import sys

    print(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(__file__)))
