"""脚本 API 层。

原程序把能力以 luaAPIV3 的形式注册进内嵌 Lua 5.1 解释器（ksyseng3.dll 导出
luaopen_cjson / luaopen_alien_core / luaopen_alien_struct，源码路径
src/quick_scan/LKSR/luaAPIV3/fileAPI4C.cpp），脚本按 UUID 调这些 API。

本模块是同一层的等价物：每个 API 用名字注册，check 型返回统一结构，
fix 型返回 (ok, message) 或携带重启要求的 FixResult。
规则包（rules/*.json）通过 api 名 + args 调用。
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
import xml.etree.ElementTree as ET

import winreg

from . import catalog
from . import sysopt
from . import win32api as w

CHECKS: dict[str, callable] = {}
FIXES: dict[str, callable] = {}


@dataclass(frozen=True)
class FixResult:
    """Structured installer outcome; reboot requirements survive API aggregation."""

    ok: bool
    message: str
    needs_reboot: bool = False
    exit_codes: tuple[int, ...] = ()


def check(name):
    def deco(fn):
        CHECKS[name] = fn
        return fn
    return deco


def fix(name):
    def deco(fn):
        FIXES[name] = fn
        return fn
    return deco


# ---------------------------------------------------------------- 公共工具

HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS,
}

REG_TYPES = {
    "REG_SZ": winreg.REG_SZ,
    "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ,
    "REG_DWORD": winreg.REG_DWORD,
    "REG_BINARY": winreg.REG_BINARY,
    "REG_MULTI_SZ": winreg.REG_MULTI_SZ,
}

# 声明式规则表里用的是短名（dword/str/bin/...）。早期直接 REG_TYPES.get(t, REG_SZ)
# 会让 "dword" 静默退化成 REG_SZ —— 写进去的是字符串 "0" 而不是 DWORD 0，
# Windows 完全不认，界面却报"修复成功"。这里统一做别名归一，缺失即报错。
_TYPE_ALIAS = {
    "dword": "REG_DWORD", "int": "REG_DWORD", "REG_DWORD": "REG_DWORD",
    "str": "REG_SZ", "sz": "REG_SZ", "string": "REG_SZ", "REG_SZ": "REG_SZ",
    "expand": "REG_EXPAND_SZ", "expand_str": "REG_EXPAND_SZ",
    "REG_EXPAND_SZ": "REG_EXPAND_SZ",
    "bin": "REG_BINARY", "binary": "REG_BINARY", "REG_BINARY": "REG_BINARY",
    "multi": "REG_MULTI_SZ", "multi_sz": "REG_MULTI_SZ", "REG_MULTI_SZ": "REG_MULTI_SZ",
}


def reg_type_code(typ: str) -> int:
    key = _TYPE_ALIAS.get(str(typ))
    if key is None:
        raise ValueError("未知注册表类型: %r" % (typ,))
    return REG_TYPES[key]


def reg_read(hive: str, key: str, name: str = ""):
    """返回 (exists, value)；键或值不存在时 exists=False。"""
    try:
        with winreg.OpenKey(HIVES[hive], key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            try:
                v, _t = winreg.QueryValueEx(k, name)
                return True, v
            except FileNotFoundError:
                return False, None
    except FileNotFoundError:
        return False, None


def _norm_bin(value) -> bytes:
    """把 "02,00,00,00" 这类十六进制串或 bytes 统一成 bytes。"""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    txt = str(value).strip()
    if not txt:
        return b""
    parts = [p for p in re.split(r"[,\s]+", txt) if p]
    try:
        return bytes(int(p, 16) for p in parts)
    except ValueError:
        return txt.encode("latin-1", "ignore")


def reg_write(hive: str, key: str, name: str, typ: str, value) -> tuple[bool, str]:
    from .journal import ACTIVE
    if ACTIVE.get():
        ACTIVE.get().registry(hive, key, name)
    try:
        code = reg_type_code(typ)
    except ValueError as exc:
        return False, str(exc)
    # 调用方常把二进制写成 "00,00,00,00"、把多字符串写成单个 str，这里统一收口
    if code == winreg.REG_BINARY and not isinstance(value, (bytes, bytearray)):
        value = _norm_bin(value)
    elif code == winreg.REG_MULTI_SZ:
        if isinstance(value, str):
            value = [value]
        else:
            value = [str(x) for x in value]
    try:
        with winreg.CreateKeyEx(HIVES[hive], key, 0,
                                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as k:
            winreg.SetValueEx(k, name, 0, code, value)
        return True, "写入成功"
    except OSError as exc:
        return False, f"写入失败: {exc}"


def reg_delete(hive: str, key: str, name: str) -> tuple[bool, str]:
    from .journal import ACTIVE
    if ACTIVE.get():
        ACTIVE.get().registry(hive, key, name)
    try:
        with winreg.OpenKey(HIVES[hive], key, 0,
                            winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as k:
            winreg.DeleteValue(k, name)
        return True, "已删除"
    except FileNotFoundError:
        return True, "值本就不存在"
    except OSError as exc:
        return False, f"删除失败: {exc}"


def subkeys(hive: str, key: str) -> list[str]:
    out = []
    try:
        with winreg.OpenKey(HIVES[hive], key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return out


def ok(detail: str, **data) -> dict:
    return {"ok": True, "detail": detail, "data": data}


def bad(detail: str, **data) -> dict:
    return {"ok": False, "detail": detail, "data": data}


def sys32(*parts: str) -> str:
    return os.path.join(w.system_root(), "System32", *parts)


def syswow(*parts: str) -> str:
    return os.path.join(w.system_root(), "SysWOW64", *parts)


def _ver_tuple(s: str) -> tuple:
    out = []
    for p in s.split("."):
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    return tuple(out)


# ---------------------------------------------------------------- 服务

@check("svc.state")
def _svc_state(a):
    info = w.service_query(a["name"])
    if not info:
        return bad(f"服务 {a['name']} 不存在")
    want = a.get("expect", "running")
    if info["state"] != want:
        return bad(f"{a['name']} 当前 {info['state']}，期望 {want}",
                   service=info["name"], state=info["state"], want=want)
    return ok(f"{a['name']} 状态正常（{info['state']}）", service=info["name"])


@check("svc.start_type")
def _svc_start_type(a):
    info = w.service_query(a["name"])
    if not info:
        return bad(f"服务 {a['name']} 不存在")
    forbid = a.get("forbid") or []
    if info["start_type"] in forbid:
        return bad(f"{a['name']} 启动类型为 {info['start_type']}，会导致功能不可用",
                   service=info["name"], start_type=info["start_type"])
    want = a.get("expect")
    if want and info["start_type"] != want:
        return bad(f"{a['name']} 启动类型 {info['start_type']}，期望 {want}",
                   service=info["name"], start_type=info["start_type"], want=want)
    return ok(f"{a['name']} 启动类型正常（{info['start_type']}）")


@check("svc.all")
def _svc_all(a):
    """批量服务体检：一个规则覆盖一组服务。"""
    rows = []
    for item in a["items"]:
        info = w.service_query(item["name"])
        if not info:
            rows.append({"name": item["name"], "problem": "服务不存在"})
            continue
        probs = []
        if item.get("state") and info["state"] != item["state"]:
            probs.append(f"状态 {info['state']}≠{item['state']}")
        if item.get("start_type") and info["start_type"] != item["start_type"]:
            probs.append(f"启动 {info['start_type']}≠{item['start_type']}")
        if info["start_type"] == "disabled":
            probs.append("被禁用")
        if probs:
            rows.append({"name": item["name"], "problem": "；".join(probs)})
    if rows:
        return bad(f"{len(rows)} 项服务异常：" + "、".join(r["name"] for r in rows), items=rows)
    return ok(f"{len(a['items'])} 项服务全部正常")


# ---------------------------------------------------------------- 文件 / 运行库

def _candidate_dirs(a) -> list[str]:
    """DLL 查找路径。

    Windows 10 1903+ 起 api-ms-win-* 桩 DLL 不再放在 System32 根目录，
    而是按架构集中到 **两个** Downlevel 目录（本机 Win11 26300.9711 实测）：
      - 64 位：``System32\\Downlevel``   112 个文件
      - 32 位：``SysWOW64\\Downlevel``   112 个文件
    每个目录 = 91 个小写 ``api-ms-win-*`` + 20 个大写 ``API-MS-Win-*``（旧式命名）
    + 1 个 ``ucrtbase.dll``。NTFS 查找不区分大小写，所以大写那批同样能命中。
    根目录 ``System32`` 与 ``SysWOW64`` 下均为 **0 个**。

    原程序只查根目录，于是在全新 Win11 上把 123 个 x86 + 123 个 x64
    全判成“缺失”（见 analysis\\逆向分析报告.md §10 的实测取证）。
    其中 110/123 在 Downlevel 里本来就有 —— 89% 是误报，只有 13 个是真缺。

    因此这里必须做四级回退，**两个 Downlevel 都要查**，
    只加 System32\\Downlevel 会漏掉全部 32 位场景。
    """
    if a.get("dirs"):
        return [w.expand(d) for d in a["dirs"]]
    if a.get("dir"):
        return [w.expand(a["dir"])]
    root = w.system_root()
    arch = a.get("arch", 64 if w.sys.maxsize > 2**32 else 32)
    if arch == 32:
        directory = "SysWOW64" if os.path.isdir(os.path.join(root, "SysWOW64")) else "System32"
    else:
        directory = "System32"
    return [
        os.path.join(root, directory),
        os.path.join(root, directory, "Downlevel"),
    ]


@check("files.present")
def _files_present(a):
    dirs = _candidate_dirs(a)
    missing, badarch, found_in = [], [], {}
    for name in a["names"]:
        hit = None
        mismatches = []
        for d in dirs:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                if a.get("arch"):
                    pi = w.pe_info(p)
                    if not pi or pi["bits"] != a["arch"]:
                        mismatches.append(f"{name}({pi['bits'] if pi else '未知'}位)")
                        continue
                hit = p
                break
        if not hit:
            if mismatches:
                badarch.extend(mismatches)
            else:
                missing.append(name)
            continue
        found_in[name] = os.path.basename(os.path.dirname(hit))
        if a.get("arch"):
            pi = w.pe_info(hit)
            if pi and pi["bits"] != a["arch"]:
                badarch.append(f"{name}({pi['bits']}位)")
    if missing or badarch:
        parts = []
        if missing:
            parts.append(f"缺失 {len(missing)} 个：{', '.join(missing[:6])}")
        if badarch:
            parts.append(f"架构不符：{', '.join(badarch[:4])}")
        return bad(f"{'；'.join(parts)}（已检索 {', '.join(os.path.basename(d) for d in dirs)}）",
                   missing=missing, badarch=badarch, dirs=dirs)
    where = ",".join(sorted(set(found_in.values())))
    return ok(f"{len(a['names'])} 个文件齐备（位于 {where}）", found=found_in)


@check("files.version_min")
def _files_version_min(a):
    p = w.expand(a["path"])
    if not os.path.isfile(p):
        return bad(f"文件不存在：{p}", missing=[os.path.basename(p)])
    ver = w.file_version(p)
    if not ver:
        return ok(f"{os.path.basename(p)} 存在（无版本资源）")
    if _ver_tuple(ver) < _ver_tuple(a["min"]):
        return bad(f"{os.path.basename(p)} 版本 {ver} 低于 {a['min']}", version=ver)
    return ok(f"{os.path.basename(p)} 版本 {ver}")


@check("fs.writable")
def _fs_writable(a):
    return ok("只读扫描不创建探测文件；目录写权限需在具体操作时验证", skip=True)


@check("fs.size_lt")
def _fs_size_lt(a):
    p = w.expand(a["path"])
    if not os.path.isdir(p):
        return ok(f"{p} 不存在，跳过")
    total, files = w.dir_size(p)
    mb = total / 1048576
    if mb > a["max_mb"]:
        return bad(f"{p} 占用 {mb:.0f} MB（阈值 {a['max_mb']} MB，{files} 个文件）",
                   path=p, mb=round(mb, 1), files=files)
    return ok(f"{p} 占用 {mb:.0f} MB，未超阈值")


@check("disk.free")
def _disk_free(a):
    drive = a.get("drive", os.environ.get("SystemDrive", "C:") + "\\")
    info = w.disk_free(drive)
    if not info.get("ok"):
        return ok(f"{drive} 无法查询，跳过")
    free_gb = info["free"] / 1073741824
    if free_gb < a["min_gb"]:
        return bad(f"{drive} 剩余 {free_gb:.1f} GB（阈值 {a['min_gb']} GB，已用 {info['used_pct']}%）",
                   drive=drive, free_gb=round(free_gb, 1))
    return ok(f"{drive} 剩余 {free_gb:.1f} GB（已用 {info['used_pct']}%）")


# ---------------------------------------------------------------- 进程

@check("proc.cpu_hogs")
def _proc_cpu(a):
    th = a.get("threshold", 70)
    rows = [r for r in w.cpu_usage(a.get("interval", 0.5)) if r["cpu"] >= th]
    if rows:
        top = ", ".join(f"{r['name']}({r['cpu']}%)" for r in rows[:5])
        return bad(f"{len(rows)} 个进程 CPU 占用超过 {th}%：{top}", procs=rows)
    return ok(f"无进程 CPU 占用超过 {th}%")


@check("proc.absent")
def _proc_absent(a):
    names = {p["name"].lower() for p in w.process_list()}
    hit = [n for n in a["names"] if n.lower() in names]
    if hit:
        return bad(f"检测到异常进程：{', '.join(hit)}", procs=hit)
    return ok("未发现异常进程")


@check("proc.present")
def _proc_present(a):
    names = {p["name"].lower() for p in w.process_list()}
    hit = [n for n in a["names"] if n.lower() in names]
    if not hit:
        return bad(f"进程未运行：{', '.join(a['names'])}", procs=[])
    return ok(f"进程在运行：{', '.join(hit)}")


# ---------------------------------------------------------------- 注册表

@check("reg.value")
def _reg_value(a):
    exists, val = reg_read(a["hive"], a["key"], a.get("name", ""))
    if not exists:
        if a.get("missing_ok"):
            return ok(f"{a['hive']}\\{a['key']} 未配置（默认值即正常）")
        return bad(f"注册表值缺失：{a['hive']}\\{a['key']} [{a.get('name','(默认)')}]",
                   key=a["key"], name=a.get("name", ""))
    expect = a.get("expect")
    if expect is not None and str(val).lower() != str(expect).lower():
        return bad(f"{a.get('name') or '(默认)'} = {val!r}，期望 {expect!r}",
                   actual=str(val), expect=str(expect))
    if a.get("contains") and str(a["contains"]).lower() not in str(val).lower():
        return bad(f"{a.get('name')} = {val!r} 不含 {a['contains']!r}", actual=str(val))
    return ok(f"{a.get('name') or '(默认)'} = {val!r}")


@check("reg.exists")
def _reg_exists(a):
    try:
        with winreg.OpenKey(HIVES[a["hive"]], a["key"], 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return ok(f"键存在：{a['key']}")
    except OSError:
        return bad(f"注册表键缺失：{a['hive']}\\{a['key']}", key=a["key"])


@check("reg.count_lt")
def _reg_count_lt(a):
    n = len(subkeys(a["hive"], a["key"]))
    if n > a["max"]:
        return bad(f"{a['key']} 下有 {n} 项（阈值 {a['max']}）", count=n)
    return ok(f"{a['key']} 下有 {n} 项")


# ---------------------------------------------------------------- 打印机

@check("print.spooler")
def _print_spooler(a):
    info = w.service_query("Spooler")
    if not info:
        return bad("打印后台处理程序服务 Spooler 不存在")
    if info["state"] != "running":
        return bad(f"Spooler 服务未运行（{info['state']}），打印机不可用", state=info["state"])
    if info["start_type"] == "disabled":
        return bad("Spooler 服务被禁用，打印机不可用", start_type="disabled")
    return ok(f"Spooler 正常（{info['state']}/{info['start_type']}）")


@check("print.queue")
def _print_queue(a):
    d = sys32("spool", "PRINTERS")
    try:
        jobs = [f for f in os.listdir(d) if f.upper().endswith((".SPL", ".SHD"))]
    except OSError as exc:
        detail = ("打印队列目录无读取权限（需管理员），检测未完成" if isinstance(exc, PermissionError)
                  else f"无法读取打印队列，检测未完成：{exc}")
        return {"ok": False, "status": "unavailable", "detail": detail,
                "data": {"path": d, "error": type(exc).__name__}}
    if len(jobs) > a.get("max_jobs", 0):
        return bad(f"打印队列积压 {len(jobs)//2} 个任务未清理", jobs=len(jobs) // 2)
    return ok("打印队列空闲")


@check("print.exists")
def _print_exists(a):
    printers = subkeys("HKLM", r"SYSTEM\CurrentControlSet\Control\Print\Printers")
    if not printers:
        return bad("系统未安装任何打印机")
    return ok(f"已安装 {len(printers)} 台打印机")


# ---------------------------------------------------------------- 音频

@check("audio.endpoints")
def _audio_endpoints(a):
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
    active = []
    for g in subkeys("HKLM", base):
        exists, st = reg_read("HKLM", f"{base}\\{g}", "DeviceState")
        if exists and int(st or 0) & 1:
            desc = ""
            for pname in ("{a45c254e-df1c-4efd-8020-67d146a850e0},2",
                          "{b3f8fa53-0004-438e-9003-51a46e139bfc},6"):
                e2, v2 = reg_read("HKLM", f"{base}\\{g}\\Properties", pname)
                if e2 and v2:
                    desc = str(v2)
                    break
            active.append(desc or g)
    if not active:
        return bad("未检测到可用音频输出设备，电脑可能没有声音", endpoints=[])
    return ok(f"检测到 {len(active)} 个可用音频输出设备：{'、'.join(active[:3])}", endpoints=active)


@check("audio.services")
def _audio_services(a):
    bads = []
    for name in ("Audiosrv", "AudioEndpointBuilder"):
        info = w.service_query(name)
        if not info:
            bads.append(f"{name} 缺失")
        elif info["state"] != "running":
            bads.append(f"{name}={info['state']}")
        elif info["start_type"] == "disabled":
            bads.append(f"{name} 被禁用")
    if bads:
        return bad("音频服务异常：" + "、".join(bads), items=bads)
    return ok("音频服务正常")


# ---------------------------------------------------------------- DirectX / VC 运行库

@check("dx.present")
def _dx_present(a):
    need = ["d3d9.dll", "dxgi.dll", "d3d11.dll", "d3dcompiler_47.dll"]
    missing = [n for n in need if not os.path.isfile(sys32(n))]
    if missing:
        return bad(f"DirectX 组件缺失：{', '.join(missing)}", missing=missing)
    exists, ver = reg_read("HKLM", r"SOFTWARE\Microsoft\DirectX", "Version")
    return ok(f"DirectX 组件齐备（{ver if exists else '未知版本'}）")


@check("vcrt.present")
def _vcrt_present(a):
    need = ["msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll", "concrt140.dll"]
    missing = [n for n in need if not os.path.isfile(sys32(n))]
    if missing:
        return bad(f"VC++ 运行库缺失：{', '.join(missing)}", missing=missing)
    return ok("VC++ 2015-2022 运行库齐备")


# ---------------------------------------------------------------- 系统

@check("dump.config")
def _dump_config(a):
    key = r"SYSTEM\CurrentControlSet\Control\CrashControl"
    exists, enabled = reg_read("HKLM", key, "CrashDumpEnabled")
    if not exists:
        return bad("CrashControl 未配置 CrashDumpEnabled，蓝屏后无法生成转储")
    if int(enabled) == 0:
        return bad("系统已关闭内存转储（CrashDumpEnabled=0），蓝屏无法定位原因")
    e2, path = reg_read("HKLM", key, "DumpFile")
    return ok(f"转储已启用（模式 {enabled}，文件 {path}）")


@check("wer.config")
def _wer_config(a):
    # WerSvc 是「手动/按需启动」服务，平时处于 stopped 属正常状态——
    # 崩溃发生时才被拉起。因此只有「被禁用」才算配置异常，
    # 把 stopped 判成异常会在几乎每台健康机器上误报。
    info = w.service_query("WerSvc")
    if info and info["start_type"] == "disabled":
        return bad(f"Windows 错误报告服务被禁用（启动类型 {info['start_type']}）",
                   severity="warn")
    exists, dis = reg_read("HKLM", r"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
                           "Disabled")
    if exists and int(dis) == 1:
        return bad("Windows 错误报告被全局禁用，崩溃信息无法收集", severity="warn")
    return ok("错误报告配置正常")


@check("shell.config")
def _shell_config(a):
    key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    e1, shell = reg_read("HKLM", key, "Shell")
    e2, userinit = reg_read("HKLM", key, "Userinit")
    if e1 and str(shell).lower() != "explorer.exe":
        return bad(f"Winlogon Shell 被篡改：{shell}", actual=str(shell))
    if e2 and "userinit.exe" not in str(userinit).lower():
        return bad(f"Winlogon Userinit 异常：{userinit}", actual=str(userinit))
    return ok("Winlogon 外壳配置正常")


@check("assoc.exe")
def _assoc_exe(a):
    e1, v = reg_read("HKCR", ".exe")
    if not e1 or str(v).lower() != "exefile":
        return bad(f".exe 文件关联异常：{v!r}", actual=str(v))
    e2, cmd = reg_read("HKCR", r"exefile\shell\open\command")
    if not e2 or "%1" not in str(cmd):
        return bad(f"exefile 打开命令异常：{cmd!r}", actual=str(cmd))
    return ok(".exe 关联正常")


@check("assoc.lnk")
def _assoc_lnk(a):
    e1, v = reg_read("HKCR", ".lnk")
    if not e1 or str(v).lower() != "lnkfile":
        return bad(f".lnk 快捷方式关联异常：{v!r}", actual=str(v))
    if not os.path.isfile(sys32("..", "System32", "shell32.dll")):
        pass
    return ok(".lnk 关联正常")


@check("startup.count")
def _startup_count(a):
    keys = [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    total = 0
    names = []
    for hive, key in keys:
        for sub in subkeys(hive, key):
            pass
        try:
            with winreg.OpenKey(HIVES[hive], key, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                        total += 1
                        names.append(n)
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass
    if total > a["max"]:
        return bad(f"开机启动项 {total} 个（阈值 {a['max']}），会拖慢开机速度",
                   count=total, items=names[:12])
    return ok(f"开机启动项 {total} 个，未超阈值")


@check("wmi.repo")
def _wmi_repo(a):
    info = w.service_query("Winmgmt")
    if info and info["state"] != "running" and info["start_type"] != "disabled":
        return bad(f"WMI 服务 Winmgmt 未运行（{info['state']}）")
    repo = os.path.join(w.system_root(), "System32", "wbem", "Repository", "OBJECTS.DATA")
    if not os.path.isfile(repo):
        return bad("WMI 存储库 OBJECTS.DATA 损坏或缺失")
    mb = os.path.getsize(repo) / 1048576
    if mb > a.get("max_mb", 2048):
        return bad(f"WMI 存储库异常膨胀（{mb:.0f} MB）", mb=round(mb, 1))
    return ok(f"WMI 存储库正常（{mb:.0f} MB）")


@check("net.winsock")
def _net_winsock(a):
    n = len(subkeys("HKLM",
                    r"SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\Protocol_Catalog9\Catalog_Entries"))
    if n == 0:
        return bad("Winsock 目录为空，网络协议栈可能损坏")
    return ok(f"Winsock 协议目录正常（{n} 项）")


@check("time.sane")
def _time_sane(a):
    t = w.local_time()
    if t["year"] < 2020:
        return bad(f"系统时间异常：{t['year']}-{t['month']:02d}-{t['day']:02d}")
    return ok(f"系统时间正常：{t['year']}-{t['month']:02d}-{t['day']:02d}")


@check("explorer.alive")
def _explorer_alive(a):
    n = sum(1 for p in w.process_list() if p["name"].lower() == "explorer.exe")
    if n == 0:
        return bad("资源管理器 explorer.exe 未运行，桌面可能空白")
    return ok(f"explorer.exe 运行中（{n} 个实例）")


@check("payload.check")
def _payload_check(a):
    d = w.expand(a["dir"])
    need = a.get("must") or []
    missing = [n for n in need if not os.path.isfile(os.path.join(d, n))]
    if missing:
        return bad(f"修复资源包不完整，缺少 {', '.join(missing[:5])}", missing=missing)
    return ok(f"修复资源包完整（{d}）")


# ---------------------------------------------------------------- 修复动作

@fix("svc.start")
def _f_svc_start(a):
    return w.service_start(a["name"])


@fix("svc.set_start")
def _f_svc_set(a):
    return w.service_set_start_type(a["name"], a["start_type"])


@fix("svc.restart")
def _f_svc_restart(a):
    w.service_stop(a["name"])
    time.sleep(1.0)
    return w.service_start(a["name"])


@fix("files.restore")
def _f_files_restore(a):
    src = w.expand(a["src_dir"])
    dst = w.expand(a.get("dst_dir") or sys32())
    names = a.get("names") or []
    if not names:
        return False, "未指定要恢复的文件"
    done, fail = [], []
    for n in names:
        s, d = os.path.join(src, n), os.path.join(dst, n)
        if not os.path.isfile(s):
            fail.append(f"{n}(源缺失)")
            continue
        try:
            from .journal import ACTIVE
            if ACTIVE.get():
                ACTIVE.get().file(d)
            if os.path.isfile(d):
                shutil.copy2(d, d + ".ksr.bak")
            shutil.copy2(s, d)
            done.append(n)
        except OSError as exc:
            fail.append(f"{n}({exc.__class__.__name__})")
    msg = f"已恢复 {len(done)} 个文件"
    if fail:
        msg += f"，失败 {len(fail)} 个：{', '.join(fail[:4])}"
    return (not fail), msg


@fix("reg.set")
def _f_reg_set(a):
    return reg_write(a["hive"], a["key"], a.get("name", ""),
                     a.get("type", "REG_SZ"), a["value"])


@fix("reg.delete")
def _f_reg_delete(a):
    return reg_delete(a["hive"], a["key"], a.get("name", ""))


@fix("print.clear_queue")
def _f_print_clear(a):
    d = sys32("spool", "PRINTERS")
    if not os.path.isdir(d):
        return True, "队列目录不存在"
    removed = 0
    for f in os.listdir(d):
        if f.upper().endswith((".SPL", ".SHD")):
            try:
                os.remove(os.path.join(d, f))
                removed += 1
            except OSError:
                return False, "清理队列失败（需要管理员权限且需先停止 Spooler）"
    return True, f"已清理 {removed // 2} 个打印任务"


@fix("proc.kill")
def _f_proc_kill(a):
    targets = {n.lower() for n in a["names"]}
    victims = [p for p in w.process_list() if p["name"].lower() in targets]
    if not victims:
        return True, "目标进程未运行"
    okc, fail = 0, []
    for p in victims:
        good, msg = w.process_kill(p["pid"])
        if good:
            okc += 1
        else:
            fail.append(f"{p['name']}({msg})")
    return (not fail), f"已结束 {okc} 个进程" + (f"，失败：{', '.join(fail[:3])}" if fail else "")


@fix("fs.clean")
def _f_fs_clean(a):
    d = w.expand(a["path"])
    if not os.path.isdir(d):
        return True, "目录不存在"
    patterns = a.get("patterns") or ["*"]
    older = a.get("older_days", 0)
    cutoff = time.time() - older * 86400
    freed = 0
    n = 0
    maximum = max(0, int(a.get("max_files", 5000)))
    if maximum == 0:
        return True, "数量上限为 0，未清理文件"
    for root, _dirs, files in os.walk(d, onerror=lambda e: None):
        _dirs[:] = [name for name in _dirs if not os.path.islink(os.path.join(root, name))
                    and not os.path.isjunction(os.path.join(root, name))] if hasattr(os.path, "isjunction") else [
                        name for name in _dirs if not os.path.islink(os.path.join(root, name))]
        for name in files:
            if not any(fnmatch.fnmatch(name.lower(), p.lower()) for p in patterns):
                continue
            p = os.path.join(root, name)
            if os.path.islink(p):
                continue
            try:
                st = os.stat(p)
                if older and st.st_mtime > cutoff:
                    continue
                os.remove(p)
                freed += st.st_size
                n += 1
            except OSError:
                pass
            if n >= maximum:
                return True, f"清理 {n} 个文件，释放 {freed / 1048576:.1f} MB（达到数量上限）"
    return True, f"清理 {n} 个文件，释放 {freed / 1048576:.1f} MB"


@fix("explorer.restart")
def _f_explorer_restart(a):
    victims = [p for p in w.process_list() if p["name"].lower() == "explorer.exe"]
    for p in victims:
        w.process_kill(p["pid"])
    return True, "已结束 explorer.exe，系统将自动重启外壳"


@fix("dump.set")
def _f_dump_set(a):
    key = r"SYSTEM\CurrentControlSet\Control\CrashControl"
    ok1, m1 = reg_write("HKLM", key, "CrashDumpEnabled", "REG_DWORD",
                        a.get("mode", 7))
    ok2, m2 = reg_write("HKLM", key, "AutoReboot", "REG_DWORD", 1)
    return (ok1 and ok2), f"{m1}；{m2}"


@fix("audio.restart")
def _f_audio_restart(a):
    msgs = []
    for name in ("AudioEndpointBuilder", "Audiosrv"):
        w.service_set_start_type(name, "auto")
        w.service_stop(name)
        time.sleep(0.5)
        good, msg = w.service_start(name)
        msgs.append(f"{name}:{msg}")
    return True, "；".join(msgs)


@fix("net.flush_dns")
def _f_flush_dns(a):
    import subprocess

    try:
        r = subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                           timeout=20, creationflags=0x08000000)
        return r.returncode == 0, "DNS 缓存已刷新" if r.returncode == 0 else "刷新失败"
    except Exception as exc:  # noqa: BLE001
        return False, f"刷新失败: {exc}"


@fix("assoc.repair")
def _f_assoc_repair(a):
    ext = a["ext"]
    progid = a["progid"]
    ok1, m1 = reg_write("HKCR", ext, "", "REG_SZ", progid)
    if a.get("command"):
        ok2, m2 = reg_write("HKCR", rf"{progid}\shell\open\command", "",
                            "REG_SZ", a["command"])
    return ok1, f"{ext} -> {progid}"


# ================================================================ 清单清点与运行库
# 对应原程序界面里的「DLL 文件」「常用运行库」「游戏必备组件」三块。
#
# 与原程序的关键差异：这里的判定分 tier（见 catalog.py）——
#   CORE 缺失 -> error，真故障
#   COMPAT 缺失 -> info，兼容性提示，正常系统也可能如此
# 原程序把两者混为一谈，在全新系统上会报出上百个"异常"，本实现不这样做。

_NO_WINDOW = 0x08000000

# 核心 COM 组件：DLL 名 -> (CLSID, 显示名)
# 这些 CLSID 均在本机实测可读，用 InprocServer32 是否存在判定"是否已注册"。
REG_DLLS = [
    ("jscript.dll",  "{F414C260-6AC0-11CF-B6D1-00AA00BBBB58}", "JScript 脚本引擎"),
    ("vbscript.dll", "{B54F3741-5B07-11CF-A4B0-00AA004A55E8}", "VBScript 脚本引擎"),
    ("scrrun.dll",   "{EE09B103-97E0-11CF-978F-00A02463E06F}", "脚本文件对象 (FSO)"),
    ("msxml3.dll",   "{F5078F35-C551-11D3-89B9-0000F81FE221}", "MSXML 3.0 解析器"),
    ("msxml6.dll",   "{88D96A05-F192-11D4-A65F-0040963251E5}", "MSXML 6.0 解析器"),
    ("zipfldr.dll",  "{E88DCCE0-B7B3-11D1-A9F0-00AA0060FA31}", "压缩文件夹支持"),
    ("shell32.dll",  "{13709620-C279-11CE-A49E-444553540000}", "Shell 应用对象"),
]

# VC++ 运行库的注册表位置，按代际。本机实测四代键名各不相同，不能套用同一个模板：
#   14.0 子键写成大写 X64/X86，10.0 的父键叫 VCRedist 而不是 Runtimes。
# 注意这里必须带 SOFTWARE\ 前缀——WOW6432Node 是 SOFTWARE 下的重定向视图，
# 少写一层就会全部读不到，把已装的运行库误报成"未安装"。
VC_GENERATIONS = [
    (14, "VC++ 2015-2022", r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes"),
    (12, "VC++ 2013",      r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\12.0\VC\Runtimes"),
    (11, "VC++ 2012",      r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\11.0\VC\Runtimes"),
    (10, "VC++ 2010",      r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\10.0\VC\VCRedist"),
]

OFFICIAL_URLS = {
    "directx": ("https://download.microsoft.com/download/1/7/1/"
                "1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"),
    "msxml4": ("https://www.microsoft.com/en-us/download/details.aspx?id=19662"),
}

# VC++ 各代际的官方安装包地址。每一条都在 2026-11-01 实测过 HTTP 200 且体积合理；
# 没验证到的一律不进表 —— 宁可界面上写「需手动安装」，也不要放一个点了没反应的按钮。
# 已知失效：VC++ 2008（5D8C65CB…）、VC++ 2013 x64 的 download.microsoft.com 直链。
VC_INSTALLERS = {
    (14, "x64"): "https://aka.ms/vs/17/release/vc_redist.x64.exe",
    (14, "x86"): "https://aka.ms/vs/17/release/vc_redist.x86.exe",
    (12, "x86"): ("https://download.microsoft.com/download/2/E/6/"
                  "2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe"),
    (11, "x64"): ("https://download.microsoft.com/download/1/6/B/"
                  "16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"),
    (10, "x64"): ("https://download.microsoft.com/download/1/6/5/"
                  "165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe"),
    (10, "x86"): ("https://download.microsoft.com/download/C/6/D/"
                  "C6D0FD4E-9E53-4897-9B91-836EBA2AACD3/vcredist_x86.exe"),
    (8, "x86"): ("https://download.microsoft.com/download/8/B/4/"
                 "8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.exe"),
}

# 静默安装参数按代际分开：2005 的 vcredist.exe 不认 /install /quiet 这套。
VC_INSTALL_ARGS_DEFAULT = ["/install", "/quiet", "/norestart"]
VC_INSTALL_ARGS = {8: ["/q"]}


def _find_dll(name: str) -> str | None:
    """在四级目录（System32 / SysWOW64 / 两个 Downlevel）里查 DLL。"""
    for d in _candidate_dirs({}):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            info = w.pe_info(p)
            if info and info["bits"] == (64 if w.sys.maxsize > 2**32 else 32):
                return p
    return None


def _vc80_sxs(arch="x86"):
    """Inventory a complete VC80 CRT assembly; not an app activation/load test."""
    if arch not in {"x86", "x64"}:
        return bad(f"不支持的 VC++ 2005 架构：{arch}")
    processor = "amd64" if arch == "x64" else "x86"
    root = Path(w.system_root()) / "WinSxS"
    pattern = re.compile(rf"{processor}_microsoft\.vc80\.crt_1fc8b3b9a1e18e3b_"
                         r"(8\.\d+\.\d+\.\d+)_none_[a-z0-9]+", re.I)
    assemblies = []
    try:
        folders = list(root.iterdir()) if root.exists() else []
        for folder in folders:
            match = pattern.fullmatch(folder.name)
            if not match or not folder.is_dir():
                continue
            manifest = root / "Manifests" / (folder.name + ".manifest")
            try:
                document = ET.parse(manifest)
            except (FileNotFoundError, ET.ParseError):
                continue
            identity = document.getroot().find("{urn:schemas-microsoft-com:asm.v1}assemblyIdentity")
            if identity is None or any(identity.get(key, "").lower() != value.lower() for key, value in {
                "name": "Microsoft.VC80.CRT", "type": "win32", "processorArchitecture": processor,
                "publicKeyToken": "1fc8b3b9a1e18e3b", "version": match.group(1),
            }.items()):
                continue
            payloads = [w.pe_info(str(folder / name)) for name in catalog.BY_ID['vc80']['files']]
            if all(info and info["arch"] == arch for info in payloads):
                assemblies.append({"version": match.group(1), "directory": str(folder), "manifest": str(manifest)})
    except OSError as exc:
        return {"ok": False, "status": "unavailable", "detail": f"无法读取 VC++ 2005 WinSxS 清单：{exc}",
                "data": {"cat": "vc80", "arch": arch}}
    if assemblies:
        assemblies.sort(key=lambda row: tuple(map(int, row['version'].split('.'))), reverse=True)
        return ok(f"VC++ 2005 ({arch}) WinSxS 清单及 CRT 文件齐备，版本 {assemblies[0]['version']}",
                  cat="vc80", arch=arch, assemblies=assemblies,
                  verification="assembly_inventory; not application activation")
    return bad(f"未找到完整的 VC++ 2005 ({arch}) WinSxS CRT 程序集（兼容组件，按需安装）",
               cat="vc80", arch=arch, severity="info", tier=catalog.COMPAT)


@check("dll.catalog")
def _dll_catalog(a):
    """按清单分组清点文件。args: {cat}"""
    cat_id = a["cat"]
    cat = catalog.BY_ID.get(cat_id)
    if not cat:
        return bad(f"未知清单分类 {cat_id}")
    if cat_id == "vc80":
        return _vc80_sxs(a.get("arch", "x86"))
    files = [name for name in cat["files"] if not name.lower().startswith(("api-", "ext-"))]
    missing = [f for f in files if not _find_dll(f)]
    tier = cat["tier"]
    if not missing:
        return ok(f"{len(files)} 个文件齐备", total=len(files), cat=cat_id)
    sev = "error" if tier == catalog.CORE else "info"
    head = "必需文件缺失" if sev == "error" else "兼容版本未安装"
    tail = ""
    if len(missing) > 6:
        tail = f" 等 {len(missing)} 个"
        names = ", ".join(missing[:6])
    else:
        names = ", ".join(missing)
    return bad(f"{head}：{names}{tail}",
               severity=sev, missing=missing, total=len(files),
               tier=tier, cat=cat_id, fix=cat.get("fix"),
               purpose=cat.get("purpose", ""))


@check("vcredist.probe")
def _vcredist_probe(a):
    """按代际 + 架构清点 VC++ 运行库。args: {major?: int, arch?: 'x64'|'x86'}"""
    want_major = a.get("major")
    want_arch = a.get("arch")
    rows, missing = [], []
    for major, label, path in VC_GENERATIONS:
        if want_major and major != want_major:
            continue
        for arch in ("x64", "x86"):
            if want_arch and arch != want_arch:
                continue
            ex_i, installed = reg_read("HKLM", f"{path}\\{arch}", "Installed")
            ex_v, ver = reg_read("HKLM", f"{path}\\{arch}", "Version")
            good = bool(ex_i and installed)
            row = {"major": major, "label": label, "arch": arch,
                   "installed": good, "version": ver if ex_v else ""}
            rows.append(row)
            if not good:
                missing.append(f"{label} ({arch})")
    if missing:
        return bad(f"未安装 {len(missing)} 项：{'、'.join(missing)}",
                   severity="error", items=rows, missing=missing)
    return ok(f"{len(rows)} 项运行库均已安装", items=rows)


@check("regsvr.state")
def _regsvr_state(a):
    """核心 COM 组件是否已注册。args: {dlls?: [...]}"""
    names = a.get("dlls") or [d for d, _, _ in REG_DLLS]
    table = {d: (g, lbl) for d, g, lbl in REG_DLLS}
    unreg, absent = [], []
    for dll in names:
        guid, label = table.get(dll, (None, dll))
        if not _find_dll(dll):
            absent.append(dll)
            continue
        if not guid:
            continue
        exists, _ = reg_read("HKCR", rf"CLSID\{guid}\InprocServer32", "")
        if not exists:
            unreg.append(f"{label}({dll})")
    if unreg or absent:
        parts = []
        if unreg:
            parts.append(f"未注册 {len(unreg)} 个：{'、'.join(unreg)}")
        if absent:
            parts.append(f"文件缺失：{'、'.join(absent)}")
        return bad("；".join(parts), severity="error",
                   unregistered=unreg, absent=absent)
    return ok(f"{len(names)} 个核心组件注册状态正常")


@check("dx.runtime")
def _dx_runtime(a):
    """DirectX 运行时版本与 DX9 兼容层的可用性。"""
    ex, ver = reg_read("HKLM", r"SOFTWARE\Microsoft\DirectX", "Version")
    need = ["d3dx9_43.dll", "d3dcompiler_43.dll", "xinput1_3.dll"]
    missing = [n for n in need if not _find_dll(n)]
    if missing:
        return bad(f"DX9 兼容层不完整，缺：{', '.join(missing)}",
                   severity="info", missing=missing, version=ver if ex else "")
    return ok(f"DirectX {ver if ex else '版本未知'}，DX9 兼容层完整")


# ---------------------------------------------------------------- 修复动作

@check("dotnet.version")
def _dotnet_version(a):
    """.NET Framework 4.x 版本。args: {min_release?: int}"""
    key = r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
    exists, release = reg_read("HKLM", key, "Release")
    ex_v, ver = reg_read("HKLM", key, "Version")
    if not exists or not isinstance(release, int):
        return bad("未安装 .NET Framework 4.x（大量软件依赖它）",
                   severity="error", release=0)
    need = int(a.get("min_release", 528040))  # 528040 = 4.8
    if release < need:
        return bad(f".NET Framework {ver} 低于要求（Release {release} < {need}）",
                   severity="warn", release=release, version=ver)
    return ok(f".NET Framework {ver}（Release {release}）", release=release)


def _download(url: str, dst: str, timeout: int = 300) -> tuple[bool, str]:
    from .downloads import download
    return download(url, dst, timeout)


def _run_installer(path: str, args: list[str], timeout: int = 900) -> FixResult:
    """静默运行安装包，保留退出码与动态重启要求。"""
    from .downloads import verify_microsoft
    verified, message = verify_microsoft(path)
    if not verified:
        return FixResult(False, message)
    try:
        r = subprocess.run([path, *args], capture_output=True,
                           timeout=timeout, creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        return FixResult(False, f"安装超时（{timeout} 秒）")
    except Exception as exc:  # noqa: BLE001
        return FixResult(False, f"无法启动安装包：{exc.__class__.__name__}: {exc}")
    if r.returncode == 0:
        return FixResult(True, "安装完成", exit_codes=(r.returncode,))
    if r.returncode == 3010:
        return FixResult(True, "安装完成（需重启生效）", needs_reboot=True, exit_codes=(r.returncode,))
    if r.returncode == 1638:
        return FixResult(True, "已安装另一版本，需复检是否满足要求", exit_codes=(r.returncode,))
    return FixResult(False, f"安装包返回 {r.returncode}", exit_codes=(r.returncode,))


@fix("regsvr.run")
def _f_regsvr_run(a):
    dlls = a.get("dlls") or [d for d, _, _ in REG_DLLS]
    exe = os.path.join(w.system_root(), "System32", "regsvr32.exe")
    done, fail = [], []
    for dll in dlls:
        p = _find_dll(dll)
        if not p:
            fail.append(f"{dll}(文件缺失)")
            continue
        try:
            r = subprocess.run([exe, "/s", p], capture_output=True,
                               timeout=60, creationflags=_NO_WINDOW)
        except Exception as exc:  # noqa: BLE001
            fail.append(f"{dll}({exc.__class__.__name__})")
            continue
        if r.returncode == 0:
            done.append(dll)
        else:
            fail.append(f"{dll}(rc={r.returncode})")
    msg = f"已重新注册 {len(done)} 个组件"
    if fail:
        msg += f"，失败 {len(fail)} 个：{'、'.join(fail[:5])}"
    return (not fail), msg


@fix("vcredist.install")
def _f_vcredist_install(a):
    """安装 VC++ 运行库。args: {gen: 8|10|11|12|14, arch?: 'x64'|'x86'}

    gen 对应 VC_GENERATIONS 的版本号；不传 arch 就把该代际所有已验证架构都装一遍。
    """
    if not w.is_admin():
        return FixResult(False, "安装运行库需要管理员权限，请以管理员身份重开本程序")
    gen = int(a.get("gen", 14))
    want_arch = a.get("arch")
    targets = sorted((g, ar) for (g, ar) in VC_INSTALLERS
                     if g == gen and (not want_arch or ar == want_arch))
    if not targets:
        return FixResult(False, f"VC++ {gen} 这一代暂无已验证的官方安装包地址，请按官网手动安装")

    parts, all_ok = [], True
    needs_reboot, exit_codes = False, []
    for g, ar in targets:
        url = VC_INSTALLERS[(g, ar)]
        with tempfile.TemporaryDirectory(prefix="ksr_install_") as folder:
            dst = os.path.join(folder, f"vc_{g}_{ar}.exe")
            good, msg = _download(url, dst)
            if not good:
                all_ok = False
                parts.append(f"{ar} 下载失败：{msg}")
                continue
            result = _run_installer(dst, VC_INSTALL_ARGS.get(g, VC_INSTALL_ARGS_DEFAULT))
            all_ok = all_ok and result.ok
            needs_reboot = needs_reboot or result.needs_reboot
            exit_codes.extend(result.exit_codes)
            parts.append(f"{ar} {result.message}")
    return FixResult(all_ok, "；".join(parts), needs_reboot, tuple(exit_codes))


@fix("directx.install")
def _f_directx_install(a):
    if not w.is_admin():
        return FixResult(False, "安装 DirectX 需要管理员权限，请以管理员身份重开本程序")
    with tempfile.TemporaryDirectory(prefix="ksr_install_") as folder:
        dst = os.path.join(folder, "dxwebsetup.exe")
        good, msg = _download(OFFICIAL_URLS["directx"], dst)
        if not good:
            return FixResult(False, msg)
        result = _run_installer(dst, ["/Q"], timeout=1200)
        return FixResult(result.ok, f"{msg}；{result.message}", result.needs_reboot, result.exit_codes)


# ====================================================================
# 系统优化检测族（逆向自 ksd.nlb 规则 #387 serviceoptmin / #399 systemoptimize）
#
# 原版在 Lua 里对每个检查点跑一次 GetValue/ExistValue，然后 E_UpAbnormalData
# 上报一行 level=1|9。这里把「探针规格」抽成数据（见 sysopt.py），执行器统一
# 解释，好处是新增检查点只改表、不改代码，也便于逐条对齐原件。
# ====================================================================

def _as_lua_str(v) -> str:
    """模拟 Lua 的 tostring()：nil -> 'nil'，其余转字符串。"""
    if v is None:
        return "nil"
    if isinstance(v, bytes):
        try:
            return v.decode("utf-16-le", "ignore").rstrip("\x00")
        except Exception:
            return v.hex()
    return str(v)


def _reg_bytes(val) -> bytes:
    """把 REG_BINARY 读出来的值统一成 bytes。"""
    if isinstance(val, bytes):
        return val
    if isinstance(val, bytearray):
        return bytes(val)
    if isinstance(val, str):
        return val.encode("latin-1", "ignore")
    return b""


def _key_exists(hive: str, key: str) -> bool:
    try:
        with winreg.OpenKey(HIVES[hive], key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        return False


def osver_name() -> str:
    """对齐 _kereng_prelude.lua:5727 的 osinfo()，返回 xp/vista/win7/win8/win8.1/win10/win11。

    原版拿 CurrentBuildNumber 做**字符串**比较（"19045" >= "22000" 为假，
    但 "9999" >= "22000" 也会为假——这点不影响正确性，保持一致即可）。
    """
    ex, ver = reg_read("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                       "CurrentVersion")
    ex2, build = reg_read("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          "CurrentBuildNumber")
    ver = str(ver or "").strip()
    build = str(build or "").strip()
    if not ex or not ex2:
        return "fail"
    if ver in ("5.1", "5.2"):
        return "xp"
    if ver == "6.0":
        return "vista"
    if ver == "6.1":
        return "win7"
    if ver == "6.2":
        return "win8"
    if ver == "6.3" and build == "9600":
        return "win8.1"
    win10_builds = {"10586", "14393", "15063", "16299", "17134", "17763",
                    "18362", "18363", "19041", "19042", "19043", "19044"}
    if ver in ("6.3", "6.4", "10.0"):
        if build in win10_builds or ("19045" <= build < "22000"):
            return "win10"
        if build >= "22000":
            return "win11"
    return "fail"


def _expand(path: str) -> str:
    """展开 %VAR% 形式的系统变量（对齐原版交给 cmd 的 if exist 语义）。"""
    out = w.expand(path)
    return out.strip().strip('"')


def _run_probe(spec: dict) -> tuple[bool | None, str, dict]:
    """执行一条探针规格。

    返回 (state, detail, extra)：
      True  -> 需优化（原版 level=1）
      False -> 已达标（原版 level=9）
      None  -> 本机不适用（原版此分支根本不执行 / 不读取，界面不出现该项）
    """
    t = spec["t"]

    if t == "reg":
        ex, val = reg_read(spec["hive"], spec["key"], spec["name"])
        got = _as_lua_str(val) if ex else "nil"
        extra = {"hive": spec["hive"], "key": spec["key"], "name": spec["name"],
                 "actual": got, "expect": spec["ne"]}
        if not ex:
            miss = spec.get("missing", "bad")
            if miss == "skip":
                return None, "注册表值不存在，本机不适用", extra
            if miss == "ok":
                return False, "值不存在（期望 %s），原版此分支判为已达标" % spec["ne"], extra
            return True, "值不存在（期望 %s）" % spec["ne"], extra
        if got != spec["ne"]:
            return True, "当前 %s，期望 %s" % (got, spec["ne"]), extra
        return False, "当前 %s，已符合" % got, extra

    if t == "reg_notin":
        ex, val = reg_read(spec["hive"], spec["key"], spec["name"])
        got = _as_lua_str(val) if ex else "nil"
        allow = spec["allow"]
        extra = {"hive": spec["hive"], "key": spec["key"], "name": spec["name"],
                 "actual": got, "expect": " / ".join(allow)}
        if not ex:
            miss = spec.get("missing", "bad")
            if miss == "skip":
                return None, "注册表值不存在，本机不适用", extra
            if miss == "ok":
                return False, "值不存在，原版此分支判为已达标", extra
            return True, "值不存在", extra
        if got not in allow:
            return True, "当前 %s，只接受 %s" % (got, " / ".join(allow)), extra
        return False, "当前 %s，已符合" % got, extra

    if t == "reg_multi":
        rows, allok = [], True
        for nm, want in spec["pairs"]:
            ex, val = reg_read(spec["hive"], spec["key"], nm)
            got = _as_lua_str(val) if ex else "nil"
            good = bool(ex) and got == want
            allok = allok and good
            rows.append({"name": nm, "actual": got, "expect": want, "ok": good})
        extra = {"hive": spec["hive"], "key": spec["key"], "values": rows}
        if allok:
            return False, "全部已符合：" + "、".join(
                "%s=%s" % (r["name"], r["actual"]) for r in rows), extra
        wrong = [r for r in rows if not r["ok"]]
        return True, "、".join(
            "%s=%s(期望%s)" % (r["name"], r["actual"], r["expect"]) for r in wrong), extra

    if t in ("reg_or", "reg_and"):
        rows, hits, miss_all = [], 0, True
        for pr in spec["pairs"]:
            ex, val = reg_read(pr["hive"], pr["key"], pr["name"])
            got = _as_lua_str(val) if ex else "nil"
            hit = bool(ex) and got == pr["ne"]
            hits += 1 if hit else 0
            miss_all = miss_all and not ex
            rows.append({"hive": pr["hive"], "key": pr["key"], "name": pr["name"],
                         "actual": got, "expect": pr["ne"], "ok": hit})
        extra = {"values": rows}
        if miss_all:
            return None, "相关注册表值均不存在，本机不适用", extra
        if t == "reg_or":
            # 任一不满足即需优化
            bad = [r for r in rows if not r["ok"]]
            if bad:
                return True, "、".join(
                    "%s=%s(期望%s)" % (r["name"], r["actual"], r["expect"])
                    for r in bad), extra
            return False, "两项均已符合", extra
        # reg_and：全部满足才需优化
        if hits == len(rows):
            return True, "、".join(
                "%s=%s" % (r["name"], r["actual"]) for r in rows), extra
        return False, "未同时满足，判为正常", extra

    if t == "svc":
        info = w.service_query(spec["name"])
        want = spec["ne"]
        if not info:
            miss_ok = spec.get("missing", "ok") == "ok"
            return (not miss_ok), "服务不存在（期望启动类型 %s）" % want, {
                "service": spec["name"], "actual": "missing"}
        code = info["start_type_code"]
        extra = {"service": spec["name"], "actual": code, "expect": want,
                 "start_type": info["start_type"], "state": info["state"]}
        if code != want:
            return True, "%s 启动类型 %s（%s），期望 %s" % (
                spec["name"], info["start_type"], code, want), extra
        return False, "%s 启动类型正常（%s）" % (spec["name"], info["start_type"]), extra

    if t == "svcs":
        bad_list, rows = [], []
        for nm in spec["names"]:
            info = w.service_query(nm)
            code = info["start_type_code"] if info else None
            row = {"name": nm, "actual": code, "expect": spec["ne"],
                   "ok": (code == spec["ne"])}
            rows.append(row)
            if not row["ok"]:
                bad_list.append(nm)
        extra = {"services": rows}
        if bad_list:
            return True, "%d 项异常：%s" % (len(bad_list), "、".join(bad_list)), extra
        return False, "%d 项服务启动类型全部正常" % len(spec["names"]), extra

    if t == "key_exists":
        exists = _key_exists(spec["hive"], spec["key"])
        extra = {"hive": spec["hive"], "key": spec["key"], "exists": exists}
        if exists:
            return True, "shell 扩展注册项存在", extra
        return None, "未检出该注册项", extra

    if t == "key_absent":
        exists = _key_exists(spec["hive"], spec["key"])
        extra = {"hive": spec["hive"], "key": spec["key"], "exists": exists}
        if exists:
            return False, "注册项已存在", extra
        return True, "注册项不存在", extra

    if t == "path_exists":
        ex, val = reg_read(spec["hive"], spec["key"], spec["name"])
        raw = _as_lua_str(val) if ex else ""
        if not ex or not raw.strip():
            return None, "未读到桌面路径配置，本机不适用", {
                "hive": spec["hive"], "key": spec["key"], "name": spec["name"],
                "actual": raw or "missing"}
        real = _expand(raw)
        extra = {"hive": spec["hive"], "key": spec["key"], "name": spec["name"],
                 "actual": raw, "resolved": real,
                 "expect": "目录必须真实存在"}
        if os.path.isdir(real):
            return False, "路径存在：%s" % real, extra
        return True, "路径不存在：%s" % real, extra

    if t == "path_lower":
        ex, val = reg_read(spec["hive"], spec["key"], spec["name"])
        got = _as_lua_str(val) if ex else "nil"
        want = _expand(spec["expect"])
        extra = {"hive": spec["hive"], "key": spec["key"], "name": spec["name"],
                 "actual": got, "expect": want}
        if not ex:
            miss = spec.get("missing", "bad")
            if miss == "skip":
                return None, "注册表值不存在，本机不适用", extra
            return (miss == "bad"), "值不存在（期望 %s）" % want, extra
        if got.strip().lower() != want.strip().lower():
            return True, "当前 %s，期望 %s" % (got, want), extra
        return False, "已为系统默认值", extra

    if t == "reg_bin0":
        ex, val = reg_read(spec["hive"], spec["key"], spec["name"])
        raw = _reg_bytes(val) if ex else b""
        first = raw[0] if raw else None
        extra = {"hive": spec["hive"], "key": spec["key"], "name": spec["name"],
                 "actual": raw.hex() if raw else "missing", "expect": "首字节 0"}
        if first == 0:
            return False, "首字节为 0，无「快捷方式」后缀", extra
        if first is None:
            return True, "值不存在，会追加「快捷方式」后缀", extra
        return True, "首字节为 %d，会追加「快捷方式」后缀" % first, extra

    if t == "reg_bin_n":
        ex, val = reg_read(spec["hive"], spec["key"], spec["name"])
        idx = int(spec["index"])
        raw = _reg_bytes(val) if ex else b""
        got = raw[idx - 1] if len(raw) >= idx else None
        extra = {"hive": spec["hive"], "key": spec["key"], "name": spec["name"],
                 "actual": raw.hex() if raw else "missing",
                 "expect": "第 %d 字节 = %s" % (idx, spec["ne"])}
        if got is None:
            miss = spec.get("missing", "skip")
            if miss == "skip":
                return None, "二进制值不存在或长度不足，本机不适用", extra
            return (miss == "bad"), "二进制值缺失", extra
        if str(got) != str(spec["ne"]):
            return True, "第 %d 字节为 %d，期望 %s" % (idx, got, spec["ne"]), extra
        return False, "第 %d 字节为 %s，已符合" % (idx, got), extra

    if t == "reg_multi_first":
        if not _key_exists(spec["hive"], spec["key"]):
            return None, "设备类注册项不存在，本机不适用", {
                "hive": spec["hive"], "key": spec["key"], "exists": False}
        ex, val = reg_read(spec["hive"], spec["key"], spec["name"])
        if isinstance(val, str):
            items = [val]
        elif isinstance(val, (list, tuple)):
            items = [str(x) for x in val]
        else:
            items = []
        extra = {"hive": spec["hive"], "key": spec["key"], "name": spec["name"],
                 "actual": " / ".join(items) if items else "missing",
                 "expect": spec["first"]}
        if not items:
            return True, "%s 不存在或为空" % spec["name"], extra
        if items[0] != spec["first"]:
            return True, "首项为 %s，期望 %s" % (items[0], spec["first"]), extra
        return False, "首项为 %s，正常" % items[0], extra

    if t == "reg_exists_any":
        rows = []
        for nm in spec["names"]:
            ex, val = reg_read(spec["hive"], spec["key"], nm)
            rows.append({"name": nm, "exists": ex,
                         "actual": _as_lua_str(val) if ex else "missing"})
        extra = {"hive": spec["hive"], "key": spec["key"], "values": rows}
        hit = [r["name"] for r in rows if r["exists"]]
        if hit:
            return True, "检出过滤驱动：%s" % "、".join(hit), extra
        return False, "未检出过滤驱动", extra

    if t == "proc":
        want = spec["name"].lower()
        running = any((p.get("name") or "").lower() == want for p in w.process_list())
        extra = {"process": spec["name"], "running": running}
        if running:
            return False, "%s 正在运行" % spec["name"], extra
        return True, "%s 未运行" % spec["name"], extra

    if t == "svc_exists_auto":
        info = w.service_query(spec["name"])
        if not info:
            return None, "服务未安装", {"service": spec["name"], "actual": "missing"}
        code = info["start_type_code"]
        extra = {"service": spec["name"], "actual": code,
                 "start_type": info["start_type"]}
        if code == 2:
            return True, "%s 为自动启动" % spec["name"], extra
        return False, "%s 启动类型 %s，已非自动" % (
            spec["name"], info["start_type"]), extra

    if t == "lang":
        rows, allok = [], True
        pairs = (
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\FontAssoc\Associated Charset",
             "ANSI(00)", "YES"),
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\FontAssoc\Associated Charset",
             "OEM(FF)", "YES"),
            ("HKCU", r"Control Panel\International", "Locale", "00000804"),
        )
        for hive, key, nm, want in pairs:
            ex, val = reg_read(hive, key, nm)
            got = _as_lua_str(val) if ex else "nil"
            good = bool(ex) and got == want
            allok = allok and good
            rows.append({"hive": hive, "name": nm, "actual": got,
                         "expect": want, "ok": good})
        extra = {"values": rows}
        if allok:
            return False, "字符集与区域设置均正确（ANSI/OEM=YES，Locale=00000804）", extra
        wrong = [r for r in rows if not r["ok"]]
        return True, "、".join("%s=%s" % (r["name"], r["actual"]) for r in wrong), extra

    if t == "edge_bg":
        # 原版此处若读不到 Edge 的 Uninstall\\DisplayName 会直接 return，整条 Scan 中止。
        # 我们只让本项不适用，不影响同一规则里其它检查点。
        ex, val = reg_read("HKLM",
                           r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
                           "DisplayName")
        if not ex:
            return None, "未安装 Edge", {"actual": "missing", "exists": False}

        boost = False
        local = os.environ.get("LOCALAPPDATA") or ""
        state = os.path.join(local, "Microsoft", "Edge", "User Data", "Local State")
        try:
            with open(state, encoding="utf-8", errors="ignore") as fh:
                txt = fh.read()
            m = re.search(r'"startup_boost"\s*:\s*\{(.*?)\}', txt, re.S)
            if m and re.search(r'"enabled"\s*:\s*true', m.group(1)):
                boost = True
        except OSError:
            boost = False

        pol = r"SOFTWARE\Policies\Microsoft\Edge"
        b_ex, b_val = reg_read("HKLM", pol, "BackgroundModeEnabled")
        s_ex, s_val = reg_read("HKLM", pol, "StartupBoostEnabled")
        extra = {"hive": "HKLM", "key": pol, "name": "BackgroundModeEnabled / StartupBoostEnabled",
                 "actual": _as_lua_str(b_val) + " / " + _as_lua_str(s_val),
                 "expect": "两键均存在", "startup_boost": boost}
        if boost and not b_ex and not s_ex:
            return True, "Edge startup_boost 已开启，且未用策略关闭后台常驻", extra
        return False, "已关闭 Edge 进程后台常驻", extra

    return False, "未知探针类型 %s" % t, {}


def _is_absent(extra: dict) -> bool:
    """判断探针结果是否属于「本机不存在该对象」。"""
    if extra.get("exists") is False:
        return True
    return extra.get("actual") == "missing"


# 服务启动类型：数字 <-> 名字（对齐 Windows SERVICE_START_TYPE）
_START_NAME = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}


def _reg_delete_tree(hive: str, key: str) -> tuple[bool, str]:
    """递归删除注册表键。"""
    def _del(h, sub):
        try:
            with winreg.OpenKey(h, sub, 0,
                                winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as k:
                while True:
                    try:
                        child = winreg.EnumKey(k, 0)
                    except OSError:
                        break
                    _del(h, sub + "\\" + child)
        except FileNotFoundError:
            return
        try:
            winreg.DeleteKeyEx(h, sub, winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            pass
        except OSError:
            winreg.DeleteKey(h, sub)

    try:
        _del(HIVES[hive], key)
        return True, "注册项已移除"
    except OSError as exc:
        return False, "移除失败: %s" % exc


@check("sysopt.probe")
def _sysopt_probe(a):
    """按 fixitem 名执行一条系统优化检测。"""
    item = sysopt.BY_ITEM.get(a["item"])
    if not item:
        return bad("未登记的系统优化项: %s" % a["item"])

    base = {
        "item": item["item"],
        "group": item["group"],
        "impact": item.get("impact", ""),
        "why": item.get("why", ""),
        "probe_text": sysopt.probe_text(item),
        "optional": bool(item.get("optional")),
        "needs_admin": bool(item.get("needs_admin")),
        "fixable": bool(item.get("fix")),
        "src": item.get("src", ""),
        "title_ok": item["title_ok"],
    }

    # 系统版本门控：原版对不符版本的机器直接跳过该分支（如 TaskbarAl 仅 Win11）
    gate = item.get("os")
    if gate:
        cur = osver_name()
        base["os"] = cur
        base["os_gate"] = gate
        if cur not in gate:
            return {"ok": True, "detail": "当前系统 %s，原版不执行该分支" % cur, "data": dict(
                base, skip=True, group=item["group"], title=item["title"],
                level=9, choice=3)}

    state, detail, extra = _run_probe(item["probe"])

    if state is None:
        return {"ok": True, "detail": detail or "本机不适用", "data": dict(
            base, skip=True, group=item["group"], title=item["title"],
            probe=extra, level=9, choice=3)}

    data = dict(
        base,
        group=item["group"],
        title=item["title"] if state else item["title_ok"],
        probe=extra,
        # 对齐原版 E_UpAbnormalData：level=1 需优化 / level=9 已达标
        level=1 if state else 9,
        choice=2 if state else 3,
        severity="warn" if state else "info",
    )
    if state:
        return bad(detail, **data)
    return ok(detail, **data)


@fix("sysopt.fix")
def _sysopt_fix(a):
    """按 fixitem 名执行修复。"""
    item = sysopt.BY_ITEM.get(a["item"])
    if a["item"] in {"camera19", "gpu19", "mouse19"}:
        return False, "设备过滤器配置需按具体设备诊断，禁止通用改写"
    if not item:
        return False, "未登记的系统优化项: %s" % a["item"]
    spec = item.get("fix")
    if not spec:
        return False, "该项没有自动修复动作"
    if item.get("needs_admin") and not w.is_admin():
        return False, "需要管理员权限"

    good, msg = _apply_fix(spec)
    extra = item.get("fix_extra")
    if extra:
        good2, msg2 = _apply_fix(extra)
        good = good and good2
        msg = "%s；%s" % (msg, msg2)
    if good and item.get("reboot"):
        msg += "（%s）" % item["reboot"]
    return good, msg


def _apply_fix(spec: dict) -> tuple[bool, str]:
    """执行一条修复规格。"""
    t = spec["t"]
    if t == "reg_set":
        val = spec["value"]
        if str(spec.get("typ", "")).lower() in ("bin", "binary", "REG_BINARY"):
            val = _norm_bin(val)
        good, msg = reg_write(spec["hive"], spec["key"], spec["name"],
                              spec["typ"], val)
        return good, "%s=%s：%s" % (spec["name"], spec["value"], msg)

    if t == "reg_multi_set":
        parts, allok = [], True
        for nm, val, typ in spec["items"]:
            good, msg = reg_write(spec["hive"], spec["key"], nm, typ, val)
            allok = allok and good
            parts.append("%s=%s %s" % (nm, val, msg))
        return allok, "；".join(parts)

    if t == "reg_or_set":
        parts, allok = [], True
        for pr in spec["pairs"]:
            good, msg = reg_write(pr["hive"], pr["key"], pr["name"],
                                  pr.get("typ", "dword"), pr["value"])
            allok = allok and good
            parts.append("%s=%s %s" % (pr["name"], pr["value"], msg))
        return allok, "；".join(parts)

    if t == "path_restore":
        val = _expand(spec["value"])
        try:
            os.makedirs(val, exist_ok=True)
        except OSError as exc:
            return False, "创建目录失败：%s" % exc
        good, msg = reg_write(spec["hive"], spec["key"], spec["name"],
                              "expand", spec["value"])
        return good, "已写回 %s 并确保目录存在：%s" % (spec["value"], msg)

    if t == "reg_multi_set_one":
        reg_delete(spec["hive"], spec["key"], spec["name"])
        good, msg = reg_write(spec["hive"], spec["key"], spec["name"],
                              "multi", list(spec["value"]))
        return good, "%s=%s：%s" % (spec["name"], " / ".join(spec["value"]), msg)

    if t == "reg_del_multi":
        parts, allok = [], True
        for nm in spec["names"]:
            good, msg = reg_delete(spec["hive"], spec["key"], nm)
            allok = allok and good
            parts.append("%s %s" % (nm, msg))
        return allok, "；".join(parts)

    if t == "key_create":
        try:
            with winreg.CreateKeyEx(HIVES[spec["hive"]], spec["key"], 0,
                                    winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "")
        except OSError as exc:
            return False, "创建注册项失败：%s" % exc
        return True, "已创建 %s（默认值置空）" % spec["key"]

    if t == "explorer_restart":
        killed = False
        for p in w.process_list():
            if (p.get("name") or "").lower() == "explorer.exe":
                good, _msg = w.process_kill(p["pid"])
                killed = killed or good
        try:
            subprocess.Popen(["explorer.exe"], close_fds=True)
        except OSError as exc:
            return False, "重启 explorer 失败：%s" % exc
        return True, "已重启资源管理器" if killed else "已拉起 explorer.exe"

    if t == "svc_set":
        if not w.service_query(spec["name"]):
            return False, "服务 %s 不存在" % spec["name"]
        name = _START_NAME.get(spec["start"], str(spec["start"]))
        return w.service_set_start_type(spec["name"], name)

    if t == "svcs_set":
        parts, allok = [], True
        name = _START_NAME.get(spec["start"], str(spec["start"]))
        for nm in spec["names"]:
            if not w.service_query(nm):
                parts.append("%s 不存在，跳过" % nm)
                continue
            good, msg = w.service_set_start_type(nm, name)
            allok = allok and good
            parts.append("%s %s" % (nm, msg))
        return allok, "；".join(parts)

    if t == "key_delete":
        return _reg_delete_tree(spec["hive"], spec["key"])

    if t == "lang_set":
        parts, allok = [], True
        triples = (
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\FontAssoc\Associated Charset",
             "ANSI(00)", "YES"),
            ("HKLM", r"SYSTEM\CurrentControlSet\Control\FontAssoc\Associated Charset",
             "OEM(FF)", "YES"),
            ("HKCU", r"Control Panel\International", "Locale", "00000804"),
        )
        for hive, key, nm, val in triples:
            good, msg = reg_write(hive, key, nm, "str", val)
            allok = allok and good
            parts.append("%s=%s %s" % (nm, val, msg))
        return allok, "；".join(parts)

    if t == "edge_bg_off":
        parts, allok = [], True
        pol = r"SOFTWARE\Policies\Microsoft\Edge"
        for nm in ("BackgroundModeEnabled", "StartupBoostEnabled"):
            good, msg = reg_write("HKLM", pol, nm, "dword", 0)
            allok = allok and good
            parts.append("%s=0 %s" % (nm, msg))
        return allok, "；".join(parts)

    return False, "未知修复类型 %s" % t


@check("sysopt.list")
def _sysopt_list(a):
    """列出全部系统优化检查点（供界面展示检测范围）。"""
    rows = []
    for it in sysopt.ITEMS:
        meta = sysopt.GROUP_META.get(it["group"], {})
        rows.append({
            "item": it["item"], "group": it["group"],
            "group_title": meta.get("title", it["group"]),
            "group_subtitle": meta.get("subtitle", ""),
            "rule_uuid": meta.get("uuid", ""),
            "title": it["title"], "title_ok": it["title_ok"],
            "impact": it.get("impact", ""), "why": it.get("why", ""),
            "probe_text": sysopt.probe_text(it),
            "os": it.get("os", []),
            "src": it.get("src", ""),
            "fixable": bool(it.get("fix")), "optional": bool(it.get("optional")),
        })
    return ok("%d 个系统优化检查点" % len(rows), items=rows,
              groups=sysopt.GROUP_META, stats=sysopt.stats())
