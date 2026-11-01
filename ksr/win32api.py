"""Win32 底层绑定层。

对应原程序中被直接 import 的 KERNEL32 / ADVAPI32 / USER32 / SETUPAPI 等：
kdinfomgr.exe 与 ksyseng3.dll 都以显式导入方式调用下列同一批 API，
本模块用 ctypes 复刻这些调用点，避免引入 psutil / pywin32 等第三方依赖。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
import time

if sys.platform != "win32":  # pragma: no cover
    raise RuntimeError("KSR 仅支持 Windows")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
ole32 = ctypes.WinDLL("ole32", use_last_error=True)

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# ---------------------------------------------------------------- 服务控制

SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_QUERY_STATUS = 0x0004
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_ALL_ACCESS = 0xF01FF

SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_CONTINUE_PENDING = 5
SERVICE_PAUSE_PENDING = 6
SERVICE_PAUSED = 7

SERVICE_BOOT_START = 0
SERVICE_SYSTEM_START = 1
SERVICE_AUTO_START = 2
SERVICE_DEMAND_START = 3
SERVICE_DISABLED = 4

SERVICE_NO_CHANGE = 0xFFFFFFFF
SERVICE_CONTROL_STOP = 0x00000001
SERVICE_WIN32_OWN_PROCESS = 0x00000010

STATE_NAME = {
    SERVICE_STOPPED: "stopped",
    SERVICE_START_PENDING: "start_pending",
    SERVICE_STOP_PENDING: "stop_pending",
    SERVICE_RUNNING: "running",
    SERVICE_CONTINUE_PENDING: "continue_pending",
    SERVICE_PAUSE_PENDING: "pause_pending",
    SERVICE_PAUSED: "paused",
}
STATE_CODE = {
    "stopped": SERVICE_STOPPED,
    "running": SERVICE_RUNNING,
    "paused": SERVICE_PAUSED,
}
START_NAME = {
    SERVICE_BOOT_START: "boot",
    SERVICE_SYSTEM_START: "system",
    SERVICE_AUTO_START: "auto",
    SERVICE_DEMAND_START: "manual",
    SERVICE_DISABLED: "disabled",
}
START_CODE = {
    "boot": SERVICE_BOOT_START,
    "system": SERVICE_SYSTEM_START,
    "auto": SERVICE_AUTO_START,
    "manual": SERVICE_DEMAND_START,
    "disabled": SERVICE_DISABLED,
}


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wt.DWORD),
        ("dwCurrentState", wt.DWORD),
        ("dwControlsAccepted", wt.DWORD),
        ("dwWin32ExitCode", wt.DWORD),
        ("dwServiceSpecificExitCode", wt.DWORD),
        ("dwCheckPoint", wt.DWORD),
        ("dwWaitHint", wt.DWORD),
        ("dwProcessId", wt.DWORD),
        ("dwServiceFlags", wt.DWORD),
    ]


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wt.DWORD),
        ("dwCurrentState", wt.DWORD),
        ("dwControlsAccepted", wt.DWORD),
        ("dwWin32ExitCode", wt.DWORD),
        ("dwServiceSpecificExitCode", wt.DWORD),
        ("dwCheckPoint", wt.DWORD),
        ("dwWaitHint", wt.DWORD),
    ]


class QUERY_SERVICE_CONFIGW(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wt.DWORD),
        ("dwStartType", wt.DWORD),
        ("dwErrorControl", wt.DWORD),
        ("lpBinaryPathName", wt.LPWSTR),
        ("lpLoadOrderGroup", wt.LPWSTR),
        ("dwTagId", wt.DWORD),
        ("lpDependencies", wt.LPWSTR),
        ("lpServiceStartName", wt.LPWSTR),
        ("lpDisplayName", wt.LPWSTR),
    ]


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    _fields_ = [
        ("lpServiceName", wt.LPWSTR),
        ("lpDisplayName", wt.LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]


adv.OpenSCManagerW.restype = wt.HANDLE
adv.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
adv.OpenServiceW.restype = wt.HANDLE
adv.OpenServiceW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.DWORD]
adv.CloseServiceHandle.argtypes = [wt.HANDLE]
adv.QueryServiceStatusEx.argtypes = [
    wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)
]
adv.QueryServiceConfigW.argtypes = [
    wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)
]
adv.StartServiceW.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p]
adv.ControlService.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p]
adv.ChangeServiceConfigW.argtypes = [
    wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD, wt.LPCWSTR, wt.LPCWSTR,
    ctypes.POINTER(wt.DWORD), wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR,
]
adv.EnumServicesStatusExW.argtypes = [
    wt.HANDLE, ctypes.c_int, wt.DWORD, wt.DWORD, ctypes.c_void_p,
    wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
    ctypes.POINTER(wt.DWORD), wt.LPCWSTR,
]


def _scm():
    h = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def service_query(name: str) -> dict | None:
    """查询单个服务的运行状态与启动类型；服务不存在返回 None。"""
    scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        h = adv.OpenServiceW(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)
        if not h:
            return None
        try:
            out = SERVICE_STATUS_PROCESS()
            need = wt.DWORD()
            ok = adv.QueryServiceStatusEx(
                h, 0, ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(need)
            )
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            cfg = _query_config(h)
            return {
                "name": name,
                "state": STATE_NAME.get(out.dwCurrentState, str(out.dwCurrentState)),
                "start_type": START_NAME.get(cfg["start_type_code"], "?"),
                "start_type_code": cfg["start_type_code"],
                "pid": int(out.dwProcessId),
                "display": cfg["display"],
                "binary": cfg["binary"],
                "exists": True,
            }
        finally:
            adv.CloseServiceHandle(h)
    finally:
        adv.CloseServiceHandle(scm)


def _query_config(h) -> dict:
    size = wt.DWORD(0)
    adv.QueryServiceConfigW(h, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(max(size.value, 8192))
    if not adv.QueryServiceConfigW(h, buf, len(buf), ctypes.byref(size)):
        return {"start_type_code": -1, "display": "", "binary": ""}
    cfg = ctypes.cast(buf, ctypes.POINTER(QUERY_SERVICE_CONFIGW)).contents
    return {
        "start_type_code": int(cfg.dwStartType),
        "display": cfg.lpDisplayName or "",
        "binary": cfg.lpBinaryPathName or "",
    }


def service_list() -> list[dict]:
    """EnumServicesStatusExW：枚举全部 Win32 服务。"""
    scm = _scm()
    try:
        need = wt.DWORD(0)
        count = wt.DWORD(0)
        resume = wt.DWORD(0)
        buf = ctypes.create_string_buffer(256 * 1024)
        out = []
        while True:
            ok = adv.EnumServicesStatusExW(
                scm, 0, SERVICE_WIN32_OWN_PROCESS, 0x00000003,
                buf, len(buf), ctypes.byref(need), ctypes.byref(count),
                ctypes.byref(resume), None,
            )
            if not ok and ctypes.get_last_error() != 234:  # ERROR_MORE_DATA
                break
            arr = ctypes.cast(buf, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW))
            for i in range(count.value):
                e = arr[i]
                s = e.ServiceStatusProcess
                out.append({
                    "name": e.lpServiceName or "",
                    "display": e.lpDisplayName or "",
                    "state": STATE_NAME.get(s.dwCurrentState, "?"),
                    "pid": int(s.dwProcessId),
                })
            if not ok:
                break
            if not resume.value:
                break
        return out
    finally:
        adv.CloseServiceHandle(scm)


def _wait_service(name: str, expected: str, timeout: float = 15) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = service_query(name)
        if state and state["state"] == expected:
            return True, f"服务状态已确认: {expected}"
        time.sleep(.2)
    return False, f"等待服务进入 {expected} 状态超时"


def service_start(name: str) -> tuple[bool, str]:
    from .journal import ACTIVE
    if ACTIVE.get():
        ACTIVE.get().service(name)
    scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return False, f"OpenSCManager 失败: {ctypes.WinError(ctypes.get_last_error())}"
    try:
        h = adv.OpenServiceW(scm, name, SERVICE_START | SERVICE_QUERY_STATUS)
        if not h:
            return False, f"OpenService 失败: {ctypes.WinError(ctypes.get_last_error())}"
        try:
            if not adv.StartServiceW(h, 0, None):
                err = ctypes.get_last_error()
                if err == 1056:  # ERROR_SERVICE_ALREADY_RUNNING
                    return True, "服务已在运行"
                return False, f"StartService 失败: {ctypes.WinError(err)}"
            return _wait_service(name, "running")
        finally:
            adv.CloseServiceHandle(h)
    finally:
        adv.CloseServiceHandle(scm)


def service_stop(name: str) -> tuple[bool, str]:
    from .journal import ACTIVE
    if ACTIVE.get():
        ACTIVE.get().service(name)
    scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return False, "OpenSCManager 失败"
    try:
        h = adv.OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS)
        if not h:
            return False, "OpenService 失败"
        try:
            st = SERVICE_STATUS()
            if not adv.ControlService(h, SERVICE_CONTROL_STOP, ctypes.byref(st)):
                if ctypes.get_last_error() == 1062:
                    return True, "服务已停止"
                return False, f"ControlService 失败: {ctypes.WinError(ctypes.get_last_error())}"
            return _wait_service(name, "stopped")
        finally:
            adv.CloseServiceHandle(h)
    finally:
        adv.CloseServiceHandle(scm)


def service_set_start_type(name: str, start_type: str) -> tuple[bool, str]:
    from .journal import ACTIVE
    if ACTIVE.get():
        ACTIVE.get().service(name)
    code = START_CODE.get(start_type)
    if code is None:
        return False, f"未知启动类型 {start_type}"
    scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return False, "OpenSCManager 失败"
    try:
        h = adv.OpenServiceW(scm, name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG)
        if not h:
            return False, f"OpenService 失败（可能权限不足）: {ctypes.WinError(ctypes.get_last_error())}"
        try:
            ok = adv.ChangeServiceConfigW(
                h, SERVICE_NO_CHANGE, code, SERVICE_NO_CHANGE,
                None, None, None, None, None, None, None,
            )
            if not ok:
                return False, f"ChangeServiceConfig 失败: {ctypes.WinError(ctypes.get_last_error())}"
            return True, f"启动类型已设为 {start_type}"
        finally:
            adv.CloseServiceHandle(h)
    finally:
        adv.CloseServiceHandle(scm)


# ---------------------------------------------------------------- 进程

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]


def process_list() -> list[dict]:
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return []
    out = []
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        if not k32.Process32FirstW(snap, ctypes.byref(e)):
            return []
        while True:
            out.append({
                "pid": int(e.th32ProcessID),
                "ppid": int(e.th32ParentProcessID),
                "name": e.szExeFile,
            })
            if not k32.Process32NextW(snap, ctypes.byref(e)):
                break
        return out
    finally:
        k32.CloseHandle(snap)


k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]

FILETIME = wt.FILETIME


def _proc_times(pid: int):
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        c, e, k, u = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                   ctypes.byref(k), ctypes.byref(u)):
            return None
        return (k.dwHighDateTime << 32) | k.dwLowDateTime
    finally:
        k32.CloseHandle(h)


def cpu_usage(interval: float = 0.5) -> list[dict]:
    """两次采样 GetProcessTimes 求 CPU 占用率（对应原程序“进程异常占用 CPU”检测）。"""
    import time

    procs = {p["pid"]: p for p in process_list() if p["pid"] > 4}
    snap1 = {pid: _proc_times(pid) for pid in procs}
    ncpu = os.cpu_count() or 1
    time.sleep(interval)
    rows = []
    for pid, p in procs.items():
        t1 = snap1.get(pid)
        t2 = _proc_times(pid)
        if t1 is None or t2 is None:
            continue
        delta = t2 - t1
        pct = delta / (interval * 1e7 * ncpu) * 100.0
        if pct > 0.5:
            rows.append({"pid": pid, "name": p["name"], "cpu": round(pct, 1)})
    rows.sort(key=lambda r: -r["cpu"])
    return rows


def process_kill(pid: int) -> tuple[bool, str]:
    h = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False, "OpenProcess 失败（权限不足）"
    try:
        if not k32.TerminateProcess(h, 1):
            return False, "TerminateProcess 失败"
        return True, "已结束进程"
    finally:
        k32.CloseHandle(h)


# ---------------------------------------------------------------- 磁盘 / 文件

def disk_free(drive: str) -> dict:
    free = ctypes.c_ulonglong()
    total = ctypes.c_ulonglong()
    avail = ctypes.c_ulonglong()
    ok = k32.GetDiskFreeSpaceExW(
        ctypes.c_wchar_p(drive), ctypes.byref(avail),
        ctypes.byref(total), ctypes.byref(free),
    )
    if not ok:
        return {"ok": False}
    return {
        "ok": True,
        "total": total.value,
        "free": free.value,
        "avail": avail.value,
        "used_pct": round((1 - free.value / max(total.value, 1)) * 100, 1),
    }


def dir_size(path: str, limit: int = 400_000) -> tuple[int, int]:
    """返回 (总字节数, 文件数)，带条目上限避免长扫描。"""
    total = 0
    files = 0
    for root, _dirs, names in os.walk(path, onerror=lambda e: None):
        for n in names:
            try:
                total += os.path.getsize(os.path.join(root, n))
                files += 1
            except OSError:
                pass
            if files >= limit:
                return total, files
    return total, files


def is_writable_dir(path: str) -> tuple[bool, str]:
    """真实写盘探测（对应原程序 “C 盘权限” 检测)。"""
    probe = os.path.join(path, f".ksr_probe_{os.getpid()}.tmp")
    try:
        with open(probe, "wb") as f:
            f.write(b"probe")
        os.remove(probe)
        return True, "可写"
    except OSError as exc:
        return False, str(exc)


# ---------------------------------------------------------------- PE

def pe_info(path: str) -> dict | None:
    """手工解析 PE 头，取 machine/subsystem/时间戳，用于运行库与架构校验。"""
    try:
        with open(path, "rb") as f:
            head = f.read(0x400)
    except OSError:
        return None
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", head, 0x3C)[0]
    if pe_off + 0x18 > len(head) or head[pe_off:pe_off + 4] != b"PE\0\0":
        return None
    machine, nsect, tstamp = struct.unpack_from("<HHI", head, pe_off + 4)
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", head, opt_off)[0]
    subsystem = struct.unpack_from("<H", head, opt_off + 68)[0]
    return {
        "machine": machine,
        "arch": {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine, hex(machine)),
        "bits": 32 if magic == 0x10B else 64,
        "pe32plus": magic == 0x20B,
        "subsystem": {2: "gui", 3: "console"}.get(subsystem, str(subsystem)),
        "timestamp": tstamp,
        "sections": nsect,
    }


# ---------------------------------------------------------------- 其它

def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


def system_root() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows")


def uptime_seconds() -> float:
    return k32.GetTickCount64() / 1000.0


def get_locale_name() -> str:
    buf = ctypes.create_unicode_buffer(85)
    k32.GetUserDefaultLocaleName(buf, 85)
    return buf.value


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wt.WORD), ("wMonth", wt.WORD), ("wDayOfWeek", wt.WORD),
        ("wDay", wt.WORD), ("wHour", wt.WORD), ("wMinute", wt.WORD),
        ("wSecond", wt.WORD), ("wMilliseconds", wt.WORD),
    ]


def local_time() -> dict:
    st = SYSTEMTIME()
    k32.GetLocalTime(ctypes.byref(st))
    return {
        "year": st.wYear, "month": st.wMonth, "day": st.wDay,
        "hour": st.wHour, "minute": st.wMinute, "second": st.wSecond,
    }


ver = ctypes.WinDLL("version", use_last_error=True)
ver.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
ver.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
ver.VerQueryValueW.argtypes = [
    ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wt.UINT)
]


def file_version(path: str) -> str:
    """从版本资源读取 FileVersion，尽量不改动文件。"""
    size = ver.GetFileVersionInfoSizeW(path, None)
    if not size:
        return ""
    buf = ctypes.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(path, 0, size, buf):
        return ""
    r = ctypes.c_void_p()
    ln = wt.UINT()
    if not ver.VerQueryValueW(buf, "\\", ctypes.byref(r), ctypes.byref(ln)):
        return ""

    class VS_FIXEDFILEINFO(ctypes.Structure):
        _fields_ = [
            ("dwSignature", wt.DWORD), ("dwStrucVersion", wt.DWORD),
            ("dwFileVersionMS", wt.DWORD), ("dwFileVersionLS", wt.DWORD),
            ("dwProductVersionMS", wt.DWORD), ("dwProductVersionLS", wt.DWORD),
        ]

    fi = ctypes.cast(r, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
    return "%d.%d.%d.%d" % (
        fi.dwFileVersionMS >> 16, fi.dwFileVersionMS & 0xFFFF,
        fi.dwFileVersionLS >> 16, fi.dwFileVersionLS & 0xFFFF,
    )
