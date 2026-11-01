"""系统文件与运行库清单。

这张表决定了「DLL 文件」与「常用运行库」两类检测的可信度，因此每个条目都遵循
一条硬规则：**只有"缺失代表真问题"的文件才入表**。

两档语义（这条分档是本实现相对原程序的核心修正）：

``CORE``    系统自带。缺失说明系统真的坏了，任何一台健康的 Win10/11 上都应该有。
            判定为 error，可以修复。
``COMPAT``  由某个可再发行组件包（DirectX 最终用户运行库 / VC++ 运行库 / PhysX …）
            提供，**正常系统本来就可能没有**。例如 ``d3dx9_24.dll`` 在全新 Win11 上
            就不存在，但 d3dx9 系列只在老游戏调用到具体版本时才需要。
            判定为 info：属于兼容性提示，不是故障。

原程序把这两档混为一谈：它按「System32 根目录里有没有这个文件」计数，在全新
Win11 上把 123 个 API Set 桩全判成缺失、进而报「需修 246 项」——实测 110/123
本来就在 ``System32\\Downlevel`` 里，误报率 89%。本表用 tier 分离语义，配合
api.py 的四级目录回退，从根上避开这一类误报。
"""

from __future__ import annotations

CORE = "core"
COMPAT = "compat"

# 由 DirectX 最终用户运行库（DirectX_Jun2010_redist / dxwebsetup）提供的文件
_DX_REDIST = "directx.install"
# 由 VC++ 可再发行包提供的文件
_VC_REDIST = "vcredist.install"
# 无自动修复路径，只能给官方下载入口
_MANUAL = None


def _seq(prefix: str, nums, suffix: str = ".dll") -> list[str]:
    return [f"{prefix}{n}{suffix}" for n in nums]


CATALOG = [
    {
        "id": "dx_core",
        "title": "核心图形接口",
        "tier": CORE,
        "purpose": "所有 2D/3D 渲染的基础，缺失会导致黑屏、软件直接崩溃",
        "fix": _DX_REDIST,
        "files": [
            "d3d9.dll", "d3d10.dll", "d3d10_1.dll", "d3d11.dll", "d3d12.dll",
            "dxgi.dll", "d3dcompiler_47.dll", "ddraw.dll", "dsound.dll",
            "dinput.dll", "dinput8.dll", "opengl32.dll", "glu32.dll",
        ],
    },
    {
        "id": "dx9_d3dx",
        "title": "DirectX 9 D3DX 运行库",
        "tier": COMPAT,
        "purpose": "老游戏与 CAD/建模软件的 D3DX 辅助库，缺版本会提示 d3dx9_xx.dll 丢失",
        "fix": _DX_REDIST,
        "files": _seq("d3dx9_", range(24, 44)),
    },
    {
        "id": "dx10_d3dx",
        "title": "DirectX 10/11 D3DX 运行库",
        "tier": COMPAT,
        "purpose": "DX10/11 时代的辅助数学与网格库",
        "fix": _DX_REDIST,
        "files": _seq("d3dx10_", range(33, 44)) + _seq("d3dx11_", range(42, 44)),
    },
    {
        "id": "d3dcompiler",
        "title": "着色器编译器（历史版本）",
        "tier": COMPAT,
        "purpose": "游戏运行期编译 HLSL 着色器，缺版本会闪退或花屏",
        "fix": _DX_REDIST,
        "files": _seq("d3dcompiler_", list(range(33, 44)) + [46]),
    },
    {
        "id": "xinput",
        "title": "XInput 手柄接口",
        "tier": COMPAT,
        "purpose": "Xbox 兼容手柄接入，缺失时手柄无响应",
        "fix": _DX_REDIST,
        "files": ["xinput1_1.dll", "xinput1_2.dll", "xinput1_3.dll",
                  "xinput1_4.dll", "xinput9_1_0.dll"],
    },
    {
        "id": "xaudio",
        "title": "XAudio / X3DAudio 音频引擎",
        "tier": COMPAT,
        "purpose": "游戏音频混音与 3D 定位，缺失时游戏无声或启动报错",
        "fix": _DX_REDIST,
        "files": (_seq("xaudio2_", range(0, 10))
                  + _seq("x3daudio1_", range(0, 8))
                  + _seq("xapofx1_", range(0, 6))),
    },
    {
        "id": "ucrt",
        "title": "Universal CRT 通用运行库",
        "tier": CORE,
        "purpose": "Win10 起所有 C 运行时都转发到这里，缺失时软件启动即报 0xc000007b",
        "fix": _VC_REDIST,
        "files": ["ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll",
                  "api-ms-win-crt-heap-l1-1-0.dll",
                  "api-ms-win-crt-filesystem-l1-1-0.dll",
                  "api-ms-win-crt-string-l1-1-0.dll",
                  "api-ms-win-crt-stdio-l1-1-0.dll",
                  "api-ms-win-crt-locale-l1-1-0.dll",
                  "api-ms-win-crt-math-l1-1-0.dll",
                  "api-ms-win-crt-convert-l1-1-0.dll",
                  "api-ms-win-crt-environment-l1-1-0.dll",
                  "api-ms-win-crt-process-l1-1-0.dll",
                  "api-ms-win-crt-time-l1-1-0.dll",
                  "api-ms-win-crt-utility-l1-1-0.dll",
                  "api-ms-win-crt-multibyte-l1-1-0.dll",
                  "api-ms-win-crt-private-l1-1-0.dll"],
    },
    {
        "id": "vc14",
        "title": "VC++ 2015-2022 运行库",
        "tier": CORE,
        "purpose": "当前绝大多数 Windows 软件与游戏依赖，缺失会报 vcruntime140 相关错误",
        "fix": _VC_REDIST,
        "files": ["vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll",
                  "msvcp140_1.dll", "msvcp140_2.dll", "msvcp140_atomic_wait.dll",
                  "msvcp140_codecvt_ids.dll", "concrt140.dll", "vccorlib140.dll"],
    },
    {
        "id": "vc80",
        "title": "VC++ 2005 运行库 x86 (msvcr80)",
        "tier": COMPAT,
        "purpose": "部分老式 32 位软件依赖，检查 WinSxS 中的 CRT 清单和文件；不代表所有程序均可启动",
        "fix": _VC_REDIST,
        "files": ["msvcr80.dll", "msvcp80.dll"],
    },
    {
        "id": "vc90",
        "title": "VC++ 2008 运行库 (msvcr90)",
        "tier": COMPAT,
        "purpose": "2008 年编译的老软件依赖，微软该版本的下载入口已不稳定，需手动安装",
        "fix": _MANUAL,
        "files": ["msvcr90.dll", "msvcp90.dll"],
    },
    {
        "id": "vc_legacy",
        "title": "VC++ 2002/2003 应用专用依赖",
        "tier": COMPAT,
        "purpose": "msvcr70/71 等需由原应用安装包提供，2008 以后的运行库无法补齐；正常系统可以没有",
        "fix": _MANUAL,
        "files": ["msvcr70.dll", "msvcr71.dll", "msvcp70.dll", "msvcp71.dll"],
    },
    {
        "id": "mfc_atl",
        "title": "MFC / ATL 7.1 应用专用依赖",
        "tier": COMPAT,
        "purpose": "旧版行业软件需由原应用安装包提供 MFC/ATL 7.1；新版 MFC 安装器不覆盖此版本",
        "fix": _VC_REDIST,
        # MFC 每版都有 ANSI（mfcXX.dll）与 Unicode（mfcXXu.dll）两套，缺一都会起不来
        "files": ["mfc71.dll", "mfc71u.dll", "atl71.dll"],
    },
    {
        "id": "msxml_core",
        "title": "MSXML 核心解析器",
        "tier": CORE,
        "purpose": "系统与企业软件读取 XML 配置的基础组件",
        "fix": _MANUAL,
        "files": ["msxml3.dll", "msxml3r.dll", "msxml6.dll", "msxml6r.dll"],
    },
    {
        "id": "msxml_legacy",
        "title": "MSXML 4.0 解析器",
        "tier": COMPAT,
        "purpose": "老版财务/ERP 软件的 XML 依赖，被误删后软件无法启动",
        "fix": _MANUAL,
        "files": ["msxml4.dll", "msxml4r.dll"],
    },
    {
        "id": "script_host",
        "title": "脚本宿主组件",
        "tier": CORE,
        "purpose": "VBScript/JScript 与 WSH 的基础，缺失会导致系统脚本与安装包失败",
        "fix": _MANUAL,
        "files": ["vbscript.dll", "jscript.dll", "jscript9.dll", "scrrun.dll",
                  "wshom.ocx", "dispex.dll"],
    },
    {
        "id": "ole_shell",
        "title": "COM 与 Shell 基础组件",
        "tier": CORE,
        "purpose": "资源管理器、文件关联、拖放与右键菜单的底层依赖",
        "fix": _MANUAL,
        "files": ["ole32.dll", "oleaut32.dll", "urlmon.dll", "wininet.dll",
                  "shell32.dll", "shlwapi.dll", "comctl32.dll", "comdlg32.dll",
                  "mshtml.dll", "actxprxy.dll", "zipfldr.dll"],
    },
    {
        "id": "media_foundation",
        "title": "媒体播放基础组件",
        "tier": COMPAT,
        "purpose": "视频播放、摄像头预览与录屏的底层组件",
        "fix": _MANUAL,
        "files": ["wmvcore.dll", "mfplat.dll", "mf.dll", "evr.dll",
                  "quartz.dll", "avifil32.dll", "msvfw32.dll", "wmp.dll"],
    },
    {
        "id": "game_extra",
        "title": "游戏专用运行库",
        "tier": COMPAT,
        "purpose": "独立游戏常用的音频与物理引擎依赖",
        "fix": _MANUAL,
        "files": ["openal32.dll", "wrap_oal.dll",
                  "PhysXLoader.dll", "PhysXCore.dll", "PhysXDevice.dll"],
    },
    {
        "id": "vcomp",
        "title": "OpenMP 并行运行库",
        "tier": COMPAT,
        "purpose": "科学计算、视频转码类软件的多线程加速组件",
        "fix": _VC_REDIST,
        "files": ["vcomp140.dll", "vcomp120.dll", "vcomp110.dll", "vcomp100.dll"],
    },
]

# mfc_atl 已在表内用列表推导展开，此处不再二次加工。

BY_ID = {c["id"]: c for c in CATALOG}


def total_files() -> int:
    return sum(len(c["files"]) for c in CATALOG)


def core_files() -> int:
    return sum(len(c["files"]) for c in CATALOG if c["tier"] == CORE)
