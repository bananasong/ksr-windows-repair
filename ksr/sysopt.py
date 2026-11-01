# -*- coding: utf-8 -*-
"""系统优化检测族 —— 逆向还原自 ksd.nlb 的 12 条原始规则。

分组依据
--------
界面上的分组**不是**按规则来的，而是按 ``ksduicfgz.dat``（KAEF 容器）解密后的
``<solution>`` 配置。其中::

    <solution id="5072" title="系统优化">        <- 界面左侧「系统优化」页
        <item uuid="5C981913-..." title="优化服务设置，提升系统稳定性" />
        <item uuid="38615810-..." title="优化系统设置，提升系统稳定性" />
        ... 共 11 个 item

``item.uuid`` 与规则 UUID **完全一致**，这就是「规则 → 界面分组」的绑定键。
每个 item 下挂的若干条 ``E_UpAbnormalData`` 上报就是子项（``showsubcheck="1"``
时逐条显示成勾选框）。所以「发现 N 个可优化项」= 该 item 下 level=1 的条数。

另一条规则 ``7A8F687A``（systemoptimize）**不属于** 5072，它挂在
``<solution id="5068" title="电脑卡慢">`` 的第一个 item
「开机时系统服务优化」上，``dftcheck="0"``（默认不勾选）。这里单独归到
``slow_boot`` 组，界面放在「电脑卡慢」页。

上报协议
--------
::

    abtype=scanresult&id=2201&name=<界面文案>&action=0&level=<1|9>&status=&choice=<2|3>&fixitem=<标识>

  level=1 + choice=2  -> 需优化，默认勾选
  level=9 + choice=3  -> 已达标，列出但不勾选

``fixitem`` 是修复脚本 ``E_getfixlist(UUID)`` 回传的标识，Process 段靠它选分支。

判定语义
--------
Lua 统一用 ``tostring(data) ~= '<期望>'`` 判坏，而 ``GetValue`` 在值缺失时返回
nil，``tostring(nil) == 'nil'``——所以「值不存在」天然落入需优化分支。少数分支
外面套了 ``if tostring(ret)=='0'``，此时值缺失**根本不报**，本模块用
``missing="skip"`` 表达这种「不适用」。

原版还有 8 处缺陷（详见报告 §16.6 / §17），凡是会影响判定结果的，这里都按
「正确的语义」实现并逐条注明，不做照抄。

本模块只做声明式登记；执行由 api._run_probe / api._sysopt_fix 完成。
"""

from __future__ import annotations

# ================================================================
# 分组：与 ksduicfg.clean.xml 的 <solution id="5072"> 逐项对齐
# ================================================================

GROUP_SVC = "sysopt_svc"           # 5C981913  优化服务设置，提升系统稳定性
GROUP_SYSSET = "sysopt_sysset"     # 38615810  优化系统设置，提升系统稳定性
GROUP_PRIV = "sysopt_priv"         # 653D4CB4  优化系统权限设置，提升隐私保护
GROUP_TASKBAR = "sysopt_taskbar"   # 8B0620F6  优化任务栏设置，使用更便捷
GROUP_DESKICON = "sysopt_deskicon"  # 0912F19D 优化桌面图标设置，让桌面更美观
GROUP_MENU = "sysopt_menu"         # C4AEFA53  优化右键菜单设置，提升右键速度
GROUP_EXPLORER = "sysopt_explorer"  # 2940C985 优化文件设置，提升浏览效率
GROUP_UDISK = "sysopt_udisk"       # B0F082D8  优化U盘设置，保护数据安全
GROUP_CAMERA = "sysopt_camera"     # E81FFFF2  检查摄像头系统默认设置是否正常
GROUP_GPU = "sysopt_gpu"           # 8EC84B32  检查显卡系统默认设置是否正常
GROUP_MOUSE = "sysopt_mouse"       # 5179BD48  检查鼠标系统默认设置是否正常

# 7A8F687A 属于 solution 5068「电脑卡慢」的第一个 item
GROUP_SLOWBOOT = "slow_boot"       # 开机时系统服务优化

# 展示顺序 = XML 里 item 的排列顺序
GROUP_ORDER = [
    GROUP_SVC, GROUP_SYSSET, GROUP_PRIV, GROUP_TASKBAR, GROUP_DESKICON,
    GROUP_MENU, GROUP_EXPLORER, GROUP_UDISK, GROUP_CAMERA, GROUP_GPU,
    GROUP_MOUSE,
]

# 标题、副标题、按钮文案全部取自 ksduicfg.clean.xml 原文
GROUP_META = {
    GROUP_SVC: {
        "title": "优化服务设置，提升系统稳定性",
        "subtitle": "优化系统服务项，解决电脑问题",
        "advice": "立即修复",
        "uuid": "5C981913-3F80-4146-8347-9559522CC7A6",
        "rule": "serviceoptmin",
    },
    GROUP_SYSSET: {
        "title": "优化系统设置，提升系统稳定性",
        "subtitle": "当桌面异常时，可勾选进行优化",
        "advice": "谨慎优化",
        "uuid": "38615810-950E-471C-A016-253C8426D970",
        "rule": "directx",
    },
    GROUP_PRIV: {
        "title": "优化系统权限设置，提升隐私保护",
        "subtitle": "一键关闭系统隐私权限，保护个人信息安全",
        "advice": "立即关闭",
        "uuid": "653D4CB4-CBAB-4BC8-B534-C7198F962862",
        "rule": "privacydetection",
    },
    GROUP_TASKBAR: {
        "title": "优化任务栏设置，使用更便捷",
        "subtitle": "优化任务栏图标，提升电脑运行速度",
        "advice": "立即修复",
        "uuid": "8B0620F6-44EC-4B04-A9E6-D95520765C34",
        "rule": "taskbarsetting",
    },
    GROUP_DESKICON: {
        "title": "优化桌面图标设置，让桌面更美观",
        "subtitle": "显示核心功能图标，提升电脑使用效率",
        "advice": "立即修复",
        "uuid": "0912F19D-5748-4148-AD46-38600736DF2D",
        "rule": "deskicon",
    },
    GROUP_MENU: {
        "title": "优化右键菜单设置，提升右键速度",
        "subtitle": "优化菜单样式，提升电脑使用效率",
        "advice": "立即修复",
        "uuid": "C4AEFA53-2DB5-4B3C-BD9C-8A945FEB4538",
        "rule": "menuoptimi",
    },
    GROUP_EXPLORER: {
        "title": "优化文件设置，提升浏览效率",
        "subtitle": "优化资源管理器设置，提升办公效率",
        "advice": "立即修复",
        "uuid": "2940C985-7251-47BC-A4B3-172CD8CD92A8",
        "rule": "explorersetting",
    },
    GROUP_UDISK: {
        "title": "优化U盘设置，保护数据安全",
        "subtitle": "移动设备接入电脑自动运行移动设备的程序，容易让电脑感染病毒",
        "advice": "立即修复",
        "uuid": "B0F082D8-0A25-472C-87CD-FCF624B870CA",
        "rule": "disautorun",
    },
    GROUP_CAMERA: {
        "title": "检查摄像头系统默认设置是否正常",
        "subtitle": "可能导致设备错误码19，建议修复",
        "advice": "立即修复",
        "uuid": "E81FFFF2-F0E7-40A8-85D5-80EA373BE009",
        "rule": "解决摄像头错误代码19问题",
    },
    GROUP_GPU: {
        "title": "检查显卡系统默认设置是否正常",
        "subtitle": "可能导致设备错误码19，建议修复",
        "advice": "立即修复",
        "uuid": "8EC84B32-07B5-4A56-B043-D37C93A69840",
        "rule": "解决显卡错误代码19问题",
    },
    GROUP_MOUSE: {
        "title": "检查鼠标系统默认设置是否正常",
        "subtitle": "可能导致设备错误码19，建议修复",
        "advice": "立即修复",
        "uuid": "5179BD48-DF99-4F8C-BE49-5BB79B391FE8",
        "rule": "解决鼠标设备错误代码19问题",
    },
    GROUP_SLOWBOOT: {
        "title": "开机时系统服务优化",
        "subtitle": "正在处理中，请稍等",
        "advice": "立即修复",
        "uuid": "7A8F687A-CE64-FF7F-0302-5302C23F3BB0",
        "rule": "systemoptimize",
        "solution": "5068",
        "note": "属于「电脑卡慢」页，dftcheck=0（原版默认不勾选）",
    },
}

# 兼容旧引用
GROUP_TITLES = {g: m["title"] for g, m in GROUP_META.items()}
GROUP_SERVICE = GROUP_SVC
GROUP_PERF = GROUP_SLOWBOOT

# 注册表根键简称
_HKLM = "HKLM"
_HKCU = "HKCU"
_HKCR = "HKCR"
_HKU = "HKU"

# 常用路径
_CDM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
_CV = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
_EXP = _CV + r"\Explorer"
_ADV = _EXPL = _EXPLORER_ADV = _CV + r"\Explorer\Advanced"

# 系统版本代号（对齐 _kereng_prelude.lua:5727 的 osinfo()）
OS_XP = "xp"
OS_VISTA = "vista"
OS_7 = "win7"
OS_8 = "win8"
OS_81 = "win8.1"
OS_10 = "win10"
OS_11 = "win11"

_WIN10_11 = [OS_10, OS_11]
_WIN7_10_11 = [OS_7, OS_10, OS_11]
_WIN8_UP = [OS_8, OS_81, OS_10, OS_11]


# ================================================================
# 探针构造器
# ================================================================

def _reg(hive, key, name, ne, missing="bad", typ="dword"):
    """单值探针：值 != ne 判需优化。

    missing: 值不存在时的处理
        "bad"  -> 判需优化（原版 tostring(nil)=='nil' 落在需优化分支）
        "ok"   -> 判已达标
        "skip" -> 本机不适用，整条不上报（原版外层套了 if tostring(ret)=='0'）
    """
    return {"t": "reg", "hive": hive, "key": key, "name": name,
            "ne": str(ne), "missing": missing, "typ": typ}


def _reg_multi(hive, key, pairs, missing="bad"):
    """多值探针：全部等于期望才算达标。pairs = [(name, expect_str), ...]"""
    return {"t": "reg_multi", "hive": hive, "key": key,
            "pairs": [(n, str(v)) for n, v in pairs], "missing": missing}


def _reg_or(pairs):
    """OR 探针：任意一条不满足即判需优化（可跨 hive/键）。

    pairs = [(hive, key, name, expect_str), ...]
    对齐原版 ``if tostring(a)~='x' or tostring(b)~='y' then 报end``。
    """
    return {"t": "reg_or",
            "pairs": [{"hive": h, "key": k, "name": n, "ne": str(v)}
                      for h, k, n, v in pairs]}


def _reg_and(pairs):
    """AND 探针：全部满足才判需优化（可跨 hive/键）。

    对齐原版 ``if tostring(a)=='x' and tostring(b)=='y' then 报end``。
    """
    return {"t": "reg_and",
            "pairs": [{"hive": h, "key": k, "name": n, "ne": str(v)}
                      for h, k, n, v in pairs]}


def _svc(name, ne=2, missing="ok"):
    """单服务探针：Start 类型 != ne 判需优化。2=自动 3=手动 4=禁用"""
    return {"t": "svc", "name": name, "ne": ne, "missing": missing}


# 修复动作
def _fix_reg(hive, key, name, value, typ="dword"):
    return {"t": "reg_set", "hive": hive, "key": key, "name": name,
            "value": value, "typ": typ}


def _fix_reg_multi(hive, key, items):
    """items = [(name, value, typ), ...]"""
    return {"t": "reg_multi_set", "hive": hive, "key": key, "items": items}


def _fix_svc(name, start=2):
    return {"t": "svc_set", "name": name, "start": start}


# ================================================================
# item 1 / 11 —— 5C981913 serviceoptmin：14 个检查点
# ================================================================
_SVC_ITEMS = [
    {
        "item": "disprocomass",
        "title": "优化程序兼容性服务，减少旧程序弹窗干扰",
        "title_ok": "已禁用程序兼容性助手",
        "impact": "老程序启动时反复弹「此程序兼容性有问题」，点掉才能继续",
        "why": "PcaSvc 程序兼容性助手在每次运行旧程序时做启发式检查并弹窗，关闭后不再打扰",
        # 原版：if tostring(ret2)=='0' then if tostring(data2)~='4' -> 缺失不上报
        "probe": _reg(_HKLM, r"SYSTEM\CurrentControlSet\Services\PcaSvc",
                      "Start", 4, missing="skip", typ="dword"),
        "fix": _fix_reg(_HKLM, r"SYSTEM\CurrentControlSet\Services\PcaSvc",
                        "Start", 4, "dword"),
        "needs_admin": True,
    },
    {
        "item": "lsadpromo",
        "title": "优化锁屏推荐服务，关闭广告与内容推广",
        "title_ok": "已关闭锁屏上的推广和提示",
        "impact": "锁屏界面会推「Windows 聚焦」广告与推广图，占流量还分心",
        "why": "RotatingLockScreenOverlayEnabled 控制锁屏上的推广浮层",
        "probe": _reg(_HKCU, _CDM, "RotatingLockScreenOverlayEnabled", 0, missing="bad"),
        "fix": _fix_reg(_HKCU, _CDM, "RotatingLockScreenOverlayEnabled", 0, "dword"),
        "needs_admin": False,
    },
    {
        "item": "smstartrec",
        "title": "优化开始菜单服务，关闭内容推荐干扰",
        "title_ok": "已关闭在开始菜单中的建议",
        "impact": "开始菜单里塞推荐应用与「建议」，点开就是广告位",
        "why": "SubscribedContent-338388Enabled 控制开始菜单的应用推荐",
        "probe": _reg(_HKCU, _CDM, "SubscribedContent-338388Enabled", 0, missing="bad"),
        "fix": _fix_reg(_HKCU, _CDM, "SubscribedContent-338388Enabled", 0, "dword"),
        "needs_admin": False,
    },
    {
        "item": "upwelwinexp",
        "title": "优化系统提示服务，关闭更新后的欢迎界面",
        "title_ok": "已关闭更新后显示欢迎使用 Windows 体验",
        "impact": "每次大版本更新后弹多页「欢迎使用」引导，强制走完",
        "why": "subscribedcontent-310093enabled 控制更新后的欢迎体验页",
        "probe": _reg(_HKCU, _CDM, "subscribedcontent-310093enabled", 0, missing="bad"),
        "fix": _fix_reg(_HKCU, _CDM, "subscribedcontent-310093enabled", 0, "dword"),
        "needs_admin": False,
    },
    {
        "item": "notifromapps",
        "title": "优化通知服务，关闭应用弹窗干扰",
        "title_ok": "已关闭来自应用和其他发送者的通知",
        "impact": "各种应用在右下角弹通知，玩游戏时被打断",
        "why": "ToastEnabled 控制全局 Toast 通知开关",
        "probe": _reg(_HKCU, _CV + r"\PushNotifications", "ToastEnabled", 0, missing="bad"),
        "fix": _fix_reg(_HKCU, _CV + r"\PushNotifications", "ToastEnabled", 0, "dword"),
        "needs_admin": False,
    },
    {
        "item": "winrecon",
        "title": "优化提示建议服务，停止系统使用建议推送",
        "title_ok": "已关闭 Windows 建议",
        "impact": "系统会推「获取更多使用技巧」之类的建议弹窗",
        "why": "ScoobeSystemSettingEnabled 控制「Windows 建议」总开关",
        "probe": _reg(_HKCU, _CV + r"\UserProfileEngagement",
                      "ScoobeSystemSettingEnabled", 0, missing="bad"),
        "fix": _fix_reg(_HKCU, _CV + r"\UserProfileEngagement",
                        "ScoobeSystemSettingEnabled", 0, "dword"),
        "needs_admin": False,
    },
    {
        "item": "expadon",
        "title": "优化资源管理器服务，去除文件窗口中的推广内容",
        "title_ok": "已关闭资源管理器中的广告",
        "impact": "资源管理器顶部显示「推荐」「同步提醒」等推广条",
        "why": "ShowSyncProviderNotifications 控制文件窗口的同步服务推广",
        "probe": _reg(_HKCU, _ADV, "ShowSyncProviderNotifications", 0, missing="bad"),
        "fix": _fix_reg(_HKCU, _ADV, "ShowSyncProviderNotifications", 0, "dword"),
        "needs_admin": False,
    },
    {
        "item": "odbkpalert",
        "title": "优化云备份提示服务，关闭备份推荐弹窗",
        "title_ok": "已关闭 OneDrive 备份提示",
        "impact": "反复弹「备份你的文件」提示，诱导开启 OneDrive",
        "why": "Microsoft.SkyDrive.Desktop 通知开关控制 OneDrive 备份提示弹窗",
        "probe": _reg(_HKCU, _CV + r"\Notifications\Settings\Microsoft.SkyDrive.Desktop",
                      "Enabled", 0, missing="bad"),
        "fix": _fix_reg(_HKCU, _CV + r"\Notifications\Settings\Microsoft.SkyDrive.Desktop",
                        "Enabled", 0, "dword"),
        "needs_admin": False,
    },
    {
        "item": "dooptoff",
        "title": "优化更新传输服务，减少网络带宽占用",
        "title_ok": "已关闭传递优化",
        "impact": "后台悄悄上传更新包给其他电脑，上行带宽被吃满、游戏卡顿",
        "why": "传递优化（P2P 更新分发）默认开启，会把本机当上游节点",
        "probe": _reg(_HKU, r"S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion"
                           r"\DeliveryOptimization\Settings",
                      "DownloadMode", 0, missing="ok", typ="dword"),
        "fix": _fix_reg(_HKU, r"S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion"
                              r"\DeliveryOptimization\Settings",
                        "DownloadMode", 0, "dword"),
        "needs_admin": True,
    },
    {
        "item": "safecenter",
        "title": "优化系统安全服务，修复防护异常问题",
        "title_ok": "安全中心服务正常",
        "impact": "Windows 安全中心服务被禁用后，杀毒与防火墙状态无法上报，防护形同虚设",
        "why": "wscsvc 被第三方优化软件禁用是常见故障，这里只校验它是否为自动启动",
        "probe": _svc("wscsvc", 2, missing="ok"),
        "fix": _fix_svc("wscsvc", 2),
        "needs_admin": True,
    },
    {
        "item": "languagefix",
        "title": "优化语言设置服务，修复程序乱码问题",
        "title_ok": "区域语言正常",
        "impact": "非 Unicode 程序显示乱码、安装包界面变成问号",
        "why": "FontAssoc 的 ANSI/OEM 字符集与 Locale 必须同时为中文环境标准值",
        "probe": {"t": "lang"},
        "fix": {"t": "lang_set"},
        "needs_admin": True,
    },
    {
        "item": "offautoupdrv",
        "title": "优化驱动更新服务，防止自动安装冲突驱动",
        "title_ok": "已关闭系统更新补丁带的驱动程序",
        "impact": "Windows 更新自动装显卡/声卡驱动，覆盖厂商版本导致黑屏、爆音",
        "why": "ExcludeWUDriversInQualityUpdate=1 让质量更新不再夹带驱动",
        "probe": _reg(_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                      "ExcludeWUDriversInQualityUpdate", 1, missing="bad", typ="dword"),
        "fix": _fix_reg(_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
                        "ExcludeWUDriversInQualityUpdate", 1, "dword"),
        "needs_admin": True,
    },
    {
        "item": "iesafecheck",
        "title": "优化浏览器安全服务，提升下载内容安全性检查能力",
        "title_ok": "已启动 IE 浏览器下载安全性检查",
        "impact": "下载的可执行文件不做数字签名校验，容易中招被替换的安装包",
        "why": "CheckExeSignatures=yes 让 IE/WebBrowser 控件在下载 exe 时验签",
        "probe": _reg(_HKCU, r"SOFTWARE\Microsoft\Internet Explorer\Download",
                      "CheckExeSignatures", "yes", missing="bad", typ="str"),
        "fix": _fix_reg(_HKCU, r"SOFTWARE\Microsoft\Internet Explorer\Download",
                        "CheckExeSignatures", "yes", "str"),
        "needs_admin": False,
    },
    {
        "item": "gamemodoff",
        "title": "优化游戏模式服务，防止资源自动调配干扰正常使用",
        "title_ok": "已关闭游戏模式",
        "impact": "游戏模式会把后台进程优先级压低，切回桌面时卡顿、录屏掉帧",
        "why": "AutoGameModeEnabled=0 关闭自动游戏模式",
        "probe": _reg(_HKCU, r"SOFTWARE\Microsoft\GameBar",
                      "AutoGameModeEnabled", 0, missing="bad", typ="dword"),
        "fix": _fix_reg(_HKCU, r"SOFTWARE\Microsoft\GameBar",
                        "AutoGameModeEnabled", 0, "dword"),
        "needs_admin": False,
    },
]

for _i in _SVC_ITEMS:
    _i["group"] = GROUP_SVC
    _i.setdefault("needs_admin", False)
    _i.setdefault("src", "0387 serviceoptmin")


# ================================================================
# item 2 / 11 —— 38615810 directx：系统桌面路径
# ================================================================
_SYSSET_ITEMS = [
    {
        "item": "syspath",
        "title": "优化桌面路径设置，修复桌面显示异常",
        # 原版达标文案
        "title_ok": "系统桌面路径正常",
        "impact": "桌面一片空白、图标全没了——多半是 User Shell Folders 里的 Desktop "
                  "指向了一个已经不存在的目录",
        "why": "读 HKCU\\...\\Explorer\\User Shell Folders 的 Desktop，展开环境变量后"
               "检查该目录是否真实存在；不存在则判为桌面异常",
        # 原版：ret==0 且 value_tmp~='' 才继续，否则整条不报
        "probe": {"t": "path_exists", "hive": _HKCU,
                  "key": _EXP + r"\User Shell Folders", "name": "Desktop"},
        "fix": {"t": "path_restore", "hive": _HKCU,
                "key": _EXP + r"\User Shell Folders", "name": "Desktop",
                "value": r"%USERPROFILE%\Desktop"},
        "reboot": "建议重启后生效（原版同样只提示重启，不做强制）",
        "needs_admin": False,
        "os": _WIN8_UP,
        "src": "0363 directx",
    },
]
for _i in _SYSSET_ITEMS:
    _i["group"] = GROUP_SYSSET
    _i.setdefault("needs_admin", False)


# ================================================================
# item 3 / 11 —— 653D4CB4 privacydetection：3 个有效检查点
# （原版第 4 个 setappadvise 整段被 -- 注释掉，见报告 §16.6）
# ================================================================
_PRIV_ITEMS = [
    {
        "item": "websitlrec",
        "title": "关闭网站访问记录权限，保护上网隐私。",
        "title_ok": "已关闭访问网站记录权限",
        "impact": "允许网站读取你的语言列表并据此生成指纹，用于跨站追踪",
        "why": "HttpAcceptLanguageOptOut=1 关闭「允许网站通过访问我的语言列表」",
        "probe": _reg(_HKCU, r"Control Panel\International\User Profile",
                      "HttpAcceptLanguageOptOut", 1, missing="skip",
                      typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, r"Control Panel\International\User Profile",
                        "HttpAcceptLanguageOptOut", 1, "dword"),
        "needs_admin": False,
        "os": _WIN10_11,
        "src": "0389 privacydetection",
    },
    {
        "item": "wintrackapp",
        "title": "关闭跟踪应用启动，读取应用使用数据等权限，避免隐私泄露",
        "title_ok": "已关闭跟踪应用启动，读取应用使用数据等权限",
        "impact": "系统记录你每个程序的启动次数与时长，用于个性化推荐",
        "why": "Start_TrackProgs=0 关闭应用启动跟踪",
        "probe": _reg(_HKCU, _ADV, "Start_TrackProgs", 0, missing="skip",
                      typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _ADV, "Start_TrackProgs", 0, "dword"),
        "needs_admin": False,
        "os": _WIN10_11,
        "src": "0389 privacydetection",
    },
    {
        "item": "appadidperm",
        "title": "关闭广告ID使用权限，避免个性化广告追踪",
        "title_ok": "已关闭广告ID使用权限",
        "impact": "应用可通过广告 ID 把你的行为串成一条画像，跨应用投放",
        "why": "AdvertisingInfo\\Enabled=0 关闭广告 ID",
        "probe": _reg(_HKCU, _CV + r"\AdvertisingInfo", "Enabled", 0,
                      missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _CV + r"\AdvertisingInfo", "Enabled", 0, "dword"),
        "needs_admin": False,
        "os": _WIN10_11,
        "src": "0389 privacydetection",
    },
]
for _i in _PRIV_ITEMS:
    _i["group"] = GROUP_PRIV
    _i.setdefault("needs_admin", False)


# ================================================================
# item 4 / 11 —— 8B0620F6 taskbarsetting：7 个检查点
# ================================================================
_TASKBAR_ITEMS = [
    {
        "item": "taskbarweather",
        "title": "关闭任务栏天气资讯插件",
        "title_ok": "任务栏天气已关闭",
        "impact": "任务栏左下角常驻天气+资讯，联网刷新、占内存，误点还会弹新闻流",
        "why": "HKLM 的 EnableFeeds=1 且 HKCU 的 ShellFeedsTaskbarViewMode=0 时，"
               "天气资讯处于「图标+温度」展示态",
        # 原版：if tostring(data)=='1' and tostring(data2)=='0' -> 报
        "probe": _reg_and([
            (_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
             "EnableFeeds", "1"),
            (_HKCU, _CV + r"\Feeds", "ShellFeedsTaskbarViewMode", "0"),
        ]),
        "fix": _fix_reg_multi(_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\Windows Feeds",
                              [("EnableFeeds", 0, "dword")]),
        "fix_extra": _fix_reg(_HKCU, _CV + r"\Feeds",
                              "ShellFeedsTaskbarViewMode", 2, "dword"),
        "needs_admin": True,
        "os": [OS_10],
        "src": "0385 taskbarsetting",
    },
    {
        "item": "fixexplorer",
        "title": "修复任务栏展示异常",
        "title_ok": "任务栏无异常",
        "impact": "任务栏空白、点开始菜单没反应、托盘图标消失",
        "why": "explorer.exe 是任务栏与桌面的宿主进程，不存在即判定任务栏异常",
        "probe": {"t": "proc", "name": "explorer.exe"},
        "fix": {"t": "explorer_restart"},
        "needs_admin": False,
        "src": "0385 taskbarsetting",
    },
    {
        "item": "Cortana",
        "title": "关闭Cortana功能",
        "title_ok": "已关闭Cortana",
        "impact": "任务栏搜索框旁边的小娜图标常驻，后台常驻进程占用内存",
        "why": "ShowCortanaButton=0 隐藏小娜按钮",
        "probe": _reg(_HKCU, _ADV, "ShowCortanaButton", 0, missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _ADV, "ShowCortanaButton", 0, "dword"),
        "needs_admin": False,
        "os": _WIN10_11,
        "src": "0385 taskbarsetting",
    },
    {
        "item": "cwindowlnk",
        "title": "禁用windows lnk",
        "title_ok": "已禁用windows lnk",
        "impact": "任务栏右侧常驻「Windows Ink 工作区」笔图标，鼠标用户完全用不上",
        "why": "AllowWindowsInkWorkspace=0 关闭墨迹工作区入口",
        "probe": _reg(_HKLM, r"Software\Policies\Microsoft\WindowsInkWorkspace",
                      "AllowWindowsInkWorkspace", 0, missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKLM, r"Software\Policies\Microsoft\WindowsInkWorkspace",
                        "AllowWindowsInkWorkspace", 0, "dword"),
        "needs_admin": True,
        "os": _WIN10_11,
        "src": "0385 taskbarsetting",
    },
    {
        "item": "taskviewicon",
        "title": "关闭任务视图图标",
        "title_ok": "已关闭任务视图图标",
        "impact": "任务栏搜索框旁边的「任务视图」按钮，不常用还占位置",
        "why": "ShowTaskViewButton=0 隐藏任务视图按钮",
        "probe": _reg(_HKCU, _ADV, "ShowTaskViewButton", 0, missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _ADV, "ShowTaskViewButton", 0, "dword"),
        "needs_admin": False,
        "os": _WIN10_11,
        "src": "0385 taskbarsetting",
    },
    {
        "item": "startmenul",
        "title": "优化开始图标位置为左侧",
        "title_ok": "已设置开始图标位置为左侧",
        "impact": "Win11 默认把开始菜单和任务栏图标居中，很多人更习惯靠左",
        "why": "TaskbarAl=0 把任务栏对齐方式改为左对齐",
        "probe": _reg(_HKCU, _ADV, "TaskbarAl", 0, missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _ADV, "TaskbarAl", 0, "dword"),
        "needs_admin": False,
        "os": [OS_11],
        "src": "0385 taskbarsetting",
    },
    {
        "item": "notifareaicon",
        "title": "恢复通知区域所有图标",
        "title_ok": "已设置显示通知区域所有图标",
        "impact": "托盘图标被折叠进小箭头里，看不到后台程序在干什么",
        "why": "EnableAutoTray=0 显示通知区域所有图标",
        "probe": _reg(_HKCU, _EXP, "EnableAutoTray", 0, missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _EXP, "EnableAutoTray", 0, "dword"),
        "needs_admin": False,
        "os": _WIN10_11,
        "src": "0385 taskbarsetting",
    },
]
for _i in _TASKBAR_ITEMS:
    _i["group"] = GROUP_TASKBAR
    _i.setdefault("needs_admin", False)


# ================================================================
# item 5 / 11 —— 0912F19D deskicon：6 个检查点
# ================================================================
_DESKICON_ITEMS = [
    {
        "item": "fixicon",
        "title": "去除桌面图标的“小箭头”标识",
        "title_ok": "桌面图标无箭头",
        "impact": "快捷方式左下角的箭头被替换成奇怪图标（第三方美化工具常见后遗症）",
        "why": "Shell Icons\\29 是快捷方式覆盖图标的注册点，被改成非系统默认值即判异常。"
               "本项判「是否等于系统默认箭头」，修复即写回默认值",
        # 原版：值存在且 != C:\WINDOWS\system32\imageres.dll,197 -> 报；值不存在也报
        "probe": {"t": "path_lower", "hive": _HKLM,
                  "key": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons",
                  "name": "29", "expect": r"%WINDIR%\system32\imageres.dll,197",
                  "missing": "bad"},
        "fix": _fix_reg(_HKLM,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons",
                        "29", r"%WINDIR%\system32\imageres.dll,197", "expand"),
        "needs_admin": True,
        "src": "0383 deskicon",
    },
    {
        "item": "fixicontxt",
        "title": "去除图标“快捷方式”字样",
        "title_ok": "无快捷方式字样",
        "impact": "每个快捷方式名字后面都拖着「- 快捷方式」，桌面一片乱",
        "why": "Explorer\\link 是 4 字节二进制开关，首字节为 0 表示不追加「快捷方式」后缀",
        # 原版：ret=='0' 且 data[1]~='0' -> 报；ret~='0'（值不存在）也报
        "probe": {"t": "reg_bin0", "hive": _HKCU, "key": _EXP, "name": "link"},
        "fix": _fix_reg(_HKCU, _EXP, "link", "00,00,00,00", "bin"),
        "needs_admin": False,
        "os": _WIN7_10_11,
        "src": "0383 deskicon",
    },
    {
        "item": "mycomputer",
        "title": "修复“此电脑”图标异常",
        "title_ok": "我的电脑桌面图标正常",
        "impact": "桌面上找不到「此电脑」，想进 C 盘得先开资源管理器",
        "why": 'HideDesktopIcons\\NewStartPanel 下 {20D04FE0-…} = 0 表示显示「此电脑」',
        "probe": _reg(_HKCU, _EXP + r"\HideDesktopIcons\NewStartPanel",
                      "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", 0,
                      missing="bad", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _EXP + r"\HideDesktopIcons\NewStartPanel",
                        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", 0, "dword"),
        "needs_admin": False,
        "src": "0383 deskicon",
    },
    {
        "item": "connectnet",
        "title": "修复“网络”图标异常",
        "title_ok": "网络连接桌面图标正常",
        "impact": "桌面上没有「网络」图标，改 IP、看共享都得多点几层",
        "why": 'HideDesktopIcons\\NewStartPanel 下 {F02C1A0D-…} = 0 表示显示「网络」',
        "probe": _reg(_HKCU, _EXP + r"\HideDesktopIcons\NewStartPanel",
                      "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", 0,
                      missing="bad", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _EXP + r"\HideDesktopIcons\NewStartPanel",
                        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", 0, "dword"),
        "needs_admin": False,
        "src": "0383 deskicon",
    },
    {
        "item": "trashcanicon",
        "title": "修复“回收站”图标异常",
        "title_ok": "回收站桌面图标正常",
        "impact": "桌面没有回收站，删错文件无处可找",
        "why": 'HideDesktopIcons\\NewStartPanel 下 {645FF040-…} = 0 表示显示「回收站」',
        # 原版此分支缺 else：键不存在时不报
        "probe": _reg(_HKCU, _EXP + r"\HideDesktopIcons\NewStartPanel",
                      "{645FF040-5081-101B-9F08-00AA002F954E}", 0,
                      missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _EXP + r"\HideDesktopIcons\NewStartPanel",
                        "{645FF040-5081-101B-9F08-00AA002F954E}", 0, "dword"),
        "needs_admin": False,
        "src": "0383 deskicon",
    },
    {
        "item": "fixdskicnhide",
        "title": "恢复被隐藏的桌面图标",
        "title_ok": "桌面图标正常显示",
        "impact": "桌面图标整体不见（右键→查看→显示桌面图标 被关掉）",
        "why": "Advanced\\HideIcons=1 表示桌面图标被整体隐藏",
        # 原版：ret=='0' 且 data=='1' -> 报；值不存在不报
        "probe": _reg(_HKCU, _ADV, "HideIcons", 0, missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _ADV, "HideIcons", 0, "dword"),
        "needs_admin": False,
        "os": _WIN7_10_11,
        "src": "0383 deskicon",
    },
]
for _i in _DESKICON_ITEMS:
    _i["group"] = GROUP_DESKICON
    _i.setdefault("needs_admin", False)


# ================================================================
# item 6 / 11 —— C4AEFA53 menuoptimi：2 个检查点（均 Win11 限定）
# ================================================================
_MENU_ITEMS = [
    {
        "item": "startmenutype",
        "title": "优化win11开始菜单设置，默认显示所有应用",
        "title_ok": "已设置win11开始菜单为显示所有应用",
        "impact": "Win11 开始菜单默认只显示固定磁贴，找程序每次都要多点一下「所有应用」",
        "why": "StartPage\\MakeAllAppsDefault=1 让开始菜单默认展开所有应用列表",
        "probe": _reg(_HKCU, _EXP + r"\StartPage", "MakeAllAppsDefault", 1,
                      missing="bad", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _EXP + r"\StartPage", "MakeAllAppsDefault", 1, "dword"),
        "needs_admin": False,
        "os": [OS_11],
        "src": "0388 menuoptimi",
    },
    {
        "item": "rkeymenu",
        "title": "切换右键菜单为 Win10 全展开样式，提升操作效率",
        "title_ok": "已切换右键菜单为Win10全展开样式",
        "impact": "Win11 右键菜单把「刷新」「新建」都折叠进「显示更多选项」，每次多点一步",
        "why": "创建 CLSID\\{86ca1aa0-…}\\InprocServer32 空项即可恢复 Win10 完整右键菜单",
        # 原版：ExistKey==false -> 报
        "probe": {"t": "key_absent", "hive": _HKCU,
                  "key": r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"},
        "fix": {"t": "key_create", "hive": _HKCU,
                "key": r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
                       r"\InprocServer32"},
        "needs_admin": False,
        "os": [OS_11],
        "src": "0388 menuoptimi",
    },
]
for _i in _MENU_ITEMS:
    _i["group"] = GROUP_MENU
    _i.setdefault("needs_admin", False)


# ================================================================
# item 7 / 11 —— 2940C985 explorersetting：3 个有效检查点
# （原版第 4 个 hideshield 整段被注释，见报告 §16.6）
# ================================================================
_EXPLORER_ITEMS = [
    {
        "item": "explorerview",
        "title": "开启文件预览",
        # 原版达标文案写成了「任务栏无异常」（复制粘贴残留），这里改正
        "title_ok": "已开启文件预览",
        "org_title_ok": "任务栏无异常",
        "impact": "资源管理器按 Alt+P 出不来预览窗格，看图看文档要先双击打开",
        "why": "DetailsContainer 是 8 字节二进制开关，第 5 字节为 1 表示预览窗格已开",
        "probe": {"t": "reg_bin_n", "hive": _HKCU,
                  "key": _EXP + r"\Modules\GlobalSettings\DetailsContainer",
                  "name": "DetailsContainer", "index": 5, "ne": "1",
                  "missing": "skip"},
        "fix": _fix_reg(_HKCU, _EXP + r"\Modules\GlobalSettings\DetailsContainer",
                        "DetailsContainer", "02,00,00,00,01,00,00,00", "bin"),
        "needs_admin": False,
        "os": _WIN10_11,
        "src": "0386 explorersetting",
    },
    {
        "item": "showhidefolder",
        "title": "显示被隐藏的文件或文件夹",
        "title_ok": "已显示隐藏文件或文件夹",
        "impact": "病毒常把自己设成隐藏属性，不显示隐藏文件根本看不见它",
        "why": "Advanced\\Hidden=1 显示隐藏项目（2 为不显示）",
        "probe": _reg(_HKCU, _ADV, "Hidden", 1, missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _ADV, "Hidden", 1, "dword"),
        "needs_admin": False,
        "os": _WIN7_10_11,
        "src": "0386 explorersetting",
    },
    {
        "item": "HideFileExt",
        "title": "显示文件扩展名",
        "title_ok": "已显示文件扩展名",
        "impact": "看不到 .exe/.scr 后缀，`照片.jpg.exe` 伪装成图片点开就中招",
        "why": "Advanced\\HideFileExt=0 显示已知文件类型的扩展名",
        "probe": _reg(_HKCU, _ADV, "HideFileExt", 0, missing="skip", typ="REG_DWORD"),
        "fix": _fix_reg(_HKCU, _ADV, "HideFileExt", 0, "dword"),
        "needs_admin": False,
        "os": _WIN7_10_11,
        "src": "0386 explorersetting",
    },
]
for _i in _EXPLORER_ITEMS:
    _i["group"] = GROUP_EXPLORER
    _i.setdefault("needs_admin", False)


# ================================================================
# item 8 / 11 —— B0F082D8 disautorun：U 盘自动播放
# ================================================================
_UDISK_ITEMS = [
    {
        "item": "56fix",
        "title": "关闭U盘自动播放",
        "title_ok": "已关闭U盘自动播放",
        "impact": "插入 U 盘就自动运行 autorun 程序，是 U 盘病毒最经典的入口",
        "why": "NoDriveTypeAutoRun=255 关闭全部驱动器的自动运行，"
               "DisableAutoplay=1 再关一层自动播放；两者任一不满足即判异常",
        "probe": _reg_or([
            (_HKCU, _CV + r"\Policies\Explorer", "NoDriveTypeAutoRun", "255"),
            (_HKCU, _EXP + r"\AutoplayHandlers", "DisableAutoplay", "1"),
        ]),
        "fix": {"t": "reg_or_set", "pairs": [
            {"hive": _HKCU, "key": _CV + r"\Policies\Explorer",
             "name": "NoDriveTypeAutoRun", "value": 255, "typ": "dword"},
            {"hive": _HKCU, "key": _EXP + r"\AutoplayHandlers",
             "name": "DisableAutoplay", "value": 1, "typ": "dword"},
        ]},
        "needs_admin": False,
        "src": "0356 disautorun",
    },
]
for _i in _UDISK_ITEMS:
    _i["group"] = GROUP_UDISK
    _i.setdefault("needs_admin", False)


# ================================================================
# item 9-11 / 11 —— 设备类过滤器驱动检查（错误代码 19）
# ================================================================
_DEV_ITEMS = [
    {
        "item": "camera19",
        "title": "摄像头设备系统配置异常，可能会导致设备错误代码19",
        "title_ok": "摄像头设备系统配置正常",
        "impact": "设备管理器里摄像头带黄色感叹号，提示「Windows 无法加载这个硬件的设备驱动程序（代码 19）」",
        "why": "摄像头上层过滤器驱动必须是 ksthunk；被第三方软件插进别的过滤驱动就会报 19",
        "probe": {"t": "reg_multi_first", "hive": _HKLM,
                  "key": r"SYSTEM\CurrentControlSet\Control\Class"
                         r"\{6bdd1fc6-810f-11d0-bec7-08002be2092f}",
                  "name": "UpperFilters", "first": "ksthunk"},
        "fix": {"t": "reg_multi_set_one", "hive": _HKLM,
                "key": r"SYSTEM\CurrentControlSet\Control\Class"
                       r"\{6bdd1fc6-810f-11d0-bec7-08002be2092f}",
                "name": "UpperFilters", "value": ["ksthunk"]},
        "reboot": "需要重启",
        "needs_admin": True,
        "group": GROUP_CAMERA,
        "src": "0367 摄像头错误代码19",
    },
    {
        "item": "gpu19",
        "title": "显卡设备系统配置异常，可能会导致设备错误代码19",
        "title_ok": "显卡设备系统配置正常",
        "impact": "显卡掉驱动、分辨率锁在 640×480，设备管理器报代码 19",
        "why": "显卡类键下出现 UpperFilters/LowerFilters，说明有过滤驱动挂在显卡栈上，这是代码 19 的典型成因",
        "probe": {"t": "reg_exists_any", "hive": _HKLM,
                  "key": r"SYSTEM\CurrentControlSet\Control\Class"
                         r"\{4d36e968-e325-11ce-bfc1-08002be10318}",
                  "names": ["UpperFilters", "LowerFilters"]},
        "fix": {"t": "reg_del_multi", "hive": _HKLM,
                "key": r"SYSTEM\CurrentControlSet\Control\Class"
                       r"\{4d36e968-e325-11ce-bfc1-08002be10318}",
                "names": ["UpperFilters", "LowerFilters"]},
        "reboot": "需要重启",
        "needs_admin": True,
        "group": GROUP_GPU,
        "src": "0369 显卡错误代码19",
    },
    {
        "item": "mouse19",
        "title": "鼠标设备系统配置异常，可能会导致设备错误代码19",
        "title_ok": "鼠标设备系统配置正常",
        "impact": "鼠标失灵、指针不动，设备管理器里鼠标设备报代码 19",
        "why": "鼠标类上层过滤器驱动必须是 mouclass",
        "probe": {"t": "reg_multi_first", "hive": _HKLM,
                  "key": r"SYSTEM\CurrentControlSet\Control\Class"
                         r"\{4d36e96f-e325-11ce-bfc1-08002be10318}",
                  "name": "UpperFilters", "first": "mouclass"},
        "fix": {"t": "reg_multi_set_one", "hive": _HKLM,
                "key": r"SYSTEM\CurrentControlSet\Control\Class"
                       r"\{4d36e96f-e325-11ce-bfc1-08002be10318}",
                "name": "UpperFilters", "value": ["mouclass"]},
        "reboot": "需要重启",
        "needs_admin": True,
        "group": GROUP_MOUSE,
        "src": "0370 鼠标错误代码19",
    },
]


# ================================================================
# solution 5068 —— 7A8F687A systemoptimize：15 个有效检查点
# （原版 Scan 里有 24 个分支，其中 9 个因 osver 判断写错或整段注释而永不执行）
# ================================================================
_SLOWBOOT_ITEMS = [
    {
        "item": "ConsentStore",
        "title": "限制应用定位权限，减少后台占用",
        "title_ok": "已优化应用访问定位信息",
        "impact": "应用后台持续定位，耗电且暴露行踪",
        "why": "ConsentStore\\location 的 Value=Deny 关闭全局定位授权",
        "probe": _reg(_HKLM, _CV + r"\CapabilityAccessManager\ConsentStore\location",
                      "Value", "Deny", missing="bad", typ="str"),
        "fix": _fix_reg(_HKLM, _CV + r"\CapabilityAccessManager\ConsentStore\location",
                        "Value", "Deny", "str"),
        "needs_admin": True,
    },
    {
        "item": "doreport",
        "title": "优化错误报告机制，降低系统资源占用",
        "title_ok": "已优化错误报告和展示错误信息",
        "impact": "程序崩溃时后台打包转储并联网上报，卡顿且占带宽",
        "why": "PCHealth\\ErrorReporting 的 doreport/showui 都要置 0",
        "probe": _reg_multi(_HKLM, r"SOFTWARE\Microsoft\PCHealth\ErrorReporting",
                            [("doreport", "0"), ("showui", "0")], missing="bad"),
        "fix": _fix_reg_multi(_HKLM, r"SOFTWARE\Microsoft\PCHealth\ErrorReporting",
                              [("doreport", 0, "dword"), ("showui", 0, "dword")]),
        "needs_admin": True,
    },
    {
        "item": "nolowdiskspacechecks",
        "title": "优化磁盘读写方式，提升磁盘性能",
        "title_ok": "已优化磁盘性能",
        "impact": "系统频繁检查低磁盘空间，机械盘上能感到明显卡顿",
        "why": "nolowdiskspacechecks=1 关闭低磁盘空间轮询",
        # 原版此分支缺失时走 else -> level=9
        "probe": _reg(_HKCU, _CV + r"\Policies\Explorer",
                      "nolowdiskspacechecks", 1, missing="ok", typ="dword"),
        "fix": _fix_reg(_HKCU, _CV + r"\Policies\Explorer",
                        "nolowdiskspacechecks", 1, "dword"),
        "needs_admin": False,
    },
    {
        "item": "desktoplivepreview",
        "title": "优化桌面效果，切换窗口更顺畅",
        "title_ok": "Aero Peek 透视桌面功能的显示速度已最优",
        "impact": "鼠标悬停任务栏要等半秒才出预览，切换窗口不跟手",
        "why": "desktoplivepreviewhovertime 默认 400ms，置 0 立即显示",
        "probe": _reg(_HKCU, _ADV, "desktoplivepreviewhovertime", 0, missing="bad", typ="dword"),
        "fix": _fix_reg(_HKCU, _ADV, "desktoplivepreviewhovertime", 0, "dword"),
        "needs_admin": False,
    },
    {
        "item": "autorestartshell",
        "title": "优化资源管理器崩溃重启机制，提升系统稳定性",
        "title_ok": "已优化 explorer 自动重启",
        "impact": "资源管理器崩了要手动重启，任务栏和桌面一起消失",
        "why": "Winlogon\\AutoRestartShell=1 让 shell 崩溃后自动拉起",
        "probe": _reg(_HKCU, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                      "AutoRestartShell", 1, missing="ok", typ="dword"),
        "fix": _fix_reg(_HKCU, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                        "AutoRestartShell", 1, "dword"),
        "needs_admin": False,
    },
    {
        "item": "remoteregaccess",
        "title": "优化注册表访问，提升系统安全性",
        "title_ok": "已禁止远程注册表修改",
        "impact": "远程注册表服务对外暴露，局域网内可被读取敏感配置",
        "why": "SecurePipeServers\\winreg 的 remoteregaccess=1 限制远程访问",
        "probe": _reg(_HKLM, r"SYSTEM\ControlSet001\Control\SecurePipeServers\winreg",
                      "remoteregaccess", 1, missing="bad", typ="dword"),
        "fix": _fix_reg(_HKLM, r"SYSTEM\ControlSet001\Control\SecurePipeServers\winreg",
                        "remoteregaccess", 1, "dword"),
        "needs_admin": True,
    },
    {
        "item": "aedebugauto",
        "title": "关闭电脑调试功能，减少系统资源消耗",
        "title_ok": "已关闭系统自动调试功能",
        "impact": "程序崩溃后自动挂调试器，进程迟迟不退出，像卡死",
        "why": "AeDebug\\auto=0 关闭崩溃后自动附加调试器",
        "probe": _reg(_HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
                      "auto", 0, missing="ok", typ="str"),
        "fix": _fix_reg(_HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
                        "auto", "0", "str"),
        "needs_admin": True,
    },
    {
        "item": "closeglobaluserdisabled",
        "title": "禁止系统应用后台联网，降低后台资源占用",
        "title_ok": "微软应用在后台运行和访问网络已禁用",
        "impact": "商店应用在后台常驻联网，开机后风扇一直转",
        "why": "BackgroundAccessApplications\\globaluserdisabled=1 全局禁止后台",
        "probe": _reg(_HKCU, _CV + r"\BackgroundAccessApplications",
                      "globaluserdisabled", 1, missing="bad", typ="dword"),
        "fix": _fix_reg(_HKCU, _CV + r"\BackgroundAccessApplications",
                        "globaluserdisabled", 1, "dword"),
        "needs_admin": False,
    },
    {
        "item": "openBootOptimizeFunction",
        "title": "启用磁盘整理程序，加快开机及文件加载速度 Dfrg",
        "title_ok": "系统启动程序 (Dfrg) 已打开",
        "impact": "开机预读（BootOptimizeFunction）被关后，开机变慢、常用程序首次启动迟滞",
        "why": "Dfrg\\BootOptimizeFunction\\enable=Y 开启开机布局优化",
        "probe": _reg(_HKLM, r"SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction",
                      "enable", "Y", missing="ok", typ="str"),
        "fix": _fix_reg(_HKLM, r"SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction",
                        "enable", "Y", "str"),
        "needs_admin": True,
    },
    {
        "item": "optimizationFileSystem",
        "title": "优化文件系统结构，提升数据读取效率",
        "title_ok": "文件系统已优化",
        "impact": "小文件密集读写场景（编译、解压）明显偏慢",
        "why": "configfileallocsize=500 调整 NTFS 配置单元分配粒度",
        "probe": _reg(_HKLM, r"SYSTEM\ControlSet001\Control\FileSystem",
                      "configfileallocsize", 500, missing="bad", typ="dword"),
        "fix": _fix_reg(_HKLM, r"SYSTEM\ControlSet001\Control\FileSystem",
                        "configfileallocsize", 500, "dword"),
        "needs_admin": True,
    },
    {
        "item": "cpufenpeiziyuan",
        "title": "调整系统资源分配策略，保障程序流畅运行",
        "title_ok": "处理器资源分配已最优",
        "impact": "前台程序与后台服务争抢 CPU 时间片，操作发涩",
        "why": "Win32PrioritySeparation=38 让前台程序获得更多时间片"
               "（原版读的键名 win32prioritycontrol 并不存在，永远判达标）",
        "probe": _reg(_HKLM, r"SYSTEM\ControlSet001\Control\PriorityControl",
                      "Win32PrioritySeparation", 38, missing="ok", typ="dword"),
        "fix": _fix_reg(_HKLM, r"SYSTEM\ControlSet001\Control\PriorityControl",
                        "Win32PrioritySeparation", 38, "dword"),
        "needs_admin": True,
    },
    {
        "item": "iopagelocklimit",
        "title": "优化系统配置，释放更多可用内存",
        "title_ok": "内存配置已最优",
        "impact": "页锁定内存上限设置不当，大程序抢不到内存",
        "why": "IoPageLockLimit 只接受 0（动态）或 134217728，其它值都是历史遗留的错误调优",
        "probe": {"t": "reg_notin", "hive": _HKLM,
                  "key": r"SYSTEM\ControlSet001\Control\Session Manager\Memory Management",
                  "name": "iopagelocklimit", "allow": ["0", "134217728"],
                  "missing": "ok", "typ": "dword"},
        "fix": _fix_reg(_HKLM, r"SYSTEM\ControlSet001\Control\Session Manager\Memory Management",
                        "iopagelocklimit", 0, "dword"),
        "needs_admin": True,
    },
    {
        "item": "Tunedoptimalperformance",
        "title": "开启最佳响应模式，全面提升系统运行效率",
        "title_ok": "已设置为最佳性能",
        "impact": "窗口动画、阴影等视觉效果占用 GPU 与 CPU，低配机明显掉帧",
        "why": "VisualFXSetting=2 对应「调整为最佳性能」",
        "probe": _reg(_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
                      "VisualFXSetting", 2, missing="bad", typ="dword"),
        "fix": _fix_reg(_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
                        "VisualFXSetting", 2, "dword"),
        "needs_admin": False,
    },
    {
        "item": "Detectingnetworkservice",
        "title": "系统关键网络服务运行异常",
        "title_ok": "系统服务正常",
        "impact": "网络图标转圈、连上网但打不开网页、VPN 连不上",
        "why": "Netman / iphlpsvc / RasMan / netprofm / EventSystem 五个服务必须自动启动",
        "probe": {"t": "svcs", "names": ["Netman", "iphlpsvc", "RasMan",
                                         "netprofm", "EventSystem"], "ne": 2},
        "fix": {"t": "svcs_set", "names": ["Netman", "iphlpsvc", "RasMan",
                                           "netprofm", "EventSystem"], "start": 2},
        "needs_admin": True,
    },
    {
        "item": "NVIDIADesktopRightClickOptimisation",
        "title": "NVIDIA 桌面右键面板可能导致桌面卡死，如出现卡死建议优化",
        "title_ok": "未检测到 NVIDIA 桌面右键扩展",
        "impact": "右键桌面要等 2-3 秒才出菜单，严重时桌面直接无响应",
        "why": "NvCplDesktopContext 是 NVIDIA 控制面板注入的 shell 扩展，"
               "只在右键时加载但会阻塞 explorer",
        # 原版：只在键存在时上报 level=1，不存在则完全不上报
        "probe": {"t": "key_exists", "hive": _HKCR,
                  "key": r"Directory\Background\shellex\ContextMenuHandlers\NvCplDesktopContext"},
        "fix": {"t": "key_delete", "hive": _HKCR,
                "key": r"Directory\Background\shellex\ContextMenuHandlers\NvCplDesktopContext"},
        "needs_admin": True,
        "optional": True,
    },
    {
        "item": "SunloginService",
        "title": "优化向日葵远程服务延迟启动",
        "title_ok": "向日葵远程服务正常",
        "impact": "向日葵开机自启抢占启动时间，且常驻监听端口",
        "why": "SunloginService 为自动启动时改为手动，需要时再拉起",
        "probe": {"t": "svc_exists_auto", "name": "SunloginService"},
        "fix": _fix_svc("SunloginService", 3),
        "needs_admin": True,
        "optional": True,
    },
    {
        "item": "edgebrowserresidentclose",
        "title": "关闭部分系统常驻进程，降低 CPU 使用",
        "title_ok": "已关闭 Edge 浏览器进程后台常驻",
        "impact": "Edge 关掉窗口后仍在后台常驻（Startup Boost），白白吃掉几百 MB 内存",
        "why": "Edge 的 startup_boost.enabled 为 true，且未用策略关掉后台模式与启动加速",
        "probe": {"t": "edge_bg"},
        "fix": {"t": "edge_bg_off"},
        "needs_admin": True,
        "optional": True,
    },
]

# 上面这条规则里，边缘项与 slow_boot 无关的两条被单独抽出——保持原顺序
for _i in _SLOWBOOT_ITEMS:
    _i["group"] = GROUP_SLOWBOOT
    _i.setdefault("needs_admin", False)


# ================================================================
# 汇总
# ================================================================
ITEMS = (
    _SVC_ITEMS
    + _SYSSET_ITEMS
    + _PRIV_ITEMS
    + _TASKBAR_ITEMS
    + _DESKICON_ITEMS
    + _MENU_ITEMS
    + _EXPLORER_ITEMS
    + _UDISK_ITEMS
    + _DEV_ITEMS
    + _SLOWBOOT_ITEMS
)

BY_ITEM = {i["item"]: i for i in ITEMS}

GROUP_ITEMS: dict[str, list] = {}
for _i in ITEMS:
    GROUP_ITEMS.setdefault(_i["group"], []).append(_i)

# 每个分组实际覆盖几条原始规则
GROUP_RULES = {g: m["uuid"] for g, m in GROUP_META.items()}


def stats() -> dict:
    sysopt = [i for i in ITEMS if i["group"] != GROUP_SLOWBOOT]
    slow = [i for i in ITEMS if i["group"] == GROUP_SLOWBOOT]
    return {
        "items": len(ITEMS),
        "sysopt_5072": len(sysopt),
        "slowboot_5068": len(slow),
        "groups": {g: len(v) for g, v in GROUP_ITEMS.items()},
        "fixable": sum(1 for i in ITEMS if i.get("fix")),
        "optional": sum(1 for i in ITEMS if i.get("optional")),
        "gated": sum(1 for i in ITEMS if i.get("os")),
    }


def probe_text(item: dict) -> str:
    """把探针规格翻译成「读了哪里」的人话，供界面展开详情用。"""
    p = item.get("probe") or {}
    t = p.get("t")
    if t == "reg":
        return "%s\\%s  →  %s（期望 %s）" % (p["hive"], p["key"], p["name"], p["ne"])
    if t == "reg_notin":
        return "%s\\%s  →  %s（接受 %s）" % (
            p["hive"], p["key"], p["name"], " / ".join(p["allow"]))
    if t == "reg_multi":
        return "%s\\%s  →  %s" % (p["hive"], p["key"],
                                  "、".join("%s=%s" % (n, v) for n, v in p["pairs"]))
    if t in ("reg_or", "reg_and"):
        joiner = " 或 " if t == "reg_or" else " 且 "
        return joiner.join("%s\\%s  →  %s=%s" % (x["hive"], x["key"], x["name"], x["ne"])
                           for x in p["pairs"])
    if t == "svc":
        return "服务 %s  →  启动类型（期望 %s）" % (p["name"], p["ne"])
    if t == "svcs":
        return "服务 %s  →  启动类型（期望 %s）" % ("、".join(p["names"]), p["ne"])
    if t == "key_exists":
        return "%s\\%s  →  是否存在" % (p["hive"], p["key"])
    if t == "key_absent":
        return "%s\\%s  →  是否不存在" % (p["hive"], p["key"])
    if t == "path_exists":
        return "%s\\%s  →  %s，展开环境变量后检查目录是否存在" % (
            p["hive"], p["key"], p["name"])
    if t == "path_lower":
        return "%s\\%s  →  %s（忽略大小写比对 %s）" % (
            p["hive"], p["key"], p["name"], p["expect"])
    if t == "reg_bin0":
        return "%s\\%s  →  %s 的首字节（期望 0）" % (p["hive"], p["key"], p["name"])
    if t == "reg_bin_n":
        return "%s\\%s  →  %s 的第 %d 字节（期望 %s）" % (
            p["hive"], p["key"], p["name"], p["index"], p["ne"])
    if t == "reg_multi_first":
        return "%s\\%s  →  %s 的首项（期望 %s）" % (
            p["hive"], p["key"], p["name"], p["first"])
    if t == "reg_exists_any":
        return "%s\\%s  →  %s 是否存在" % (p["hive"], p["key"], " / ".join(p["names"]))
    if t == "proc":
        return "进程 %s 是否在运行" % p["name"]
    if t == "svc_exists_auto":
        return "服务 %s  →  是否为自动启动" % p["name"]
    if t == "lang":
        return "FontAssoc 字符集 + Control Panel\\International\\Locale"
    if t == "edge_bg":
        return "Edge Local State 的 startup_boost + 组策略后台模式"
    return str(p)
