# KSR · Windows 诊断与修复

免费开源的 Windows 10/11 x64 工具。支持可读规则、检测与修复分离、应用依赖诊断和本地修复记录。
当前 **1.1.0a3 为预览版**，已实现基础闭环，尚未完成全部 Windows 版本和故障样本验证。

没有会员、广告、账户或自动上传。扫描、诊断和修复记录留在本机。
项目与联想、金山及微软无隶属关系。公开包不附带原商业软件、提取规则或逆向样本。

## 启动

Windows 便携包解压后运行 `KSR.exe`；首次扫描不要求管理员。
需要修改系统配置或安装运行库的操作，请明确选择项目并以管理员身份运行。

源码需要 64 位 Python 3.10+，运行时无第三方 Python 依赖：

```powershell
py -3 -m ksr ui
py -3 -m ksr scan
py -3 -m ksr fix --dry-run
```

安装为命令行工具：`py -3 -m pip install .`，随后运行 `ksr ui`。

## 能做什么

- **分类检测**：系统服务、声音服务/端点、打印队列、系统设置、常用运行库和 DLL 清单。
- **明确选择后修复**：受支持的服务和注册表配置、部分运行库官方安装路径等。
- **应用诊断**：选择 EXE/DLL，静态检查直接依赖的架构与候选文件，读取 .NET 运行时配置。
- **本地记录与撤销**：记录受支持的注册表值、服务及文件变更；恢复前检查是否有后续用户修改。
- **独立结果状态**：执行成功不等于验证成功；待重启和无法验证分别报告。

1.1.0a2 修正了安装器返回 3010 后误报已验证、打印队列读取失败仍计为通过的问题。
待重启项目会保留安装器退出码和重启要求，并提示用户重启后重新扫描；不会自动重启。
1.1.0a3 增加现代 .NET 运行时的按应用匹配与安装，支持基础、Desktop、ASP.NET 家族。
读取微软发布元数据，按架构与版本策略选择受支持的稳定版补丁，核对 SHA-512；系统安装还需通过 Windows 签名校验。

个性化优化、兼容运行库建议和清理操作默认不勾选。设备过滤器通用改写已退出发布规则。
不会从不明 DLL 网站向系统目录补文件；API Set 不按同名实体文件是否存在判断缺失。

```powershell
# 检查具体程序，不启动它
py -3 -m ksr diagnose 'C:\Apps\Example\app.exe' --json

# 现代 .NET：先查看计划，再选择安装；不启动目标应用
py -3 -m ksr dotnet-install 'C:\Apps\Example\app.exe'
py -3 -m ksr dotnet-install 'C:\Apps\Example\app.exe' --yes

# 非管理员可选择尚不存在的新私有目录；之后用该目录的 dotnet.exe 启动应用 DLL
py -3 -m ksr dotnet-install 'C:\Apps\Example\app.dll' --install-dir 'C:\Users\Example\KSR-runtime' --yes

# 先查规则及变更计划，使用唯一 UUID 前缀选择
py -3 -m ksr list
py -3 -m ksr fix --uuid <规则前缀> --dry-run
py -3 -m ksr fix --uuid <规则前缀> --yes

# 可选操作需要单独启用，建议始终同时指定规则
py -3 -m ksr fix --uuid <规则前缀> --include-optional --yes

# 查看记录，再撤销其中受支持的变更
py -3 -m ksr history
py -3 -m ksr undo <操作记录ID> --yes
```

记录位于 `%LOCALAPPDATA%\KSR\history`。可能包含本地路径及原配置，请自行保管。
撤销不能整体卸载运行库，也不能恢复已清理的文件、打印任务或被结束的进程。
完整支持边界与验收状态见 [LIMITATIONS](docs/LIMITATIONS.md)。

## 开发与构建

```powershell
py -3 -m unittest discover -s tests -v
py -3 -m ksr.selftest
py -3 -m ksr build-pack
py -3 -m pip install pyinstaller==6.22.3 build
powershell -ExecutionPolicy Bypass -File tools/build_portable.ps1
```

测试只使用隔离临时文件、临时 HKCU 测试键或外部接口替身，不会安装运行库或重置真实设备。
真实修复验收应在有快照的虚拟机和测试设备上进行，不能由单元测试成绩替代。
1.1.0a3 已实际下载并安装私有 .NET Desktop Runtime，以自建程序验证缺失时失败、恢复后加载 WPF 成功；
也已通过 Windows Print to PDF 生成测试页，测试音经现场用户确认清晰正常。物理网络打印因连接不可达未验证。
系统级 EXE 安装和重启、真实声卡故障恢复及物理出纸不据此宣称通过。

源码采用 MIT。研究来源与发行边界见 [PROVENANCE](docs/PROVENANCE.md)。
欢迎提交复现步骤、系统版本、目标应用架构和脱敏诊断结果；请勿提交个人文件、凭据或内存转储。
