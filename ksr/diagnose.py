"""Read-only PE import and .NET configuration inspection. Never loads the selected application."""
from __future__ import annotations
import os
from pathlib import Path
import struct

MACHINES = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64", 0x1c4: "arm"}


class PE:
    def __init__(self, path):
        self.path = Path(path)
        if self.path.stat().st_size > 256 * 1024 * 1024:
            raise ValueError("文件超过 256 MB 的分析上限")
        self.data = self.path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError("不是 Windows PE 文件")
        header = self.u32(0x3c)
        if self.data[header:header + 4] != b"PE\0\0":
            raise ValueError("PE 头无效")
        self.machine = MACHINES.get(self.u16(header + 4), "unknown")
        if self.machine == "unknown":
            raise ValueError("尚不支持该 PE 机器类型")
        count = self.u16(header + 6)
        optional_size = self.u16(header + 20)
        optional = header + 24
        magic = self.u16(optional)
        if magic not in (0x10b, 0x20b) or optional_size < (96 if magic == 0x10b else 112):
            raise ValueError("PE 可选头无效")
        self.bits = 32 if magic == 0x10b else 64
        self.directory = optional + (96 if self.bits == 32 else 112)
        self.directory_count = min(self.u32(self.directory - 4), (optional + optional_size - self.directory) // 8)
        self.headers_size = self.u32(optional + 60)
        self.sections = []
        section_table = optional + optional_size
        if count > 96:
            raise ValueError("PE 节数量超过上限")
        for n in range(count):
            base = section_table + 40 * n
            self.read(base, 40)
            self.sections.append((self.u32(base + 12), self.u32(base + 16), self.u32(base + 20)))

    def read(self, offset, count):
        if offset < 0 or count < 0 or offset + count > len(self.data):
            raise ValueError("PE 数据截断或地址越界")
        return self.data[offset:offset + count]

    def u16(self, offset):
        return struct.unpack("<H", self.read(offset, 2))[0]

    def u32(self, offset):
        return struct.unpack("<I", self.read(offset, 4))[0]

    def rva(self, address):
        if address < self.headers_size:
            self.read(address, 1)
            return address
        for start, size, raw in self.sections:
            if start <= address < start + size:
                offset = raw + address - start
                self.read(offset, 1)
                return offset
        raise ValueError("RVA 没有对应文件数据")

    def cstring(self, address):
        offset = self.rva(address)
        end = self.data.find(b"\0", offset, min(offset + 1024, len(self.data)))
        if end < 0:
            raise ValueError("导入名称没有终止符")
        name = self.data[offset:end].decode("ascii")
        if not name or any(c in name for c in "/\\:"):
            raise ValueError("导入名称不合法")
        return name

    def imports(self):
        if self.directory_count < 2:
            return []
        address = self.u32(self.directory + 8)
        size = self.u32(self.directory + 12)
        if not address:
            return []
        names = []
        for n in range(min(size // 20, 4096)):
            offset = self.rva(address + n * 20)
            entry = self.read(offset, 20)
            if entry == b"\0" * 20:
                return sorted(set(names), key=str.casefold)
            name = self.u32(offset + 12)
            names.append(self.cstring(name))
        raise ValueError("导入表没有在声明范围内终止")


def _family(name):
    lower = name.lower()
    if lower.startswith(("api-", "ext-")):
        return "api_contract"
    if lower.startswith(("qt5", "qt6")):
        return "application_qt"
    if lower.startswith(("vcruntime", "msvcp", "msvcr", "concrt", "vcomp", "mfc")):
        return "visual_cpp"
    if lower.startswith(("d3dx", "xinput1_3", "xaudio2_7")):
        return "legacy_directx"
    return "dll"


def inspect(path):
    source = Path(path).expanduser().resolve(strict=True)
    binary = PE(source)
    system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    system_dir = system / ("SysWOW64" if binary.machine == "x86" and (system / "SysWOW64").exists() else "System32")
    dependencies = []
    for name in binary.imports():
        family = _family(name)
        result = {"name": name, "family": family, "status": "unresolved", "path": "", "candidates": []}
        if family == "api_contract":
            result.update(status="contract", detail="API 合约由系统加载器映射，不能按实体 DLL 缺失判断")
        else:
            for directory in (source.parent, system_dir):
                candidate = directory / name
                if not candidate.is_file():
                    continue
                try:
                    other = PE(candidate)
                    result["candidates"].append({"path": str(candidate), "machine": other.machine})
                    if other.machine == binary.machine:
                        result.update(status="candidate_found", path=str(candidate))
                        break
                    result["status"] = "architecture_mismatch"
                except (OSError, ValueError, UnicodeError) as exc:
                    result["candidates"].append({"path": str(candidate), "error": str(exc)})
                    result["status"] = "unreadable"
        dependencies.append(result)
    configuration = source.with_suffix(".runtimeconfig.json")
    runtime = None
    unresolved = [d for d in dependencies if d["status"] in {"unresolved", "architecture_mismatch", "unreadable"}]
    recommendations = []
    if any(d["family"] == "application_qt" for d in unresolved):
        recommendations.append("Qt 属于应用私有依赖，优先使用原应用安装程序修复完整组件及插件。")
    if any(d["family"] == "visual_cpp" for d in unresolved):
        recommendations.append("核对目标程序要求的 VC++ 代际与架构，再安装对应官方运行库。")
    if any(d["family"] == "legacy_directx" for d in unresolved):
        recommendations.append("核对旧版 DirectX SDK 兼容组件；它与 Windows 自带核心 DirectX 不同。")
    if configuration.is_file():
        from .dotnet import inspect_app
        runtime = inspect_app(source)
        if runtime['status'] == 'missing':
            recommendations.append('应用所需的现代 .NET 运行时尚不满足，可查看官方运行时安装计划。')
    return {"path": str(source), "machine": binary.machine, "bits": binary.bits,
            "dependencies": dependencies, "runtime": runtime, "recommendations": recommendations,
            "limitations": ["静态分析，不启动或加载目标程序。", "仅检查直接普通导入；未解析延迟导入、全部传递依赖和加载器搜索策略。",
                            "未解析到依赖是诊断线索，不等于确认缺失；应用可能使用 SxS、自定义路径或插件。",
                            "现代 .NET 支持稳定版常规框架依赖；自定义宿主、旧版本策略和命令行覆盖需要另行诊断。"]}
