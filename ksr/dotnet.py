"""Modern .NET runtime planning and explicit installation from Microsoft metadata.

Does not launch the diagnosed application or change its runtimeconfig. Stable
framework-dependent Windows x64/x86 deployments only; unsupported host settings
are reported instead of guessed. Private ZIP installs need a new directory.
"""
from __future__ import annotations
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import urllib.request
import zipfile

from . import downloads

BASE = 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/'
FAMILIES = {'Microsoft.NETCore.App': 'runtime', 'Microsoft.WindowsDesktop.App': 'windowsdesktop',
            'Microsoft.AspNetCore.App': 'aspnetcore-runtime'}
POLICIES = {'Disable', 'LatestPatch', 'Minor', 'LatestMinor', 'Major', 'LatestMajor'}


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise ValueError('仅支持稳定版 major.minor.patch 版本')
    return tuple(map(int, value.split('.')))


def select_version(requested, available, policy='Minor'):
    want = version_tuple(requested)
    if policy not in POLICIES:
        raise ValueError('不支持的 rollForward 策略')
    candidates = []
    for value in available:
        try: v = version_tuple(value)
        except ValueError: continue
        if v < want: continue
        if policy == 'Disable' and v != want: continue
        if policy == 'LatestPatch' and v[:2] != want[:2]: continue
        if policy in {'Minor', 'LatestMinor'} and v[0] != want[0]: continue
        candidates.append((v, value))
    if not candidates: return None
    if policy in {'Disable', 'LatestPatch', 'LatestMinor', 'LatestMajor'}:
        return max(candidates)[1]
    major = min(v[0] for v, _ in candidates)
    minor = min(v[1] for v, _ in candidates if v[0] == major)
    return max((v, value) for v, value in candidates if v[:2] == (major, minor))[1]


def fetch_json(url):
    if not downloads.allowed_url(url): raise ValueError('元数据来源不是微软官方 HTTPS')
    opener = urllib.request.build_opener(downloads.OfficialRedirect())
    with opener.open(urllib.request.Request(url, headers={'User-Agent': 'KSR/1.1'}), timeout=30) as response:
        if not downloads.allowed_url(response.geturl()): raise ValueError('元数据重定向不受信任')
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024: raise ValueError('元数据超过大小上限')
    result = json.loads(data)
    if not isinstance(result, dict): raise ValueError('元数据格式错误')
    return result


def default_root(architecture):
    import winreg
    key = rf'SOFTWARE\dotnet\Setup\InstalledVersions\{architecture}'
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as handle:
            value, _ = winreg.QueryValueEx(handle, 'InstallLocation')
            return Path(value)
    except FileNotFoundError: pass
    base = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)') if architecture == 'x86' else os.environ.get(
        'ProgramW6432', os.environ.get('ProgramFiles', r'C:\Program Files'))
    return Path(base) / 'dotnet'


def any_cpu(binary):
    # IMAGE_FILE_MACHINE_I386 can represent AnyCPU IL, not necessarily x86.
    if binary.machine == 'x86' and binary.directory_count > 14:
        address = binary.u32(binary.directory + 14 * 8)
        if address:
            flags = binary.u32(binary.rva(address) + 16)
            if flags & 1 and not flags & (2 | 0x20000):
                return True
    return False


def architecture_for(binary):
    if any_cpu(binary):
        return 'x64' if os.environ.get('PROCESSOR_ARCHITEW6432', os.environ.get('PROCESSOR_ARCHITECTURE', '')).upper() == 'AMD64' else binary.machine
    return binary.machine


def inspect_app(path, architecture=None, runtime_root=None):
    from .diagnose import PE
    source = Path(path).expanduser().resolve(strict=True)
    binary = PE(source)
    arch = architecture or architecture_for(binary)
    if arch not in {'x86', 'x64'}: raise ValueError('当前自动安装仅支持 Windows x86/x64')
    if architecture and architecture != architecture_for(binary) and not any_cpu(binary):
        raise ValueError('指定架构与目标 PE/IL 架构不符')
    root = Path(runtime_root) if runtime_root is not None else default_root(arch)
    configuration = source.with_suffix('.runtimeconfig.json')
    result = {'configuration': str(configuration), 'architecture': arch, 'runtime_root': str(root),
              'frameworks': [], 'status': 'not_applicable', 'issues': [],
              'note': '按稳定版 runtimeconfig 与单一运行时目录检查；不模拟自定义宿主、命令行覆盖或应用实际运行。'}
    if not configuration.is_file(): return result
    if configuration.stat().st_size > 1024 * 1024: raise ValueError('运行时配置超过大小上限')
    data = json.loads(configuration.read_text(encoding='utf-8-sig'))
    if not isinstance(data, dict) or not isinstance(data.get('runtimeOptions'), dict): raise ValueError('运行时配置格式错误')
    options = data['runtimeOptions']
    if options.get('includedFrameworks'):
        result['status'] = 'self_contained'; return result
    frameworks = options.get('frameworks') or ([options['framework']] if options.get('framework') else [])
    if not isinstance(frameworks, list) or len(frameworks) > 16: raise ValueError('framework 配置无效')
    if not frameworks: return result
    if runtime_root is None and any(key.upper().startswith('DOTNET_ROOT') and value for key, value in os.environ.items()):
        result['issues'].append('存在自定义 DOTNET_ROOT；不按系统目录推断应用宿主，请显式选择私有目录或检查自定义宿主')
    if 'applyPatches' in options or 'rollForwardOnNoCandidateFx' in options:
        result['issues'].append('旧版 applyPatches/rollForwardOnNoCandidateFx 尚不支持自动处理')
    if os.environ.get('DOTNET_ROLL_FORWARD_TO_PRERELEASE', '0') not in ('0', ''):
        result['issues'].append('预发布运行时覆盖尚不支持')
    seen = set()
    for entry in frameworks:
        if not isinstance(entry, dict): raise ValueError('framework 必须是对象')
        name, version = entry.get('name'), entry.get('version')
        policy = os.environ.get('DOTNET_ROLL_FORWARD') or entry.get('rollForward', options.get('rollForward', 'Minor'))
        row = {'name': name, 'requested_version': version, 'roll_forward': policy,
               'installed_candidates': [], 'selected_version': None}
        if not isinstance(name, str) or name not in FAMILIES or name in seen:
            result['issues'].append('未知或重复的运行时家族'); result['frameworks'].append(row); continue
        seen.add(name)
        if 'applyPatches' in entry or 'rollForwardOnNoCandidateFx' in entry:
            result['issues'].append('framework 级旧版版本策略尚不支持')
        try:
            version_tuple(version)
            if policy not in POLICIES: raise ValueError('未知 rollForward')
            shared = root / 'shared' / name
            if shared.is_dir():
                row['installed_candidates'] = sorted(p.name for p in shared.iterdir()
                    if p.is_dir() and (p / (name + '.deps.json')).is_file())
            row['selected_version'] = select_version(version, row['installed_candidates'], policy)
        except ValueError as exc: result['issues'].append(str(exc))
        result['frameworks'].append(row)
    # Shared Desktop/ASP.NET frameworks have their own dependency on NETCore.
    # Inspect that requirement rather than treating the outer directory as enough.
    for row in list(result['frameworks']):
        if row['name'] == 'Microsoft.NETCore.App' or not row['selected_version']: continue
        dependency = root / 'shared' / row['name'] / row['selected_version'] / (row['name'] + '.runtimeconfig.json')
        if not dependency.is_file():
            row['selected_version'] = None
            continue
        if dependency.stat().st_size > 1024 * 1024: raise ValueError('共享运行时配置超过大小上限')
        dep_options = json.loads(dependency.read_text(encoding='utf-8-sig')).get('runtimeOptions', {})
        dep = dep_options.get('framework', {})
        if dep.get('name') != 'Microsoft.NETCore.App':
            result['issues'].append('共享运行时依赖不是受支持的常规 NETCore 结构'); continue
        shared = root / 'shared' / 'Microsoft.NETCore.App'
        installed = [p.name for p in shared.iterdir() if p.is_dir() and (p / 'Microsoft.NETCore.App.deps.json').is_file()] if shared.is_dir() else []
        policy = os.environ.get('DOTNET_ROLL_FORWARD') or dep_options.get('rollForward', 'Minor')
        selected = select_version(dep.get('version'), installed, policy)
        explicit = next((r for r in result['frameworks'] if r['name'] == 'Microsoft.NETCore.App'), None)
        if explicit:
            if not select_version(dep['version'], [explicit['selected_version']] if explicit['selected_version'] else [], policy):
                explicit['selected_version'] = None
                if explicit['roll_forward'] == 'Disable':
                    result['issues'].append('精确固定的基础运行时与共享框架依赖冲突')
        else:
            result['frameworks'].append({'name': 'Microsoft.NETCore.App', 'requested_version': dep['version'],
                'roll_forward': policy, 'installed_candidates': sorted(installed), 'selected_version': selected, 'implicit': True})
    result['status'] = 'blocked' if result['issues'] else 'satisfied' if all(r['selected_version'] for r in result['frameworks']) else 'missing'
    return result


def plan_for_app(path, architecture=None, runtime_root=None, mode='system'):
    if mode not in {'system', 'private'}: raise ValueError('未知安装模式')
    inspection = inspect_app(path, architecture, runtime_root)
    plan = {'path': str(Path(path).resolve()), 'mode': mode, 'inspection': inspection, 'packages': [],
            'status': inspection['status'], 'issues': list(inspection['issues'])}
    if inspection['status'] != 'missing': return plan
    index = fetch_json(BASE + 'releases-index.json')
    channels = {x['channel-version']: x for x in index['releases-index']}
    metadata, packages = {}, {}

    def package(family, version, release):
        info = release[FAMILIES[family]]
        if info['version'] != version: raise ValueError('运行时版本与发布元数据不一致')
        ext = '.zip' if mode == 'private' else '.exe'
        prefix = {'Microsoft.NETCore.App': 'dotnet-runtime', 'Microsoft.WindowsDesktop.App': 'windowsdesktop-runtime',
                  'Microsoft.AspNetCore.App': 'aspnetcore-runtime'}[family]
        expected_name = prefix + '-win-' + inspection['architecture'] + ext
        candidates = [f for f in info['files'] if f.get('rid') == 'win-' + inspection['architecture'] and f['name'] == expected_name]
        if len(candidates) != 1: raise ValueError('元数据中没有唯一匹配的 Windows 安装包')
        item = candidates[0]
        if not downloads.allowed_url(item['url']) or not re.fullmatch('[0-9a-fA-F]{128}', item['hash']):
            raise ValueError('安装包来源或 SHA-512 无效')
        packages[(family, version)] = {'family': family, 'version': version,
            'architecture': inspection['architecture'], 'url': item['url'], 'sha512': item['hash'],
            'format': ext[1:]}

    for row in inspection['frameworks']:
        if row['selected_version']: continue
        want = version_tuple(row['requested_version']); channel = f'{want[0]}.{want[1]}'
        if channel not in channels or channels[channel].get('support-phase') not in {'active', 'maintenance'}:
            plan['issues'].append(f'{channel} 不是受支持的稳定版通道'); continue
        if channel not in metadata: metadata[channel] = fetch_json(BASE + channel + '/releases.json')
        releases = metadata[channel]['releases']
        choices = []
        for release in releases:
            info = release.get(FAMILIES[row['name']])
            if not info: continue
            try: v = version_tuple(info['version'])
            except ValueError: continue
            if v[:2] == want[:2]: choices.append((v, info['version'], release))
        if not choices: plan['issues'].append('没有稳定版安装包'); continue
        _, latest, release = max(choices, key=lambda item: item[0])
        if not select_version(row['requested_version'], [latest], row['roll_forward']):
            plan['issues'].append('应用固定的版本不能使用当前补丁；不自动安装历史补丁或改写应用配置'); continue
        package(row['name'], latest, release)
        if mode == 'private' and row['name'] != 'Microsoft.NETCore.App':
            package('Microsoft.NETCore.App', release['runtime']['version'], release)
    if plan['issues']:
        plan['status'] = 'blocked'
    else:
        plan['status'] = 'ready'; plan['packages'] = list(packages.values())
        plan['packages'].sort(key=lambda p: (p['family'] != 'Microsoft.NETCore.App', p['family']))
    return plan


def extract_archive(archive, destination):
    root = Path(destination).resolve()
    with zipfile.ZipFile(archive) as package:
        entries = package.infolist()
        if len(entries) > 30000 or sum(i.file_size for i in entries) > 1024 * 1024 * 1024:
            raise ValueError('运行时压缩包超过展开上限')
        for item in entries:
            name = item.filename.replace('\\', '/')
            parts = PurePosixPath(name).parts
            if name.startswith('/') or '..' in parts or ':' in name or (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('压缩包包含不安全路径')
            target = root.joinpath(*parts)
            if not target.resolve().is_relative_to(root): raise ValueError('压缩包路径越界')
        package.extractall(root)


def install_for_app(path, architecture=None, install_dir=None, expected_packages=None):
    from . import api, journal, win32api as w
    private = install_dir is not None
    target = Path(install_dir).expanduser().absolute() if private else None
    if private and target.exists(): raise ValueError('私有运行时安装必须选择尚不存在的新目录')
    if not private and not w.is_admin():
        return {'status': 'failed', 'ok': False, 'message': '系统级 .NET 安装需要管理员权限；可选择新目录安装私有运行时'}
    plan = plan_for_app(path, architecture, target, 'private' if private else 'system')
    if plan['status'] != 'ready':
        return {'status': 'not_needed' if plan['status'] == 'satisfied' else 'blocked', 'ok': plan['status'] == 'satisfied',
                'message': '运行时已满足配置要求' if plan['status'] == 'satisfied' else '; '.join(plan['issues']) or plan['status'], 'plan': plan}
    if expected_packages is not None and expected_packages != plan['packages']:
        return {'status': 'blocked', 'ok': False, 'message': '安装计划发生变化，请重新查看并确认', 'plan': plan}
    record = journal.Journal('dotnet.application', '安装应用所需的现代 .NET 运行时')
    codes, reboot, messages = [], False, []
    outcome = {'ok': False, 'status': 'failed', 'needs_reboot': False, 'installer_exit_codes': codes,
               'journal_id': record.id, 'plan': plan}
    try:
        if private: target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='ksr_dotnet_', dir=str(target.parent) if private else None) as folder:
            folder = Path(folder); staging = folder / 'runtime'; staging.mkdir()
            for n, package in enumerate(plan['packages']):
                archive = folder / f'package-{n}.{package["format"]}'
                good, message = downloads.download(package['url'], archive, expected_sha512=package['sha512'])
                if not good: raise OSError(message)
                if private: extract_archive(archive, staging)
                else:
                    result = api._run_installer(str(archive), ['/install', '/quiet', '/norestart'])
                    codes.extend(result.exit_codes); reboot = reboot or result.needs_reboot
                    messages.append(result.message)
                    if not result.ok: raise OSError(result.message)
            if private:
                trusted, message = downloads.verify_microsoft(staging / 'dotnet.exe')
                if not trusted: raise OSError(message)
                inspection = inspect_app(path, architecture, staging)
                if inspection['status'] != 'satisfied': raise OSError('私有运行时展开后未满足应用配置')
                os.rename(staging, target)  # Refuses a concurrently created destination on Windows.
                messages.append('私有运行时安装完成；请使用此目录的 dotnet.exe 启动应用 DLL，不改变系统安装')
            outcome['status'] = 'pending_reboot' if reboot else 'unverified'
            outcome['needs_reboot'] = reboot
            if not reboot:
                postcheck = inspect_app(path, architecture, target)
                outcome['postcheck'] = postcheck
                if postcheck['status'] != 'satisfied': raise OSError('安装后运行时配置复检未通过')
                outcome.update(ok=True, status='verified')
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        outcome.update(ok=False, status='failed'); messages.append(str(exc))
    outcome['needs_reboot'] = reboot
    outcome['message'] = '；'.join(messages) + ('；需手动重启后重新检测' if reboot else '')
    record.data.update(needs_reboot=reboot, installer_exit_codes=codes, packages=plan['packages'],
                       install_dir=str(target) if private else None, undo_supported=False)
    record.finish(outcome['status'], outcome['message'])
    return outcome
