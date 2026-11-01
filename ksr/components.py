"""Pinned, signed official compatibility installers and architecture-aware inventory."""
from pathlib import Path
import hashlib
import json
import os
import tempfile
import zipfile

from . import downloads

PACKAGES = json.loads(Path(__file__).with_name('components.json').read_text(encoding='utf-8'))


def system_directory(arch):
    from . import win32api as w
    return Path(w.system_root()) / ('SysWOW64' if arch == 'x86' else 'System32')


def probe_package(identifier):
    from . import api
    package = PACKAGES[identifier]
    arch = package['arch']; kind = package['kind']
    missing = []; evidence = []
    if kind == 'vc' and package['gen'] in {8, 9}:
        gen = package['gen']; suffix = str(gen * 10)
        for assembly, files in [('CRT', [f'msvcr{suffix}.dll', f'msvcp{suffix}.dll']),
                                ('MFC', [f'mfc{suffix}.dll', f'mfc{suffix}u.dll']),
                                ('ATL', [f'atl{suffix}.dll'])]:
            result = api._vc80_sxs(arch, gen, assembly, files)
            if result.get('status') == 'unavailable': return result
            if not result['ok']: missing.append(assembly)
            else: evidence.extend(result['data']['assemblies'])
    else:
        if kind == 'vc':
            suffix = str(package['gen'] * 10)
            names = [f'msvcr{suffix}.dll', f'msvcp{suffix}.dll', f'mfc{suffix}.dll', f'mfc{suffix}u.dll']
            if package['gen'] in {10, 11}: names.append(f'atl{suffix}.dll')
            targets = [(system_directory(arch) / name, arch) for name in names]
        elif kind == 'msxml4':
            targets = [(system_directory('x86') / name, 'x86') for name in ['msxml4.dll', 'msxml4r.dll']]
        elif kind == 'openal':
            targets = [(system_directory(ar) / name, ar) for ar in ['x86', 'x64'] for name in ['OpenAL32.dll', 'wrap_oal.dll']]
        elif kind == 'physx':
            common = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'NVIDIA Corporation/PhysX/Common'
            paths = [common / 'PhysXLoader.dll', system_directory('x86') / 'PhysXLoader.dll']
            targets = [(next((p for p in paths if p.is_file()), paths[0]), 'x86')]
        else:
            raise ValueError('未知组件类型')
        for path, target_arch in targets:
            info = api.w.pe_info(str(path))
            if not info or info['arch'] != target_arch: missing.append(str(path))
            else: evidence.append(str(path))
    data = {'package': identifier, 'tier': 'compat', 'severity': 'info', 'missing': missing,
            'missing_kind': 'assemblies' if kind == 'vc' and package['gen'] in {8, 9} else 'files',
            'official_url': package['url'], 'publisher': package['publisher'], 'sha256': package['sha256'],
            'evidence': evidence, 'verification': 'component inventory; not application execution'}
    if missing:
        return api.bad(f"{package['title']} 兼容组件未齐备，按需要选择安装：" + '、'.join(missing), **data)
    return api.ok(package['title'] + ' 清单及文件架构检查通过', **data)


def install_package(identifier):
    from . import api
    package = PACKAGES[identifier]
    if probe_package(identifier)['ok']:
        return api.FixResult(True, '当前组件已通过检测，无需重复安装')
    if not api.w.is_admin():
        return api.FixResult(False, '安装组件需要管理员权限，请以管理员身份重开本程序')
    with tempfile.TemporaryDirectory(prefix='ksr_component_') as folder:
        target = Path(folder) / ('package.zip' if package.get('member') else 'installer.exe')
        good, message = downloads.download(package['url'], target, expected_sha256=package['sha256'])
        if not good: return api.FixResult(False, message)
        if package.get('member'):
            with zipfile.ZipFile(target) as archive:
                member = archive.getinfo(package['member'])
                if member.file_size > 16 * 1024 * 1024: return api.FixResult(False, '安装器解压大小超限')
                # Read only the fixed member; never extract paths supplied by the archive.
                data = archive.read(member)
            if hashlib.sha256(data).hexdigest() != package['member_sha256']:
                return api.FixResult(False, 'ZIP 内安装器 SHA-256 不匹配')
            target = Path(folder) / 'installer.exe'; target.write_bytes(data)
        return api._run_installer(str(target), package['args'], publisher=package['publisher'])
