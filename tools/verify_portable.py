"""Check the actual distribution ZIP, then start its extracted CLI in a clean cwd."""
from pathlib import Path, PurePosixPath
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import zipfile


def subsystem(data):
    offset = struct.unpack_from('<I', data, 60)[0]
    return struct.unpack_from('<H', data, offset + 24 + 68)[0]


def verify(archive, version):
    with zipfile.ZipFile(archive) as source:
        if source.testzip() is not None: raise ValueError('ZIP 校验失败')
        for name in source.namelist():
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name or path.parts[0] != 'KSR':
                raise ValueError('发行包路径异常')
        with zipfile.ZipFile(io.BytesIO(source.read('KSR/_internal/base_library.zip'))) as stdlib:
            if stdlib.testzip() is not None or 'encodings/__init__.pyc' not in stdlib.namelist():
                raise ValueError('内置 Python 启动依赖缺失或损坏')
        if subsystem(source.read('KSR/KSR.exe')) != 2 or subsystem(source.read('KSR/KSR-cli.exe')) != 3:
            raise ValueError('GUI/CLI 子系统不正确')
        with tempfile.TemporaryDirectory(prefix='ksr-release-check-') as directory:
            source.extractall(directory)
            environment = {k: v for k, v in os.environ.items() if not k.upper().startswith(('PYTHON', '_PYI'))}
            environment['PYTHONIOENCODING'] = 'utf-8'
            environment['KSR_STATE_DIR'] = str(Path(directory) / 'state')
            executable = str(Path(directory) / 'KSR/KSR-cli.exe')
            for _ in range(3):
                result = subprocess.run([executable, '--version'], cwd=directory, env=environment,
                                        capture_output=True, timeout=30)
                if result.returncode or result.stdout.decode().strip() != 'ksr ' + version:
                    raise ValueError('发行包冷启动失败：' + repr(result))
            result = subprocess.run([executable, 'scan', '--group', 'runtime', '--json'], cwd=directory,
                                    env=environment, capture_output=True, timeout=60)
            text = result.stdout.decode('utf-8', errors='replace')
            scan = json.loads(text[text.index('{'):])
            if result.returncode or scan['scanned'] <= 0: raise ValueError('便携版运行库扫描失败')
    return {'version': version, 'extracted_cli_starts': 3, 'stdlib_verified': True,
            'runtime_scanned': scan['scanned'], 'actual_reboot_test': False}


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2]), ensure_ascii=True))
