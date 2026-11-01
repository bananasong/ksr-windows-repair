"""Explicitly selected Run entries, with write-ahead snapshots and conflict checks."""
import hashlib
import json
import winreg

from . import api, journal

KEYS = [('HKCU', r'Software\Microsoft\Windows\CurrentVersion\Run', '当前用户'),
        ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', '所有用户 64 位'),
        ('HKLM', r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', '所有用户 32 位')]


def items():
    rows = []
    for hive, key, scope in KEYS:
        try:
            with winreg.OpenKey(api.HIVES[hive], key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
                i = 0
                while True:
                    try: name, command, kind = winreg.EnumValue(handle, i)
                    except OSError as exc:
                        if getattr(exc, 'winerror', None) == 259: break
                        raise
                    i += 1
                    if kind not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ}: continue
                    approved = r'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
                    approved += '\\' + ('Run32' if 'WOW6432Node' in key else 'Run')
                    exists, state = api.reg_read(hive, approved, name)
                    enabled = not (exists and isinstance(state, bytes) and state[:1] in {b'\x03', b'\x07'})
                    identifier = hashlib.sha256(json.dumps([hive, key, name]).encode()).hexdigest()
                    fingerprint = hashlib.sha256(json.dumps([hive, key, name, command, kind, repr(state)], ensure_ascii=True).encode()).hexdigest()
                    rows.append({'id': identifier, 'fingerprint': fingerprint, 'hive': hive, 'key': key,
                                 'name': name, 'command': command, 'type': kind, 'scope': scope, 'enabled': enabled})
        except FileNotFoundError:
            continue
    return rows


def disable(selections):
    if not isinstance(selections, list) or not selections or len(selections) > 300:
        raise ValueError('请明确选择需要停用的启动项')
    current = {row['id']: row for row in items()}
    selected = []
    for choice in selections:
        if not isinstance(choice, dict): raise ValueError('启动项选择格式错误')
        row = current.get(choice.get('id'))
        if not row or not row['enabled'] or row['fingerprint'] != choice.get('fingerprint'):
            raise ValueError('启动项已变化，请刷新后重新选择')
        if row not in selected: selected.append(row)
    if any(row['hive'] == 'HKLM' for row in selected) and not api.w.is_admin():
        raise ValueError('停用所有用户的启动项需要以管理员身份运行')
    log = journal.Journal('startup-selected', f'停用所选 {len(selected)} 个 Run 启动项')
    token = journal.ACTIVE.set(log)
    try:
        for row in selected:
            before = journal.registry_state(row['hive'], row['key'], row['name'])
            if before != {'exists': True, 'type': row['type'], 'value': row['command']}:
                raise ValueError('启动项在操作前已变化，停止处理')
            good, message = api.reg_delete(row['hive'], row['key'], row['name'])
            if not good: raise OSError(message)
            if journal.registry_state(row['hive'], row['key'], row['name'])['exists']:
                raise OSError('停用后复检未通过')
        message = f'已停用并验证 {len(selected)} 个 Run 启动项，可在修复记录中撤销'
        log.finish('verified', message)
        return {'ok': True, 'message': message, 'journal_id': log.id}
    except (OSError, ValueError) as exc:
        log.finish('failed', str(exc))
        return {'ok': False, 'message': str(exc), 'journal_id': log.id}
    finally:
        journal.ACTIVE.reset(token)
