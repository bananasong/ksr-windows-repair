"""Local write-ahead repair journal. Only recorded registry/service/file changes can be undone."""
from __future__ import annotations
import base64
import contextvars
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import uuid
import winreg

ACTIVE = contextvars.ContextVar("ksr_journal", default=None)
HIVES = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER,
         "HKCR": winreg.HKEY_CLASSES_ROOT, "HKU": winreg.HKEY_USERS}


def root():
    return Path(os.environ.get("KSR_STATE_DIR") or Path(os.environ.get("LOCALAPPDATA", Path.home())) / "KSR") / "history"


def _encode(value):
    return {"binary": base64.b64encode(value).decode("ascii")} if isinstance(value, bytes) else value


def registry_state(hive, key, name):
    try:
        with winreg.OpenKey(HIVES[hive], key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
            value, typ = winreg.QueryValueEx(handle, name)
            return {"exists": True, "type": typ, "value": _encode(value)}
    except FileNotFoundError:
        return {"exists": False}


def service_state(name):
    from . import win32api as w
    state = w.service_query(name)
    if not state:
        raise OSError("无法备份服务配置: " + name)
    return {"state": state["state"], "start_type": state["start_type"]}


def file_state(path):
    path = Path(path)
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise ValueError("不能备份链接目标")
    if not path.exists():
        return {"exists": False}
    if not path.is_file():
        raise ValueError("目标不是普通文件")
    return {"exists": True, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


class Journal:
    def __init__(self, rule_id, title):
        self.id = uuid.uuid4().hex
        self.folder = root() / self.id
        self.folder.mkdir(parents=True, exist_ok=False)
        self.data = {"schema": 1, "id": self.id, "rule": rule_id, "title": title,
                     "created_at": time.time(), "status": "running", "changes": []}
        self.save()

    def save(self):
        temp = self.folder / "journal.part"
        with temp.open("w", encoding="utf-8") as stream:
            json.dump(self.data, stream, ensure_ascii=False, indent=2)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, self.folder / "journal.json")

    def record(self, kind, target, before, backup=None):
        if any(c["kind"] == kind and c["target"] == target for c in self.data["changes"]):
            return
        self.data["changes"].append({"kind": kind, "target": target, "before": before, "backup": backup})
        self.save()  # Backup must reach disk before the system write.

    def registry(self, hive, key, name):
        self.record("registry", [hive, key, name], registry_state(hive, key, name))

    def service(self, name):
        self.record("service", name, service_state(name))

    def file(self, path):
        path = str(Path(path).absolute())
        if any(c["kind"] == "file" and c["target"] == path for c in self.data["changes"]):
            return
        before = file_state(path)
        backup = None
        if before["exists"]:
            backup = str(len(self.data["changes"])) + ".bak"
            shutil.copy2(path, self.folder / backup)
        self.record("file", path, before, backup)

    def finish(self, status, message):
        for change in self.data["changes"]:
            try:
                change["after"] = current_state(change)
            except OSError as exc:
                change["snapshot_error"] = str(exc)
        self.data.update(status=status, message=message, finished_at=time.time())
        self.save()


def current_state(change):
    if change["kind"] == "registry":
        return registry_state(*change["target"])
    if change["kind"] == "service":
        return service_state(change["target"])
    return file_state(change["target"])


def history():
    if not root().exists():
        return []
    rows = []
    for path in root().glob("*/journal.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            rows.append({k: data.get(k) for k in ("id", "title", "status", "created_at", "message")}
                        | {"changes": len(data.get("changes", []))})
        except (OSError, ValueError):
            continue
    return sorted(rows, key=lambda r: r["created_at"], reverse=True)


def undo(identifier):
    from . import win32api as w
    if not isinstance(identifier, str) or len(identifier) != 32 or any(c not in "0123456789abcdef" for c in identifier):
        raise ValueError("无效的操作记录 ID")
    folder = root() / identifier
    path = folder / "journal.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("status") == "undone":
        return {"ok": True, "message": "已撤销", "id": identifier}
    changes = data.get("changes", [])
    if not changes:
        raise ValueError("该操作没有可撤销快照；安装器、清理或进程操作不能整体撤销")
    # Preflight every change before restoring any value; avoid overwriting later user edits.
    for c in changes:
        if "after" not in c or current_state(c) != c["after"]:
            raise ValueError("当前状态与修复后快照不一致，停止撤销: " + str(c["target"]))
        if c["kind"] == "file" and c["before"]["exists"]:
            backup = folder / c["backup"]
            if backup.parent != folder or file_state(backup).get("sha256") != c["before"]["sha256"]:
                raise ValueError("备份文件校验失败")
    restored = 0
    try:
        for c in reversed(changes):
            before = c["before"]
            if c["kind"] == "registry":
                hive, key, name = c["target"]
                if before["exists"]:
                    value = before["value"]
                    if isinstance(value, dict) and "binary" in value:
                        value = base64.b64decode(value["binary"])
                    with winreg.CreateKeyEx(HIVES[hive], key, 0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as h:
                        winreg.SetValueEx(h, name, 0, before["type"], value)
                else:
                    try:
                        with winreg.OpenKey(HIVES[hive], key, 0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY) as h:
                            winreg.DeleteValue(h, name)
                    except FileNotFoundError:
                        pass
            elif c["kind"] == "service":
                good, message = w.service_set_start_type(c["target"], before["start_type"])
                if not good:
                    raise OSError(message)
                actual = service_state(c["target"])
                if actual["state"] != before["state"]:
                    operation = w.service_start if before["state"] == "running" else w.service_stop
                    good, message = operation(c["target"])
                    if not good:
                        raise OSError(message)
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline and service_state(c["target"])["state"] != before["state"]:
                        time.sleep(.2)
            elif before["exists"]:
                shutil.copy2(folder / c["backup"], c["target"])
            else:
                Path(c["target"]).unlink(missing_ok=True)
            if current_state(c) != before:
                raise OSError("恢复后验证未通过: " + str(c["target"]))
            restored += 1
    except Exception as exc:
        data.update(status="undo_failed", undo_error=str(exc), restored_changes=restored)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        raise
    data.update(status="undone", restored_changes=restored)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "id": identifier, "changes": restored, "message": "已恢复并验证记录的配置"}
