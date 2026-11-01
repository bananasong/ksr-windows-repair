import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import uuid
import winreg

from ksr import api, journal, diagnose, downloads


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {"KSR_STATE_DIR": self.temp.name})
        env.start(); self.addCleanup(env.stop)

    def test_file_restore_and_refuse_later_user_edit(self):
        target = Path(self.temp.name, "data.txt"); target.write_text("before")
        record = journal.Journal("rule", "Test")
        record.file(target); target.write_text("after"); record.finish("verified", "done")
        target.write_text("user change")
        with self.assertRaises(ValueError):
            journal.undo(record.id)
        self.assertEqual(target.read_text(), "user change")
        target.write_text("after")
        self.assertTrue(journal.undo(record.id)["ok"])
        self.assertEqual(target.read_text(), "before")

    def test_registry_restores_original_binary_and_type(self):
        key = "Software\\KSR\\Test_" + uuid.uuid4().hex
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key) as handle:
            winreg.SetValueEx(handle, "sample", 0, winreg.REG_BINARY, b"original")
        self.addCleanup(lambda: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key))
        record = journal.Journal("rule", "Registry test")
        token = journal.ACTIVE.set(record)
        try:
            good, _ = api.reg_write("HKCU", key, "sample", "str", "changed")
        finally:
            journal.ACTIVE.reset(token)
        self.assertTrue(good)
        record.finish("verified", "done")
        journal.undo(record.id)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as h:
            value, typ = winreg.QueryValueEx(h, "sample")
        self.assertEqual((value, typ), (b"original", winreg.REG_BINARY))

    def test_unknown_or_path_history_identifier_rejected(self):
        for identifier in ("../file", "A" * 32, "", None):
            with self.assertRaises(ValueError):
                journal.undo(identifier)


def pe_bytes(machine=0x8664):
    data = bytearray(1024)
    data[:2] = b"MZ"; struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, machine, 1)
    struct.pack_into("<H", data, 0x94, 240)
    struct.pack_into("<H", data, 0x98, 0x20b)
    struct.pack_into("<I", data, 0x98 + 60, 512)
    struct.pack_into("<I", data, 0x98 + 108, 16)
    struct.pack_into("<II", data, 0x98 + 112 + 8, 0x1000, 40)
    sh = 0x98 + 240
    struct.pack_into("<IIII", data, sh + 8, 512, 0x1000, 512, 512)
    struct.pack_into("<I", data, 512 + 12, 0x1050)
    name = b"Qt5Core.dll\0"; data[592:592 + len(name)] = name
    return data


class DiagnoseTests(unittest.TestCase):
    def test_static_qt_import_does_not_launch_or_load_application(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "app.exe"); path.write_bytes(pe_bytes())
            with patch("subprocess.run", side_effect=AssertionError("must not execute")):
                report = diagnose.inspect(path)
            self.assertEqual(report["machine"], "x64")
            self.assertEqual(report["dependencies"][0]["name"], "Qt5Core.dll")
            self.assertEqual(report["dependencies"][0]["family"], "application_qt")

    def test_runtimeconfig_preserves_framework_family(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "app.exe"); path.write_bytes(pe_bytes())
            path.with_suffix(".runtimeconfig.json").write_text(json.dumps({"runtimeOptions": {
                "framework": {"name": "Microsoft.WindowsDesktop.App", "version": "8.0.0"}}}))
            report = diagnose.inspect(path)
            self.assertEqual(report["runtime"]["frameworks"][0]["name"], "Microsoft.WindowsDesktop.App")

    def test_truncated_pe_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bad.exe"); path.write_bytes(b"MZ\0")
            with self.assertRaises(ValueError):
                diagnose.inspect(path)


class DownloadTests(unittest.TestCase):
    def test_reject_nonofficial_and_non_https(self):
        for url in ("http://download.microsoft.com/a.exe", "https://example.com/a.exe",
                    "https://download.microsoft.com.evil.example/a.exe", "https://user@aka.ms/a.exe"):
            self.assertFalse(downloads.allowed_url(url))

    def test_invalid_signature_prevents_installer_execution(self):
        with patch.object(downloads, "verify_microsoft", return_value=(False, "invalid signature")), \
             patch.object(api.subprocess, "run", side_effect=AssertionError("installer executed")):
            result = api._run_installer("test.exe", [])
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
