import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ksr import api, engine, build_pack


def config(**overrides):
    rule = dict(uuid="test", group="test", title="Test", check={"api": "test.check"},
                fix={"api": "test.fix"}, verify={"api": "test.check"})
    rule.update(overrides)
    return engine.ConfigManager({"info": {"groups": [{"id": "test"}]}, "scripts": [rule]})


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        environment = patch.dict(os.environ, {"KSR_STATE_DIR": self.temp.name})
        environment.start(); self.addCleanup(environment.stop)
        self.checks = patch.dict(api.CHECKS, {"test.check": lambda _: api.ok("healthy")})
        self.fixes = patch.dict(api.FIXES, {"test.fix": lambda _: (True, "done")})
        self.checks.start(); self.fixes.start()
        self.addCleanup(self.checks.stop); self.addCleanup(self.fixes.stop)

    def test_repeat_scan_does_not_accumulate_passes(self):
        e = engine.Engine(config())
        e.run_scan()
        self.assertEqual(len(e.run_scan()["passed"]), 1)

    def test_verification_exception_cannot_be_success(self):
        cfg = config()
        f = engine.Finding(next(iter(cfg.rules.values())), "", {})
        with patch.dict(api.CHECKS, {"test.check": lambda _: (_ for _ in ()).throw(OSError("offline"))}):
            engine.Engine(cfg, dry_run=False).run_fix([f])
        self.assertIs(f.fix_ok, False)

    def test_check_failure_is_not_repairable(self):
        with patch.dict(api.CHECKS, {"test.check": lambda _: (_ for _ in ()).throw(PermissionError("denied"))}):
            f = engine.Engine(config()).run_scan()["findings"][0]
        self.assertEqual(f.to_dict()["status"], "unavailable")
        self.assertIsNone(f.to_dict()["fix"])

    def test_invalid_verify_api_is_rejected_at_load(self):
        with self.assertRaises(ValueError):
            config(verify={"api": "unregistered"})

    def test_optional_actions_are_not_fixed_by_default(self):
        cfg = config(optional=True)
        f = engine.Finding(next(iter(cfg.rules.values())), "", {})
        with patch.dict(api.FIXES, {"test.fix": lambda _: self.fail("optional action executed")}):
            engine.Engine(cfg, dry_run=False).run_fix([f])
        self.assertIsNone(f.fix_ok)


class ApiTests(unittest.TestCase):
    def test_file_search_tries_matching_architecture(self):
        with patch.object(api, "_candidate_dirs", return_value=["x64", "x86"]), \
             patch.object(api.os.path, "isfile", return_value=True), \
             patch.object(api.w, "pe_info", side_effect=lambda p: {"bits": 64 if p.startswith("x64") else 32}):
            result = api.CHECKS["files.present"]({"names": ["library.dll"], "arch": 32})
        self.assertTrue(result["ok"], result)

    def test_access_denied_is_not_missing_registry_value(self):
        with patch.object(api.winreg, "OpenKey", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                api.reg_read("HKLM", "test", "value")

    def test_cleanup_limit_is_global(self):
        with tempfile.TemporaryDirectory() as temp:
            for sub in ("a", "b", "c"):
                directory = Path(temp, sub); directory.mkdir()
                (directory / "old.tmp").write_text("data")
            api.FIXES["fs.clean"]({"path": temp, "max_files": 1})
            self.assertEqual(len(list(Path(temp).rglob("old.tmp"))), 2)

    def test_no_automatic_driver_filter_rewrite(self):
        for r in build_pack.build()["scripts"]:
            if r["check"]["api"] == "sysopt.probe" and r["check"]["args"]["item"] in {"camera19", "gpu19", "mouse19"}:
                self.assertIsNone(r.get("fix"), r["title"])


if __name__ == "__main__":
    unittest.main()
