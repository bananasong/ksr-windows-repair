"""Repair outcome regressions; installer and filesystem failures are injected."""
import json
import os
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from ksr import api, build_pack, downloads, engine, journal, report


def configuration():
    pack = build_pack.build()
    return engine.ConfigManager({"info": {"groups": pack["groups"]}, "scripts": pack["scripts"]})


class InstallerOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {"KSR_STATE_DIR": self.temp.name})
        env.start(); self.addCleanup(env.stop)
        admin = patch.object(api.w, "is_admin", return_value=True)
        admin.start(); self.addCleanup(admin.stop)
        download = patch.object(api, "_download", return_value=(True, "fixture package"))
        download.start(); self.addCleanup(download.stop)
        signature = patch.object(downloads, "verify_microsoft", return_value=(True, "fixture signature"))
        signature.start(); self.addCleanup(signature.stop)
        self.cfg = configuration()
        self.vc = next(r for r in self.cfg.rules.values() if r.fix and r.fix["api"] == "vcredist.install"
                       and r.fix["args"].get("gen") == 14 and r.fix["args"].get("arch") == "x64")

    def repair(self, code, verify):
        with patch.object(api.subprocess, "run", return_value=SimpleNamespace(returncode=code)), \
             patch.dict(api.CHECKS, {self.vc.verify["api"]: verify}):
            finding = engine.Finding(self.vc, "fixture missing runtime", {})
            engine.Engine(self.cfg, dry_run=False, include_optional=True).run_fix([finding])
        return finding

    def test_3010_is_pending_even_when_immediate_probe_would_pass(self):
        verify = Mock(return_value=api.ok("files installed"))
        finding = self.repair(3010, verify)
        self.assertEqual(finding.fix_status, "pending_reboot")
        self.assertIs(finding.fix_ok, False)
        self.assertTrue(finding.to_dict()["needs_reboot"])
        self.assertEqual(finding.to_dict()["installer_exit_codes"], [3010])
        verify.assert_not_called()
        record = json.loads((journal.root() / finding.journal_id / "journal.json").read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "pending_reboot")
        self.assertTrue(record["needs_reboot"])
        self.assertEqual(record["installer_exit_codes"], [3010])

    def test_3010_does_not_require_files_to_be_ready_before_reboot(self):
        finding = self.repair(3010, Mock(side_effect=AssertionError("probe before reboot")))
        self.assertEqual(finding.fix_status, "pending_reboot")

    def test_zero_still_requires_a_successful_postcheck(self):
        for healthy, expected in ((True, "verified"), (False, "failed")):
            with self.subTest(healthy=healthy):
                verify = Mock(return_value=api.ok("ready") if healthy else api.bad("still missing"))
                finding = self.repair(0, verify)
                self.assertEqual(finding.fix_status, expected)
                self.assertEqual(finding.fix_ok, healthy)
                self.assertFalse(finding.to_dict()["needs_reboot"])
                verify.assert_called_once()

    def test_installer_failure_is_not_verified(self):
        verify = Mock(side_effect=AssertionError("probe after failed installer"))
        finding = self.repair(1603, verify)
        self.assertEqual(finding.fix_status, "failed")
        self.assertFalse(finding.fix_ok)
        self.assertEqual(finding.to_dict()["installer_exit_codes"], [1603])
        verify.assert_not_called()

    def test_unavailable_postcheck_is_unverified_instead_of_failed(self):
        verify = Mock(return_value={"ok": False, "status": "unavailable", "detail": "fixture access denied", "data": {}})
        finding = self.repair(0, verify)
        self.assertEqual(finding.fix_status, "unverified")
        self.assertFalse(finding.fix_ok)

    def test_multiarch_preserves_reboot_and_does_not_hide_partial_failure(self):
        for codes, good in (((3010, 0), True), ((0, 3010), True), ((3010, 1603), False)):
            with self.subTest(codes=codes), patch.object(api.subprocess, "run", side_effect=[
                    SimpleNamespace(returncode=code) for code in codes]):
                result = api.FIXES["vcredist.install"]({"gen": 14})
                self.assertEqual(result.ok, good)
                self.assertTrue(result.needs_reboot)
                self.assertEqual(result.exit_codes, codes)

    def test_partial_install_failure_stays_failed_with_reboot_flag(self):
        rule = engine.Rule("multi", "runtime", "fixture", check={"api": "dotnet.version"},
                           fix={"api": "vcredist.install", "args": {"gen": 14}})
        finding = engine.Finding(rule, "fixture", {})
        with patch.object(api.subprocess, "run", side_effect=[
                SimpleNamespace(returncode=3010), SimpleNamespace(returncode=1603)]):
            engine.Engine(self.cfg, dry_run=False).run_fix([finding])
        self.assertEqual(finding.fix_status, "failed")
        self.assertFalse(finding.fix_ok)
        self.assertTrue(finding.to_dict()["needs_reboot"])

    def test_directx_forwards_dynamic_reboot_requirement(self):
        with patch.object(api.subprocess, "run", return_value=SimpleNamespace(returncode=3010)):
            result = api.FIXES["directx.install"]({})
        self.assertTrue(result.ok)
        self.assertTrue(result.needs_reboot)
        self.assertEqual(result.exit_codes, (3010,))

    def test_invalid_signature_and_timeout_fail_without_success_metadata(self):
        with patch.object(downloads, "verify_microsoft", return_value=(False, "invalid signature")), \
             patch.object(api.subprocess, "run", side_effect=AssertionError("untrusted installer executed")):
            result = api._run_installer("fixture.exe", [])
        self.assertFalse(result.ok)
        self.assertFalse(result.needs_reboot)
        with patch.object(api.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture.exe", 7)):
            result = api._run_installer("fixture.exe", [], timeout=7)
        self.assertFalse(result.ok)
        self.assertIn("7", result.message)


class PrintOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = configuration()
        self.rule = next(r for r in self.cfg.rules.values() if r.check["api"] == "print.queue")

    def test_unreadable_queue_is_unavailable_and_never_counted_as_healthy(self):
        for error in (PermissionError("denied"), FileNotFoundError("missing"), OSError("I/O failure")):
            with self.subTest(error=type(error).__name__), \
                 patch.object(api.os, "listdir", side_effect=error), \
                 patch.object(api.os.path, "isdir", return_value=True):
                scan = engine.Engine(self.cfg).run_scan(uuids=[self.rule.uuid])
            self.assertEqual(scan["passed"], [])
            self.assertEqual(len(scan["findings"]), 1)
            finding = scan["findings"][0]
            self.assertEqual(finding.status, "unavailable")
            self.assertIsNone(finding.to_dict()["fix"])
            with patch.dict(api.FIXES, {"print.clear_queue": Mock(side_effect=AssertionError("queue cleared"))}):
                engine.Engine(self.cfg, dry_run=False, include_optional=True).run_fix([finding])
            self.assertEqual(finding.fix_status, "not_run")

    def test_empty_readable_queue_still_passes(self):
        with patch.object(api.os.path, "isdir", return_value=True), patch.object(api.os, "listdir", return_value=[]):
            scan = engine.Engine(self.cfg).run_scan(uuids=[self.rule.uuid])
        self.assertEqual(scan["findings"], [])
        self.assertEqual(len(scan["passed"]), 1)
        self.assertFalse(scan["passed"][0]["skip"])


class ReportOutcomeTests(unittest.TestCase):
    def render(self, finding):
        scan = {"findings": [finding], "groups": {}, "scanned": 1, "elapsed_ms": 0}
        return report.render(scan, {}, configuration(), dry_run=False)

    def test_pending_reboot_is_not_rendered_as_failure(self):
        rule = next(r for r in configuration().rules.values() if r.fix)
        finding = engine.Finding(rule, "fixture", {}, fix_status="pending_reboot", fix_ok=False)
        html = self.render(finding)
        self.assertIn("待重启验证", html)
        self.assertNotIn('class="fail">失败', html)

    def test_unavailable_check_has_no_repair_action_in_report(self):
        rule = next(r for r in configuration().rules.values() if r.check["api"] == "print.queue")
        html = self.render(engine.Finding(rule, "fixture access denied", {}, status="unavailable"))
        self.assertIn("检测未完成", html)
        self.assertNotIn("修复动作", html)


if __name__ == "__main__":
    unittest.main()
