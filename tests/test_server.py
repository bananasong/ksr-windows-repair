import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from ksr import api, engine
from ksr.ui.server import make_server


class ServerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        env = patch.dict(os.environ, {"KSR_STATE_DIR": temp.name})
        env.start(); self.addCleanup(env.stop)
        self.fixed = []
        checks = patch.dict(api.CHECKS, {"http.check": lambda _: api.ok("healthy")})
        fixes = patch.dict(api.FIXES, {"http.fix": lambda _: self.fixed.append(True) or (True, "done")})
        checks.start(); fixes.start()
        self.addCleanup(checks.stop); self.addCleanup(fixes.stop)
        cfg = engine.ConfigManager({"info": {"groups": [{"id": "http"}]}, "scripts": [{
            "uuid": "http-test", "group": "http", "title": "HTTP test",
            "check": {"api": "http.check"}, "fix": {"api": "http.fix"}}]})
        self.server, self.state = make_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    def request(self, path, payload=None, headers=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base + path, data=data, headers=headers or {})
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()

    def test_home_and_api_require_session(self):
        for path in ("/", "/api/bootstrap"):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request(path)
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
        status, _ = self.request("/?t=" + self.state.token)
        self.assertEqual(status, 200)

    def test_cross_origin_request_rejected_even_with_token(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request("/api/bootstrap", headers={"X-KSR-Token": self.state.token, "Origin": "https://example.com"})
        self.assertEqual(error.exception.code, 403)
        error.exception.close()

    def test_fix_rechecks_current_state_and_skips_healthy_rule(self):
        _, response = self.request("/api/fix", {"uuids": ["http-test"]}, {"X-KSR-Token": self.state.token})
        events = [json.loads(line) for line in response.splitlines()]
        self.assertTrue(any(e.get("status") == "not_needed" for e in events))
        self.assertFalse(self.fixed)

    def test_preloaded_content_cannot_terminate_script_element(self):
        attack = "</script><script>alert('unexpected')</script>"
        with patch.dict(api.CHECKS, {"http.check": lambda _: api.bad(attack)}):
            _, body = self.request("/?t=" + self.state.token)
        self.assertNotIn(attack.encode(), body)
        self.assertIn(b"\\u003c/script>", body)

    def test_pending_reboot_event_is_not_reported_as_failed(self):
        with patch.dict(api.CHECKS, {"http.check": lambda _: api.bad("fixture issue")}), \
             patch.dict(api.FIXES, {"http.fix": lambda _: api.FixResult(True, "installed", True, (3010,))}):
            _, response = self.request("/api/fix", {"uuids": ["http-test"]}, {"X-KSR-Token": self.state.token})
        events = [json.loads(line) for line in response.splitlines()]
        item = next(e for e in events if e["type"] == "item")
        done = next(e for e in events if e["type"] == "done")
        self.assertEqual(item["status"], "pending_reboot")
        self.assertTrue(item["needs_reboot"])
        self.assertEqual(item["installer_exit_codes"], [3010])
        self.assertEqual(done["ok_count"], 0)
        self.assertEqual(done["failed"], [])
        self.assertEqual(len(done["pending_reboot"]), 1)

    def test_dotnet_install_requires_session_and_explicit_plan_confirmation(self):
        for headers, payload, expected in (({}, {}, 403), ({"X-KSR-Token": self.state.token}, {}, 400),
                ({"X-KSR-Token": self.state.token}, {"confirm": True}, 400)):
            with self.subTest(expected=expected), self.assertRaises(urllib.error.HTTPError) as error:
                self.request('/api/dotnet/install', payload, headers)
            self.assertEqual(error.exception.code, expected)
            error.exception.close()


if __name__ == "__main__":
    unittest.main()
