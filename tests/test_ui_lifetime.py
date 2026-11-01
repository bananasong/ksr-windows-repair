import urllib.parse
import urllib.request
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ksr import api, engine
from ksr.ui import app


class WindowLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = engine.ConfigManager({'info': {'groups': []}, 'scripts': []})

    def test_exited_edge_launcher_does_not_stop_a_live_page(self):
        launcher = Mock(); launcher.poll.return_value = 0
        args = []
        observed = []

        def launch(command):
            args.extend(command)
            return launcher

        def page_is_alive(_):
            url = next(a.removeprefix('--app=') for a in args if a.startswith('--app='))
            parsed = urllib.parse.urlsplit(url)
            token = urllib.parse.parse_qs(parsed.query)['t'][0]
            request = urllib.request.Request(f'http://{parsed.netloc}/api/bootstrap', headers={'X-KSR-Token': token})
            with urllib.request.urlopen(request, timeout=3) as response:
                observed.append(response.status)
            raise KeyboardInterrupt

        with patch.object(app, '_find_browser', return_value='fixture-edge.exe'), \
             patch.object(app.subprocess, 'Popen', side_effect=launch), \
             patch.object(app.time, 'sleep', side_effect=page_is_alive):
            app.run(self.cfg)
        self.assertEqual(observed, [200], 'An exited launcher must not terminate the page service')

    def test_repeated_launches_have_separate_browser_profiles(self):
        profiles = []

        def launch(command):
            profiles.append(next(a for a in command if a.startswith('--user-data-dir=')))
            return Mock(poll=lambda: None)

        with patch.object(app, '_find_browser', return_value='fixture-edge.exe'), \
             patch.object(app.subprocess, 'Popen', side_effect=launch), \
             patch.object(app.time, 'sleep', side_effect=KeyboardInterrupt):
            app.run(self.cfg)
            app.run(self.cfg)
        self.assertEqual(len(set(profiles)), 2)

    def test_server_expires_after_client_closes_or_never_connects(self):
        for seen, expected in ((None, 3), (0.0, 2)):
            now = [0.0]
            state = SimpleNamespace(last_client_seen=seen)

            def tick(_):
                now[0] += 1
                if now[0] > 5: self.fail('UI service did not expire')

            with self.subTest(seen=seen), patch.object(app.time, 'monotonic', side_effect=lambda: now[0]), \
                 patch.object(app.time, 'sleep', side_effect=tick):
                app._wait_for_ui(state, startup_timeout=3, client_timeout=2)
            self.assertEqual(now[0], expected)

    def test_default_browser_failure_is_reported(self):
        with patch.object(app.webbrowser, 'open', return_value=False), self.assertRaises(RuntimeError):
            app.run(self.cfg, browser_only=True)


if __name__ == '__main__':
    unittest.main()
