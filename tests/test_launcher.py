import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ksr import __main__ as cli

spec = importlib.util.spec_from_file_location('ksr_gui_launcher', Path(__file__).resolve().parents[1] / 'tools/ksr_launcher.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class LauncherTests(unittest.TestCase):
    def test_double_click_uses_default_browser(self):
        with patch.object(cli, 'main', return_value=0) as called:
            self.assertEqual(launcher.main([]), 0)
        called.assert_called_once_with(['ui', '--browser'])

    def test_cli_arguments_are_preserved(self):
        with patch.object(cli, 'main', return_value=0) as called:
            self.assertEqual(launcher.main(['scan', '--json']), 0)
        called.assert_called_once_with(['scan', '--json'])

    def test_failed_gui_start_is_visible_even_without_console(self):
        with patch.object(cli, 'main', return_value=1), patch.object(launcher, 'show_startup_error') as message:
            self.assertEqual(launcher.main([]), 1)
        message.assert_called_once()

    def test_windowed_executable_with_no_stdio_writes_local_log(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'KSR_STATE_DIR': directory}):
            opened = None
            with patch.object(launcher.sys, 'stdout', None), patch.object(launcher.sys, 'stderr', None):
                try:
                    path = launcher.configure_output()
                    opened = launcher.sys.stdout
                    print('GUI 启动日志', flush=True)
                    self.assertIs(launcher.sys.stdout, launcher.sys.stderr)
                finally:
                    if opened is not None: opened.close()
            self.assertIn('GUI 启动日志', Path(path).read_text(encoding='utf-8'))


if __name__ == '__main__': unittest.main()
