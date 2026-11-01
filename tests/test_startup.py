import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch
import winreg

from ksr import startup, journal


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.key = 'Software\\KSRTests\\' + uuid.uuid4().hex
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.key) as h:
            winreg.SetValueEx(h, 'FixtureApp', 0, winreg.REG_SZ, 'C:\\Fixture\\app.exe --background')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {'KSR_STATE_DIR': self.temp.name}); env.start(); self.addCleanup(env.stop)
        keys = patch.object(startup, 'KEYS', [('HKCU', self.key, '测试当前用户')]); keys.start();self.addCleanup(keys.stop)
        self.addCleanup(lambda: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, self.key))

    def test_selected_run_value_can_be_disabled_and_undone(self):
        row=startup.items()[0]
        result=startup.disable([{'id':row['id'],'fingerprint':row['fingerprint']}])
        self.assertTrue(result['ok']);self.assertEqual(startup.items(),[])
        journal.undo(result['journal_id'])
        self.assertEqual(startup.items()[0]['command'],row['command'])

    def test_stale_selection_cannot_disable_changed_value(self):
        row=startup.items()[0]
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,self.key,0,winreg.KEY_WRITE) as h:
            winreg.SetValueEx(h,'FixtureApp',0,winreg.REG_SZ,'C:\\Fixture\\updated.exe')
        with self.assertRaises(ValueError):startup.disable([{'id':row['id'],'fingerprint':row['fingerprint']}])
        self.assertEqual(len(startup.items()),1)

    def test_arbitrary_id_and_empty_selection_do_not_write(self):
        for selections in [[],[{'id':'arbitrary','fingerprint':'x'}]]:
            with self.assertRaises(ValueError):startup.disable(selections)
        self.assertEqual(len(startup.items()),1)

    def test_no_startup_item_is_preselected_or_disabled_by_inventory(self):
        row=startup.items()[0]
        self.assertTrue(row['enabled']);self.assertEqual(len(startup.items()),1)
        self.assertFalse((Path(self.temp.name)/'history').exists())


if __name__=='__main__':unittest.main()
