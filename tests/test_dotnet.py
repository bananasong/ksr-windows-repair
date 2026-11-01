import json
import hashlib
import io
import os
from pathlib import Path
import tempfile
import struct
import unittest
import zipfile
from unittest.mock import Mock, patch

from ksr import dotnet, downloads, api
from test_journal_diagnose import pe_bytes


class RuntimePolicyTests(unittest.TestCase):
    def test_official_roll_forward_examples(self):
        available = ['8.2.0', '8.2.3', '8.4.5', '9.0.0', '9.0.6', '9.7.8', '10.0.0-preview.1']
        for policy, expected in {'Minor': '8.2.3', 'Major': '8.2.3', 'LatestPatch': None,
                                 'LatestMinor': '8.4.5', 'LatestMajor': '9.7.8', 'Disable': None}.items():
            with self.subTest(policy=policy):
                self.assertEqual(dotnet.select_version('8.0.0', available, policy), expected)

    def test_no_downgrade_and_disable_is_exact(self):
        self.assertIsNone(dotnet.select_version('8.0.8', ['8.0.7', '7.0.20'], 'Minor'))
        self.assertEqual(dotnet.select_version('8.0.8', ['8.0.8', '8.0.33'], 'Disable'), '8.0.8')

    def test_reject_prerelease_and_unknown_policy(self):
        for version, policy in [('8.0.0-preview.1', 'Minor'), ('8.0.0', 'Unexpected')]:
            with self.assertRaises(ValueError):
                dotnet.select_version(version, [], policy)


class RuntimePlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        environment = patch.dict(os.environ)
        environment.start(); self.addCleanup(environment.stop)
        for key in list(os.environ):
            if key.upper().startswith(('DOTNET_ROOT', 'DOTNET_ROLL_FORWARD')): os.environ.pop(key)
        self.root = Path(self.temp.name)
        self.app = self.root / 'sample.exe'; self.app.write_bytes(pe_bytes())
        self.runtime = self.root / 'runtime'
        self.config()
        self.metadata = {
            'index': {'releases-index': [{'channel-version': '8.0', 'support-phase': 'maintenance'}]},
            'releases': {'releases': [{'release-version': '8.0.33', 'runtime': self.package('runtime'),
                                      'windowsdesktop': self.package('windowsdesktop'),
                                      'aspnetcore-runtime': self.package('aspnetcore-runtime')}]}}
        fetch = patch.object(dotnet, 'fetch_json', side_effect=lambda url: self.metadata['index' if url.endswith('releases-index.json') else 'releases'])
        fetch.start(); self.addCleanup(fetch.stop)

    def package(self, name):
        prefix = {'runtime': 'dotnet-runtime', 'windowsdesktop': 'windowsdesktop-runtime',
                  'aspnetcore-runtime': 'aspnetcore-runtime'}[name]
        return {'version': '8.0.33', 'files': [{'rid': 'win-' + arch,
                'name': prefix + '-win-' + arch + '.' + ext,
                'url': 'https://builds.dotnet.microsoft.com/dotnet/' + name + '-' + arch + '.' + ext,
                'hash': 'a' * 128} for arch in ('x64', 'x86') for ext in ('exe', 'zip')]}

    def config(self, family='Microsoft.WindowsDesktop.App', version='8.0.0', **options):
        data = {'framework': {'name': family, 'version': version}, **options}
        self.app.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': data}), encoding='utf-8')

    def plan(self, **kw):
        return dotnet.plan_for_app(self.app, runtime_root=self.runtime, **kw)

    def test_desktop_plan_has_matching_architecture_hash_and_base_runtime(self):
        p = self.plan(mode='private')
        self.assertEqual(p['status'], 'ready')
        self.assertEqual({x['family'] for x in p['packages']}, {'Microsoft.WindowsDesktop.App', 'Microsoft.NETCore.App'})
        self.assertTrue(all(x['architecture'] == 'x64' and len(x['sha512']) == 128 for x in p['packages']))

    def test_console_does_not_choose_desktop_or_sdk(self):
        self.config(family='Microsoft.NETCore.App')
        self.assertEqual([x['family'] for x in self.plan()['packages']], ['Microsoft.NETCore.App'])

    def pe32(self, neutral=False):
        data = bytearray(1024); data[:2] = b'MZ'
        struct.pack_into('<I', data, 0x3c, 0x80); data[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<HH', data, 0x84, 0x14c, 1)
        struct.pack_into('<H', data, 0x94, 224); struct.pack_into('<H', data, 0x98, 0x10b)
        struct.pack_into('<I', data, 0x98 + 60, 512); struct.pack_into('<I', data, 0x98 + 92, 16)
        struct.pack_into('<IIII', data, 0x98 + 224 + 8, 512, 0x1000, 512, 512)
        if neutral:
            struct.pack_into('<II', data, 0x98 + 96 + 14 * 8, 0x1100, 72)
            struct.pack_into('<I', data, 768 + 16, 1)
        self.app.write_bytes(data)

    def test_pe32_targets_x86_runtime(self):
        self.pe32()
        self.assertEqual(self.plan()['packages'][0]['architecture'], 'x86')

    def test_apphost_zip_is_not_mistaken_for_base_runtime(self):
        files = self.metadata['releases']['releases'][0]['runtime']['files']
        files.append({'rid': 'win-x64', 'name': 'dotnet-apphost-pack-win-x64.zip',
                      'url': 'https://builds.dotnet.microsoft.com/dotnet/apphost.zip', 'hash': 'b' * 128})
        result = self.plan(mode='private')
        self.assertEqual(result['status'], 'ready')
        self.assertEqual(next(p for p in result['packages'] if p['family'] == 'Microsoft.NETCore.App')['sha512'], 'a' * 128)

    def test_anycpu_defaults_to_host_but_allows_explicit_x86(self):
        self.pe32(neutral=True)
        with patch.dict(os.environ, {'PROCESSOR_ARCHITECTURE': 'AMD64', 'PROCESSOR_ARCHITEW6432': 'AMD64'}):
            self.assertEqual(self.plan()['packages'][0]['architecture'], 'x64')
            self.assertEqual(self.plan(architecture='x86')['packages'][0]['architecture'], 'x86')

    def test_self_contained_does_not_offer_shared_runtime_installation(self):
        self.app.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
            'includedFrameworks': [{'name': 'Microsoft.NETCore.App', 'version': '8.0.0'}]}}))
        self.assertEqual(self.plan()['status'], 'self_contained')
        self.assertEqual(self.plan()['packages'], [])

    def test_aspnet_gets_its_own_runtime(self):
        self.config(family='Microsoft.AspNetCore.App')
        self.assertEqual([x['family'] for x in self.plan()['packages']], ['Microsoft.AspNetCore.App'])

    def test_exact_old_patch_is_not_silently_upgraded(self):
        self.config(version='8.0.0', rollForward='Disable')
        p = self.plan()
        self.assertEqual(p['status'], 'blocked')
        self.assertEqual(p['packages'], [])

    def test_unsupported_or_eol_channel_does_not_install(self):
        self.metadata['index']['releases-index'][0]['support-phase'] = 'eol'
        self.assertEqual(self.plan()['status'], 'blocked')

    def test_unknown_family_and_legacy_policy_are_blocked(self):
        for family, options in [('Something.Else', {}), ('Microsoft.NETCore.App', {'applyPatches': False})]:
            self.config(family=family, **options)
            self.assertEqual(self.plan()['status'], 'blocked')

    def test_invalid_download_origin_or_hash_is_rejected(self):
        for field, value in [('url', 'https://evil.invalid/file.exe'), ('hash', 'bad')]:
            entry = self.metadata['releases']['releases'][0]['windowsdesktop']['files'][0]
            previous = entry[field]; entry[field] = value
            with self.assertRaises(ValueError): self.plan()
            entry[field] = previous

    def test_environment_override_is_reported_and_applied(self):
        with patch.dict(os.environ, {'DOTNET_ROLL_FORWARD': 'Disable'}):
            self.assertEqual(self.plan()['status'], 'blocked')

    def test_custom_runtime_root_is_not_mistaken_for_system_host(self):
        with patch.dict(os.environ, {'DOTNET_ROOT_X64': str(self.root / 'custom')}), \
             patch.object(dotnet, 'default_root', return_value=self.runtime):
            self.assertEqual(dotnet.inspect_app(self.app)['status'], 'blocked')

    def test_existing_private_destination_is_not_modified(self):
        self.runtime.mkdir(); marker = self.runtime / 'user.txt'; marker.write_text('keep')
        with self.assertRaises(ValueError):
            dotnet.install_for_app(self.app, install_dir=self.runtime)
        self.assertEqual(marker.read_text(), 'keep')

    def test_system_install_requires_admin_before_download(self):
        with patch('ksr.win32api.is_admin', return_value=False), \
             patch.object(downloads, 'download', side_effect=AssertionError('download without admin')):
            result = dotnet.install_for_app(self.app)
        self.assertEqual(result['status'], 'failed')

    def test_plan_change_requires_review_again(self):
        with patch('ksr.win32api.is_admin', return_value=True), \
             patch.object(dotnet, 'default_root', return_value=self.runtime):
            result = dotnet.install_for_app(self.app, expected_packages=[])
        self.assertEqual(result['status'], 'blocked')

    def test_installer_3010_preserves_pending_state(self):
        with patch.dict(os.environ, {'KSR_STATE_DIR': str(self.root / 'state')}), \
             patch('ksr.win32api.is_admin', return_value=True), \
             patch.object(dotnet, 'default_root', return_value=self.runtime), \
             patch.object(downloads, 'download', return_value=(True, 'fixture package')), \
             patch.object(api, '_run_installer', return_value=api.FixResult(True, 'installed', True, (3010,))):
            result = dotnet.install_for_app(self.app)
        self.assertEqual(result['status'], 'pending_reboot')
        self.assertFalse(result['ok'])
        self.assertTrue(result['needs_reboot'])
        self.assertEqual(result['installer_exit_codes'], [3010])

    def test_private_archive_cannot_escape_destination(self):
        archive = self.root / 'unsafe.zip'
        with zipfile.ZipFile(archive, 'w') as z: z.writestr('../escaped.txt', 'bad')
        destination = self.root / 'extract'; destination.mkdir()
        with self.assertRaises(ValueError): dotnet.extract_archive(archive, destination)
        self.assertFalse((self.root / 'escaped.txt').exists())

    def test_desktop_without_its_base_runtime_is_not_satisfied(self):
        folder = self.runtime / 'shared/Microsoft.WindowsDesktop.App/8.0.33'; folder.mkdir(parents=True)
        (folder / 'Microsoft.WindowsDesktop.App.deps.json').write_text('{}')
        (folder / 'Microsoft.WindowsDesktop.App.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
            'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.33'}, 'rollForward': 'LatestPatch'}}))
        result = dotnet.inspect_app(self.app, runtime_root=self.runtime)
        self.assertEqual(result['status'], 'missing')
        self.assertTrue(any(r.get('implicit') and not r['selected_version'] for r in result['frameworks']))


class HashTests(unittest.TestCase):
    def test_sha512_mismatch_discards_download(self):
        data = b'x' * 65536
        class Response(io.BytesIO):
            def geturl(self): return 'https://builds.dotnet.microsoft.com/dotnet/test.zip'
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'file.zip'
            opener = Mock()
            opener.open.side_effect = lambda *a, **k: Response(data)
            with patch.object(downloads.urllib.request, 'build_opener', return_value=opener):
                good, _ = downloads.download('https://builds.dotnet.microsoft.com/dotnet/test.zip', target, expected_sha512='0' * 128)
                self.assertFalse(good)
                self.assertFalse(target.exists())
                good, _ = downloads.download('https://builds.dotnet.microsoft.com/dotnet/test.zip', target,
                                             expected_sha512=hashlib.sha512(data).hexdigest())
                self.assertTrue(good)
                self.assertEqual(target.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
