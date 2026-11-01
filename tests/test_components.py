import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from ksr import api, build_pack, components, downloads


def pe(path, arch):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = bytearray(256); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\x00\x00'; struct.pack_into('<H', data, 132, 0x14c if arch == 'x86' else 0x8664)
    path.write_bytes(data)


class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        stub = patch.object(api.w, 'system_root', return_value=str(self.root))
        stub.start(); self.addCleanup(stub.stop)

    def test_2008_in_sxs_not_system32(self):
        self.assertFalse(components.probe_package('vc2008-x86')['ok'])
        for group, files in [('crt',['msvcr90.dll','msvcp90.dll']),('mfc',['mfc90.dll','mfc90u.dll']),('atl',['atl90.dll'])]:
            name=f'x86_microsoft.vc90.{group}_1fc8b3b9a1e18e3b_9.0.30729.6161_none_fixture'
            for name_dll in files: pe(self.root/'WinSxS'/name/name_dll, 'x86')
            manifest=self.root/'WinSxS/Manifests'/(name+'.manifest');manifest.parent.mkdir(exist_ok=True)
            manifest.write_text(f'<assembly xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity type="win32" name="Microsoft.VC90.{group.upper()}" version="9.0.30729.6161" processorArchitecture="x86" publicKeyToken="1fc8b3b9a1e18e3b"/></assembly>')
        self.assertTrue(components.probe_package('vc2008-x86')['ok'])
        self.assertFalse(components.probe_package('vc2008-x64')['ok'])

    def test_2013_requires_crt_and_mfc_matching_arch(self):
        for name in ['msvcr120.dll','msvcp120.dll','mfc120.dll','mfc120u.dll']:
            pe(self.root/'SysWOW64'/name,'x86')
        self.assertTrue(components.probe_package('vc2013-x86')['ok'])
        pe(self.root/'SysWOW64/mfc120u.dll','x64')
        self.assertFalse(components.probe_package('vc2013-x86')['ok'])

    def test_msxml4_uses_32bit_system_directory(self):
        for name in ['msxml4.dll','msxml4r.dll']: pe(self.root/'SysWOW64'/name,'x86')
        self.assertTrue(components.probe_package('msxml4')['ok'])

    def test_missing_components_require_explicit_optional_install(self):
        rules=[r for r in build_pack.build()['scripts'] if r['check']['api']=='component.probe']
        self.assertGreaterEqual(len(rules),13)
        self.assertTrue(all(r['optional'] and r['fix']['api']=='component.install' for r in rules))

    def test_unsupported_71_not_claimed_by_modern_package(self):
        rules=build_pack.build()['scripts']
        legacy=[r for r in rules if r['check']['args'].get('cat') in {'mfc_atl','vc_legacy'}]
        self.assertTrue(legacy)
        self.assertTrue(all(not r.get('fix') for r in legacy))
        self.assertEqual(api.catalog.BY_ID['vc_legacy']['files'],['msvcr70.dll','msvcr71.dll','msvcp70.dll','msvcp71.dll'])

    def test_no_admin_rejected_before_download(self):
        with patch.object(api.w,'is_admin',return_value=False), patch.object(downloads,'download') as download:
            result=components.install_package('vc2008-x86')
        self.assertFalse(result.ok); download.assert_not_called()

    def test_download_mismatch_never_executes_installer(self):
        with patch.object(api.w,'is_admin',return_value=True), patch.object(downloads,'download',return_value=(False,'SHA-256 mismatch')), patch.object(api,'_run_installer') as run:
            self.assertFalse(components.install_package('vc2008-x86').ok)
        run.assert_not_called()

    def test_3010_preserved_and_hash_is_required(self):
        with patch.object(api.w,'is_admin',return_value=True), patch.object(downloads,'download',return_value=(True,'downloaded')) as download, patch.object(api,'_run_installer',return_value=api.FixResult(True,'reboot',True,(3010,))):
            result=components.install_package('vc2008-x86')
        self.assertTrue(result.needs_reboot); self.assertEqual(result.exit_codes,(3010,))
        self.assertEqual(download.call_args.kwargs['expected_sha256'],components.PACKAGES['vc2008-x86']['sha256'])

    def test_publisher_rejection_never_executes(self):
        with patch.object(downloads,'verify_publisher',return_value=(False,'wrong signer')), patch.object(api.subprocess,'run') as run:
            self.assertFalse(api._run_installer('fixture.exe',[],publisher='NVIDIA Corporation').ok)
        run.assert_not_called()

    def test_non_official_download_hosts_and_unknown_publishers_rejected(self):
        self.assertTrue(downloads.allowed_url('https://openal.org/downloads/oalinst.zip'))
        self.assertFalse(downloads.allowed_url('https://openal.org.evil.test/installer.exe'))
        with self.assertRaises(ValueError): downloads.verify_publisher('anything.exe','Unknown Company')

    def test_existing_package_does_not_reinstall(self):
        with patch.object(components,'probe_package',return_value={'ok':True}), patch.object(downloads,'download') as download:
            self.assertTrue(components.install_package('openal').ok)
        download.assert_not_called()

    def test_changed_openal_zip_member_never_runs(self):
        def downloaded(url,target,**kwargs):
            with zipfile.ZipFile(target,'w') as archive:
                archive.writestr('oalinst.exe',b'changed installer')
                archive.writestr('../outside.exe',b'must not extract')
            return True,'fixture ZIP'
        with patch.object(api.w,'is_admin',return_value=True), patch.object(downloads,'download',side_effect=downloaded), patch.object(api,'_run_installer') as run:
            result=components.install_package('openal')
        self.assertFalse(result.ok);run.assert_not_called()


if __name__=='__main__': unittest.main()
