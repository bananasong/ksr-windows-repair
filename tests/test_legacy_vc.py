"""VC2005 installed in WinSxS must not repeatedly request installation."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from ksr import api, build_pack


class LegacyVCTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        stub = patch.object(api.w, 'system_root', return_value=str(self.root))
        stub.start(); self.addCleanup(stub.stop)

    def assembly(self, arch='x86', version='8.0.50727.9680', files=('msvcr80.dll', 'msvcp80.dll')):
        name = f'{arch}_microsoft.vc80.crt_1fc8b3b9a1e18e3b_{version}_none_fixture'
        folder = self.root / 'WinSxS' / name
        folder.mkdir(parents=True, exist_ok=True)
        manifest = self.root / 'WinSxS/Manifests' / (name + '.manifest')
        manifest.parent.mkdir(exist_ok=True)
        manifest.write_text(f'<assembly xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity '
                            f'name="Microsoft.VC80.CRT" type="win32" version="{version}" '
                            f'processorArchitecture="{arch}" publicKeyToken="1fc8b3b9a1e18e3b"/></assembly>', encoding='utf-8')
        for file in files:
            data = bytearray(256)
            data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 128)
            data[128:132] = b'PE\x00\x00'
            struct.pack_into('<H', data, 132, 0x14c if arch == 'x86' else 0x8664)
            (folder / file).write_bytes(data)
        return folder, manifest

    def probe(self):
        return api.CHECKS['dll.catalog']({'cat': 'vc80'})

    def test_complete_x86_sxs_passes_without_system32_dlls(self):
        self.assembly()
        self.assertTrue(self.probe()['ok'])

    def test_x64_does_not_satisfy_x86_requirement(self):
        self.assembly('amd64')
        self.assertFalse(self.probe()['ok'])

    def test_manifest_and_both_dlls_required_in_same_assembly(self):
        self.assembly(files=('msvcr80.dll',))
        self.assembly(version='8.0.50727.6195', files=('msvcp80.dll',))
        self.assertFalse(self.probe()['ok'])

    def test_directory_without_manifest_is_not_installed(self):
        _, manifest = self.assembly()
        manifest.unlink()
        self.assertFalse(self.probe()['ok'])

    def test_wrong_architecture_payload_rejected(self):
        folder, _ = self.assembly()
        for file in folder.glob('*.dll'):
            data = bytearray(file.read_bytes()); struct.pack_into('<H', data, 132, 0x8664)
            file.write_bytes(data)
        self.assertFalse(self.probe()['ok'])

    def test_invalid_manifest_identity_rejected(self):
        _, manifest = self.assembly()
        manifest.write_text(manifest.read_text().replace('Microsoft.VC80.CRT', 'Unrelated.CRT'))
        self.assertFalse(self.probe()['ok'])

    def test_system32_files_do_not_prove_sxs_installation(self):
        with patch.object(api, '_find_dll', return_value='unrelated.dll'):
            self.assertFalse(self.probe()['ok'])

    def test_rule_install_and_verification_target_same_architecture(self):
        rule = next(r for r in build_pack.build()['scripts'] if r['check']['args'].get('cat') == 'vc80')
        self.assertEqual(rule['check']['args']['arch'], 'x86')
        self.assertEqual(rule['fix']['args']['arch'], 'x86')


if __name__ == '__main__': unittest.main()
