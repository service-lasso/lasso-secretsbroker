"""SPEC-194 IPC-1/2: producer CLI, inherited transport and immutable identity."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
GENERATOR = ROOT / 'scripts/macos11-compat-profile.py'


class Profile(unittest.TestCase):
    def generate(self, root, tag='2026.10.5-aaaaaaa', candidate='a' * 40):
        (root / 'provenance.json').write_text(json.dumps({'candidateSHA': candidate}))
        return subprocess.run([sys.executable, str(GENERATOR), str(ROOT / 'service.json'),
                               str(root / 'archive.json'), str(root / 'public.json'), tag,
                               str(root / 'provenance.json')], capture_output=True)

    def test_raw_profile_matches_core_native_contract(self):
        before = (ROOT / 'service.json').read_bytes()
        original = json.loads(before)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.generate(root)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual((root / 'archive.json').read_bytes(), (root / 'public.json').read_bytes())
            profile = json.loads((root / 'public.json').read_bytes())
            self.assertNotIn('endpoints', profile)
            self.assertNotIn('SECRETSBROKER_LISTEN', profile['execconfig']['env'])
            self.assertEqual(profile['execconfig']['env']['SECRETSBROKER_MODE'], 'production')
            self.assertEqual(profile['execconfig']['env']['SECRETSBROKER_TRANSPORT'], 'auto')
            self.assertEqual(profile['healthchecks'], [{'id': 'secretsbroker-process-health',
                             'type': 'process', 'required': True, 'retries': 80, 'interval': 250}])
            self.assertNotIn('healthcheck', profile)
            self.assertNotIn('${endpoint.', json.dumps(profile))
            self.assertEqual(profile['artifact']['source']['tag'], '2026.10.5-aaaaaaa')
            self.assertNotIn('channel', profile['artifact']['source'])
            for platform in ('win32', 'linux', 'default'):
                self.assertEqual(profile['artifact']['platforms'][platform], original['artifact']['platforms'][platform])
            darwin = copy.deepcopy(original['artifact']['platforms']['darwin'])
            darwin['assetName'] = 'secretsbroker-darwin-amd64-macos11.tar.gz'
            self.assertEqual(profile['artifact']['platforms']['darwin'], darwin)
        self.assertEqual((ROOT / 'service.json').read_bytes(), before)
        self.assertEqual(original['healthchecks'][0]['type'], 'http')
        self.assertTrue(original['endpoints'])

    def test_bad_identity_does_not_emit_profile(self):
        for tag, candidate in [('latest', 'a' * 40), ('2026.10.5-bbbbbbb', 'a' * 40),
                               ('2026.10.5-aaaaaaa', 'a' * 7)]:
            with self.subTest(tag=tag, candidate=candidate), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                self.assertNotEqual(self.generate(root, tag, candidate).returncode, 0)
                self.assertFalse((root / 'archive.json').exists())
                self.assertFalse((root / 'public.json').exists())


if __name__ == '__main__':
    unittest.main()
