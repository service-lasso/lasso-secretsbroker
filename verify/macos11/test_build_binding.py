"""Candidate provenance and archive refusal regressions; no Go/native execution."""
import importlib.util
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HELPER = pathlib.Path(__file__).resolve().parents[2] / 'scripts/verify-compat-build.py'
spec = importlib.util.spec_from_file_location('binding', HELPER)
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


class BuildBinding(unittest.TestCase):
    def fixture(self, directory):
        root = pathlib.Path(directory) / 'root'
        owned = pathlib.Path(directory) / 'owned'
        files = [root / name for name in ('go.mod', 'go.sum', 'toolchains/macos11/go1.26.8.patch')]
        files += [owned / 'artifacts' / name for name in ('secretsbroker', 'secretsbroker-resolve')]
        for path in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(path.name.encode())
        doc = {'candidateSHA': 'a' * 40, 'sourceTree': 'b' * 40,
               'hashes': {str(p.relative_to(root)) if p.is_relative_to(root) else str(p): binding.digest(p)
                          for p in files}}
        (owned / 'artifacts/provenance.json').write_text(json.dumps(doc))
        return root, owned, doc

    @patch.object(binding, 'source_identity', return_value=('a' * 40, 'b' * 40))
    def test_stale_identity_missing_hash_and_mutated_binary_are_refused(self, identity):
        for mutation in ('commit', 'tree', 'missing', 'binary', 'source'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root, owned, doc = self.fixture(directory)
                if mutation == 'commit':
                    doc['candidateSHA'] = 'c' * 40
                elif mutation == 'tree':
                    doc['sourceTree'] = 'c' * 40
                elif mutation == 'missing':
                    del doc['hashes']['go.mod']
                elif mutation == 'binary':
                    (owned / 'artifacts/secretsbroker').write_bytes(b'mutated')
                else:
                    (root / 'go.mod').write_bytes(b'mutated source')
                (owned / 'artifacts/provenance.json').write_text(json.dumps(doc))
                with self.assertRaises(ValueError):
                    binding.inspect_inputs(root, owned)

    @patch.object(binding, 'source_identity', return_value=('a' * 40, 'b' * 40))
    def test_exact_archive_then_mutation_and_missing_entry(self, identity):
        with tempfile.TemporaryDirectory() as directory:
            root, owned, _ = self.fixture(directory)
            snapshot = binding.inspect_inputs(root, owned)
            staging = pathlib.Path(directory) / 'staging'
            staging.mkdir()
            for name in ('secretsbroker', 'secretsbroker-resolve'):
                (staging / name).write_bytes((owned / 'artifacts' / name).read_bytes())
            (staging / 'toolchain-provenance.json').write_bytes((owned / 'artifacts/provenance.json').read_bytes())
            (staging / 'service.json').write_bytes(b'{}')
            archive = pathlib.Path(directory) / 'candidate.tar.gz'
            def pack(omit=None):
                with tarfile.open(archive, 'w:gz') as payload:
                    for path in staging.iterdir():
                        if path.name != omit:
                            payload.add(path, arcname=path.name)
            pack()
            binding.verify_package(root, owned, snapshot, staging, archive)
            pack('service.json')
            with self.assertRaises(ValueError):
                binding.verify_package(root, owned, snapshot, staging, archive)
            pack()
            (staging / 'secretsbroker').write_bytes(b'stale')
            with self.assertRaises(ValueError):
                binding.verify_package(root, owned, snapshot, staging, archive)


if __name__ == '__main__':
    unittest.main()
