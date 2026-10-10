#!/usr/bin/env python3
"""Bind an owned compatibility build to its source, then verify packaged bytes."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Expected a regular input: {path}')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity(root):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Packaging requires a clean immutable source checkout')
    return git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')


def inspect_inputs(root, owned):
    provenance = owned / 'artifacts/provenance.json'
    provenance_hash = digest(provenance)
    doc = json.loads(provenance.read_text())
    head, tree = source_identity(root)
    if (doc.get('candidateSHA'), doc.get('sourceTree')) != (head, tree):
        raise ValueError('Compatibility build does not match current source commit/tree')
    expected = doc['hashes']
    required = ['go.mod', 'go.sum', 'toolchains/macos11/go1.26.8.patch']
    required += [str(owned / 'artifacts' / name)
                 for name in ('secretsbroker', 'secretsbroker-resolve')]
    if any(name not in expected for name in required):
        raise ValueError('Compatibility provenance lacks required input hashes')
    for name, value in expected.items():
        path = pathlib.Path(name)
        if not path.is_absolute():
            path = root / path
        if digest(path) != value:
            raise ValueError(f'Compatibility build input changed: {name}')
    return {'candidateSHA': head, 'sourceTree': tree,
            'provenanceSHA256': provenance_hash,
            'binaries': {name: digest(owned / 'artifacts' / name)
                         for name in ('secretsbroker', 'secretsbroker-resolve')}}


def verify_package(root, owned, snapshot, staging, archive):
    if inspect_inputs(root, owned) != snapshot:
        raise ValueError('Compatibility inputs changed during packaging')
    expected = {**snapshot['binaries'],
                'toolchain-provenance.json': snapshot['provenanceSHA256']}
    files = {}
    for path in staging.rglob('*'):
        if path.is_symlink():
            raise ValueError('Redirected staging input')
        if path.is_file():
            files[path.relative_to(staging).as_posix()] = digest(path)
    if any(files.get(name) != value for name, value in expected.items()):
        raise ValueError('Staged binaries/provenance do not match the owned build')
    with tarfile.open(archive, 'r:gz') as payload:
        actual = {}
        for member in payload:
            if member.isdir():
                continue
            if not member.isfile() or member.name in actual:
                raise ValueError('Unsupported or duplicate archive entry')
            actual[member.name] = hashlib.sha256(payload.extractfile(member).read()).hexdigest()
        if actual != files:
            raise ValueError('Archive bytes do not match the verified staging inventory')


if __name__ == '__main__':
    mode, root_arg, owned_arg, *rest = sys.argv[1:]
    root, owned = pathlib.Path(root_arg).resolve(), pathlib.Path(owned_arg).resolve()
    if mode == 'inputs' and not rest:
        print(json.dumps(inspect_inputs(root, owned), sort_keys=True))
    elif mode == 'archive' and len(rest) == 3:
        snapshot, staging, archive = rest
        verify_package(root, owned, json.loads(snapshot), pathlib.Path(staging), pathlib.Path(archive))
    else:
        raise SystemExit('Usage: inputs ROOT OWNED | archive ROOT OWNED SNAPSHOT STAGING ARCHIVE')
