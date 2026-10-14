#!/usr/bin/env python3
"""Generate only the explicit Core-managed authenticated native IPC profile."""
import copy
import json
import pathlib
import re
import sys


def compatibility_profile(original, tag, candidate):
    if not re.fullmatch(r'[0-9a-f]{40}', candidate) or not re.fullmatch(
            r'\d{4}\.\d{1,2}\.\d{1,2}-' + re.escape(candidate[:7]), tag):
        raise ValueError('Compatibility manifest tag must bind exact candidate SHA')
    doc = copy.deepcopy(original)
    doc['artifact']['platforms']['darwin']['assetName'] = 'secretsbroker-darwin-amd64-macos11.tar.gz'
    doc['artifact']['source'].pop('channel', None)
    doc['artifact']['source']['tag'] = tag
    doc['description'] += (' Explicit custom maintained-Go 1.26.8 compatibility profile; '
                           'select only on Intel macOS 11. Core-managed authenticated native IPC; '
                           'select the default manifest for ARM64.')
    environment = doc['execconfig']['env']
    environment.pop('SECRETSBROKER_LISTEN', None)
    environment['SECRETSBROKER_MODE'] = 'production'
    environment['SECRETSBROKER_TRANSPORT'] = 'auto'
    doc.pop('endpoints', None)
    doc.pop('healthcheck', None)
    # Core independently probes authenticated IPC after this process-start gate.
    doc['healthchecks'] = [{'id': 'secretsbroker-process-health', 'type': 'process',
                            'required': True, 'retries': 80, 'interval': 250}]
    return doc


if __name__ == '__main__':
    source, archive_manifest, public_manifest, tag, provenance = sys.argv[1:]
    candidate = json.loads(pathlib.Path(provenance).read_text())['candidateSHA']
    doc = compatibility_profile(json.loads(pathlib.Path(source).read_text()), tag, candidate)
    payload = json.dumps(doc, indent=2) + '\n'
    for destination in (archive_manifest, public_manifest):
        pathlib.Path(destination).write_text(payload, encoding='utf-8')
