#!/usr/bin/env python3
"""Verify an actual authorized GitHub comment, never a dispatch-supplied pass flag."""
import hashlib,json,os,pathlib,re,sys
comments_path,assets_path,output_path=map(pathlib.Path,sys.argv[1:])
candidate=os.environ['GITHUB_SHA'];run_id=str(os.environ['GITHUB_RUN_ID'])
reviewer=int(os.environ['MACOS11_NATIVE_REVIEWER_ID'])
if not re.fullmatch('[0-9a-f]{40}',candidate): raise SystemExit('Invalid candidate identity')
asset_names=('secretsbroker-darwin-amd64-macos11.tar.gz','secretsbroker-darwin-amd64-macos11.cdx.json','service-darwin-amd64-macos11.json','macos11-toolchain-provenance.json','macos11-go-trust-probe-amd64')
hashes={n:hashlib.sha256((assets_path/n).read_bytes()).hexdigest() for n in asset_names}
provenance=json.loads((assets_path/'macos11-toolchain-provenance.json').read_text())
if provenance['candidateSHA']!=candidate: raise SystemExit('Compatibility provenance candidate mismatch')
manifest=json.loads((assets_path/'service-darwin-amd64-macos11.json').read_text())
source=manifest.get('artifact',{}).get('source',{})
if source.get('repo')!='service-lasso/lasso-secretsbroker' or source.get('type')!='github-release' or source.get('tag')!=os.environ['CANDIDATE_VERSION'] or 'channel' in source:
    raise SystemExit('Compatibility manifest must pin exact candidate tag')
binary_hashes={pathlib.Path(k).name:v for k,v in provenance['hashes'].items() if pathlib.Path(k).name in ('secretsbroker','secretsbroker-resolve','link')}
required=('native-host-roots-chain','native-wrong-hostname','native-current-time-positive','native-current-time-negative','native-unknown-self-signed','go-custom-root-eku-pair','native-process-local-anchor-eku-pair','independent-concurrent-chain-ownership','live-trusted-https','cli-linkage-existing-exit-contract','broker-serve-bootstrap','signed-ipc-secret-resolution','core-admin-managed-flow','stop-restart-retention','zero-owned-processes','macho-imports-minos-signing')
pages=json.loads(comments_path.read_text());comments=[c for page in pages for c in page] if pages and isinstance(pages[0],list) else pages
for comment in reversed(comments):
    if comment.get('user',{}).get('id')!=reviewer: continue
    body=comment.get('body','').strip()
    if not body.startswith('BROKER188_NATIVE_RECEIPT\n'): continue
    try: receipt=json.loads(body.split('\n',1)[1])
    except ValueError: continue
    if receipt.get('schema')!=1 or receipt.get('candidateSHA')!=candidate or str(receipt.get('workflowRunID'))!=run_id: continue
    if receipt.get('host',{}).get('architecture')!='x86_64' or not re.fullmatch(r'11\.\d+\.\d+',receipt.get('host',{}).get('version','')): continue
    if receipt.get('artifactSHA256')!=hashes or receipt.get('binarySHA256')!=binary_hashes: continue
    gates=receipt.get('gates',{})
    if set(gates)!=set(required) or any(gates[g] is not True for g in required): continue
    if not isinstance(receipt.get('evidence'),str) or not receipt['evidence'].strip(): continue
    receipt['githubComment']={'id':comment['id'],'url':comment['html_url'],'actualAuthorID':reviewer}
    output_path.write_text(json.dumps(receipt,indent=2)+'\n');print('Exact-candidate actual macOS 11 native receipt verified');break
else: raise SystemExit('No trusted matching complete macOS 11 native receipt; publication blocked')
