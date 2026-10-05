import copy,hashlib,json,os,pathlib,subprocess,tempfile,unittest

class Receipt(unittest.TestCase):
    def test_identity_and_required_gates_fail_closed(self):
        verifier=pathlib.Path(__file__).resolve().parents[2]/'scripts/verify-macos11-receipt.py'
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            names=('secretsbroker-darwin-amd64-macos11.tar.gz','secretsbroker-darwin-amd64-macos11.cdx.json','service-darwin-amd64-macos11.json','macos11-toolchain-provenance.json','macos11-go-trust-probe-amd64')
            candidate='a'*40
            for name in names: (root/name).write_text(name)
            (root/names[3]).write_text(json.dumps({'candidateSHA':candidate,'hashes':{'artifacts/secretsbroker':'b'*64,'artifacts/secretsbroker-resolve':'c'*64,'go/pkg/tool/linux_amd64/link':'d'*64}}))
            (root/names[2]).write_text(json.dumps({'artifact':{'source':{'repo':'service-lasso/lasso-secretsbroker','type':'github-release','tag':'2026.10.5-aaaaaaa'}}}))
            required=('native-host-roots-chain','native-wrong-hostname','native-current-time-positive','native-current-time-negative','native-unknown-self-signed','go-custom-root-eku-pair','native-process-local-anchor-eku-pair','independent-concurrent-chain-ownership','live-trusted-https','cli-linkage-existing-exit-contract','broker-serve-bootstrap','signed-ipc-secret-resolution','core-admin-managed-flow','stop-restart-retention','zero-owned-processes','macho-imports-minos-signing')
            receipt={'schema':1,'candidateSHA':candidate,'workflowRunID':'123','host':{'architecture':'x86_64','version':'11.7.11'},'artifactSHA256':{n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names},'binarySHA256':{'secretsbroker':'b'*64,'secretsbroker-resolve':'c'*64,'link':'d'*64},'gates':{g:True for g in required},'evidence':'private retained native evidence'}
            comment={'user':{'id':170312},'id':1,'html_url':'https://github.com/service-lasso/lasso-secretsbroker/issues/188#issuecomment-1'}
            env=dict(os.environ,GITHUB_SHA=candidate,GITHUB_RUN_ID='123',MACOS11_NATIVE_REVIEWER_ID='170312',CANDIDATE_VERSION='2026.10.5-aaaaaaa')
            variants=[('valid',{},True),('wrong-author',{'author':2},False),('wrong-sha',{'candidateSHA':'e'*40},False),('wrong-run',{'workflowRunID':'124'},False),('failed-gate',{'gate':False},False),('integer-pass',{'gate':1},False),('wrong-bytes',{'hash':True},False),('wrong-os',{'os':True},False)]
            for name,change,expected in variants:
                with self.subTest(name=name):
                    r=copy.deepcopy(receipt);c=copy.deepcopy(comment)
                    for key in ('candidateSHA','workflowRunID'):
                        if key in change:r[key]=change[key]
                    if 'author'in change:c['user']['id']=change['author']
                    if 'gate'in change:r['gates'][required[0]]=change['gate']
                    if 'hash'in change:r['artifactSHA256'][names[0]]='f'*64
                    if 'os'in change:r['host']['version']='12.0.0'
                    c['body']='BROKER188_NATIVE_RECEIPT\n'+json.dumps(r)
                    (root/'comments.json').write_text(json.dumps([[c]]))
                    result=subprocess.run([os.sys.executable,str(verifier),str(root/'comments.json'),str(root),str(root/'verified.json')],env=env,capture_output=True)
                    self.assertEqual(result.returncode==0,expected,result.stderr.decode())

if __name__=='__main__': unittest.main()
