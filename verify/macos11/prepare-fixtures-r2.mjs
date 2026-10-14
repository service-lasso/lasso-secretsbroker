import {mkdir,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const root=path.dirname(new URL(import.meta.url).pathname),dir=root+'/certificates-r2';
await mkdir(dir,{recursive:true,mode:0o700});
const run=(args)=>{const r=spawnSync('/usr/bin/openssl',args,{cwd:dir,encoding:'utf8'});if(r.status!==0)throw Error('openssl fixture preparation failed: '+r.stderr);};
run(['req','-sha256','-x509','-newkey','rsa:2048','-nodes','-keyout','unknown.key','-out','unknown.pem','-days','10','-subj','/CN=unknown.example.invalid']);
run(['req','-sha256','-x509','-newkey','rsa:2048','-nodes','-keyout','anchor.key','-out','anchor.pem','-days','30','-subj','/CN=Independent process local test anchor']);
for(const name of ['unknown','anchor'])run(['x509','-in',name+'.pem','-outform','DER','-out',name+'.der']);
for(const [name,eku] of [['server','serverAuth'],['client','clientAuth']]){
 await writeFile(dir+'/'+name+'.ext',`basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=${eku}\nsubjectAltName=DNS:eku.example.invalid\n`,{mode:0o600});
 run(['req','-sha256','-new','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN=eku.example.invalid']);
 run(['x509','-sha256','-req','-in',name+'.csr','-CA','anchor.pem','-CAkey','anchor.key','-set_serial',name==='server'?'10':'11','-days','10','-extfile',name+'.ext','-out',name+'.pem']);
 run(['x509','-in',name+'.pem','-outform','DER','-out',name+'.der']);
}
const entries=[];const date=String(Math.floor(Date.now()/1000));
for(const [name,host,anchor,cert,expected] of [['unknown-host-roots','unknown.example.invalid','-','unknown',false],['native-eku-server','eku.example.invalid',dir+'/anchor.der','server',true],['native-eku-client','eku.example.invalid',dir+'/anchor.der','client',false]]){
 const out=root+'/native-results/r2-'+name;await mkdir(out,{recursive:true,mode:0o700});
 const r=spawnSync(root+'/apple-trust',[host,date,out,anchor,dir+'/'+cert+'.der'],{encoding:'utf8'});
 await writeFile(out+'/result.json',r.stdout,{mode:0o600});await writeFile(out+'/stderr.log',r.stderr,{mode:0o600});
 const result=r.status===0?JSON.parse(r.stdout):{helperExit:r.status};entries.push({name,host,date,anchor,cert,expected,result,pass:result.accepted===expected});
}
await writeFile(root+'/native-fixture-matrix-r2.json',JSON.stringify(entries,null,2),{mode:0o600});console.log(JSON.stringify(entries.map(e=>({name:e.name,pass:e.pass,accepted:e.result.accepted,errorCode:e.result.errorCode}))));
if(entries.some(e=>!e.pass))process.exitCode=1;

