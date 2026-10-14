import tls from 'node:tls';
import {X509Certificate} from 'node:crypto';
import {mkdir,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const root=path.dirname(new URL(import.meta.url).pathname);
const certdir=path.join(root,'certificates');
await mkdir(certdir,{recursive:true,mode:0o700});
// Acquisition only; native Security policy below supplies the trust decision.
const host='github.com';
const chain=await new Promise((resolve,reject)=>{
 const socket=tls.connect({host,port:443,servername:host,rejectUnauthorized:false},()=>{
  const out=[];const seen=new Set();let c=socket.getPeerCertificate(true);
  while(c?.raw){const x=new X509Certificate(c.raw);if(seen.has(x.fingerprint256))break;seen.add(x.fingerprint256);out.push({der:c.raw,x});c=c.issuerCertificate;}
  socket.end();resolve(out);
 });socket.setTimeout(15000,()=>socket.destroy(new Error('certificate capture timeout')));socket.on('error',reject);
});
const inputs=[];
for(let i=0;i<chain.length;i++){const f=path.join(certdir,`host-${i}.der`);await writeFile(f,chain[i].der,{mode:0o600});inputs.push(f);}
const leaf=chain[0].x;const validFrom=Date.parse(leaf.validFrom)/1000,validTo=Date.parse(leaf.validTo)/1000;
let expired=validTo+1;
if(!chain.slice(1).every(c=>Date.parse(c.x.validFrom)/1000<expired && Date.parse(c.x.validTo)/1000>expired))expired=validFrom-1;
if(!chain.slice(1).every(c=>Date.parse(c.x.validFrom)/1000<expired && Date.parse(c.x.validTo)/1000>expired))throw Error('no leaf-only expired point within issuer validity');
const now=Math.floor(Date.now()/1000);
const entries=[];
for(const [name,dns,date,expected] of [['host-positive',host,now,true],['host-wrong-name','wrong.example.invalid',now,false],['host-expired',host,expired,false],['host-expiry-positive-control',host,Math.min(validTo-1,Math.max(validFrom+1,expired-2)),true]]){
 const out=path.join(root,'native-results',name);await mkdir(out,{recursive:true,mode:0o700});
 const r=spawnSync(path.join(root,'apple-trust'),[dns,String(date),out,'-',...inputs],{encoding:'utf8'});
 await writeFile(out+'/result.json',r.stdout,{mode:0o600});await writeFile(out+'/stderr.log',r.stderr,{mode:0o600});
 const result=r.status===0?JSON.parse(r.stdout):{helperExit:r.status};entries.push({name,date,expected,result,pass:result.accepted===expected});
}
await writeFile(root+'/native-matrix.json',JSON.stringify({host,captureOnlyTlsVerificationDisabled:true,inputs,validFrom,validTo,issuerDates:chain.slice(1).map(c=>({from:c.x.validFrom,to:c.x.validTo})),entries},null,2),{mode:0o600});
console.log(JSON.stringify(entries.map(({name,pass,result})=>({name,pass,accepted:result.accepted,errorCode:result.errorCode,chainSha256:result.chainSha256}))));
if(entries.some(e=>!e.pass))process.exitCode=1;
