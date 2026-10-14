import {readFile,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const probes=process.argv.slice(2);
if(probes.length===0)throw Error('At least one trust probe is required');
const root=path.dirname(new URL(import.meta.url).pathname);
const observations=[];
async function observe(probe,args,selection){
 const started=new Date().toISOString();
 const result=spawnSync(probe,args,{encoding:'utf8'});
 observations.push({probe,args,selection,started,completed:new Date().toISOString(),pid:result.pid,status:result.status,signal:result.signal,error:result.error?.message,stdout:result.stdout,stderr:result.stderr});
 await writeFile(root+'/probe-observations.json',JSON.stringify(observations,null,2));
 return result;
}
const host=JSON.parse(await readFile(root+'/native-matrix.json','utf8'));
const fixtures=JSON.parse(await readFile(root+'/native-fixture-matrix-r2.json','utf8'));
const rows=host.entries.map(e=>({...e,dns:e.name==='host-wrong-name'?'wrong.example.invalid':host.host,roots:'-',certs:host.inputs,kind:'native-host-roots'}));
for(const e of fixtures){
 const cert=root+'/certificates-r2/'+e.cert+'.der';
 if(e.anchor==='-') rows.push({...e,dns:e.host,roots:'-',certs:[cert],kind:'native-host-roots'});
 else rows.push({...e,dns:e.host,roots:e.anchor,certs:[cert],kind:'custom-root-go-policy'});
}
const results=[];
for(const row of rows){
 const outputs=[];
 for(const probe of probes){
  const p=await observe(probe,[row.dns,String(row.date),row.roots,...row.certs],row.name);
  if(p.status!==0)throw Error('Go probe failed '+row.name+': '+p.stderr);
  const result=JSON.parse(p.stdout);
  if(result.accepted!==row.expected || !result.repeatedConcurrentStable || result.calls!==101)throw Error('Unexpected Go trust decision '+row.name);
  if(row.kind==='native-host-roots' && row.expected && JSON.stringify(result.chainSha256[0])!==JSON.stringify(row.result.chainSha256))throw Error('Native chain mismatch '+row.name);
  outputs.push(result);
 }
 if(outputs.some(r=>JSON.stringify(r)!==JSON.stringify(outputs[0])))throw Error('Official/custom decision mismatch '+row.name);
 results.push({name:row.name,kind:row.kind,expected:row.expected,results:outputs,pass:true});
}
for(const probe of probes){
 const p=await observe(probe,['https'],'live-https');
 if(p.status!==0 || !JSON.parse(p.stdout).liveTrustedHttps)throw Error('Trusted live HTTPS failed');
}
await writeFile(root+'/comparison.json',JSON.stringify(results,null,2));
console.log(JSON.stringify({rows:results.length,pass:true,independentCallsPerRowPerVariant:101}));
