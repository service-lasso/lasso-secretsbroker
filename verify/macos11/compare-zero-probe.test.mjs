import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

test('native trust comparison refuses zero probes before reading fixtures',()=>{
 const script=fileURLToPath(new URL('./compare.mjs',import.meta.url));
 const result=spawnSync(process.execPath,[script],{encoding:'utf8',timeout:5000});
 assert.ifError(result.error);
 assert.notEqual(result.status,0);
 assert.equal(result.stdout,'');
 assert.match(result.stderr,/At least one trust probe is required/);
});
