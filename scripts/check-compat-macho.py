#!/usr/bin/env python3
import json,pathlib,struct,sys
results=[]
for arg in sys.argv[1:]:
    path=pathlib.Path(arg);data=path.read_bytes()
    if struct.unpack_from('<I',data)[0]!=0xfeedfacf: raise SystemExit('Expected thin Mach-O64')
    cpu=struct.unpack_from('<I',data,4)[0];ncmd=struct.unpack_from('<I',data,16)[0]
    offset=32;minimum=None;signed=False;symbols=[]
    for _ in range(ncmd):
        command,size=struct.unpack_from('<II',data,offset)
        if command==0x32: minimum=struct.unpack_from('<III',data,offset+8)
        if command==0x1d: signed=True
        if command==2:
            symoff,count,stroff,strsize=struct.unpack_from('<IIII',data,offset+8)
            for i in range(count):
                index,kind=struct.unpack_from('<IB',data,symoff+i*16)
                if kind&0xe==0 and index:
                    end=data.index(b'\0',stroff+index)
                    symbols.append(data[stroff+index:end].decode())
        offset+=size
    expected=11<<16 if cpu==0x1000007 else 12<<16 if cpu==0x100000c else None
    if minimum!=(1,expected,expected): raise SystemExit('Unexpected compatibility deployment metadata '+str(minimum))
    if '_SecTrustCopyCertificateChain' in symbols: raise SystemExit('Unavailable chain-copy import remains')
    if any('SecTrust' in s for s in symbols):
        if not {'_SecTrustGetCertificateCount','_SecTrustGetCertificateAtIndex','_SecTrustEvaluateWithError'}.issubset(symbols): raise SystemExit('Missing legacy evaluated-chain imports')
    if cpu==0x100000c and not signed: raise SystemExit('ARM64 signature missing')
    results.append({'file':path.name,'cpu':cpu,'minOS':expected,'syntheticSDK':expected,'codeSignaturePresent':signed,'imports':symbols})
print(json.dumps(results,indent=2))
