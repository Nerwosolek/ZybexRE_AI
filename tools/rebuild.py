#!/usr/bin/env python3
"""Reassemble sources, verify every byte, and rebuild the original ATR.

Runs the included MAC/65-subset verifier, NOT native MAC/65 or ATasm.
Requires only Python 3.10+ and its standard library.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
from mac65_subset import assemble, AssemblyError
from extract import EXPECTED_SHA256

ROOT=Path(__file__).resolve().parents[1]

def digest(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def read_source(path:Path)->str:return path.read_bytes().replace(b'\x9b',b'\n').decode('ascii')
def require(condition:bool,message:str)->None:
    if not condition:raise ValueError(message)

def rebuild(root:Path=ROOT)->dict:
    build=root/'build';build.mkdir(exist_ok=True)
    manifest=json.loads((root/'manifest.json').read_text())
    for name,meta in manifest['blocks'].items():
        data=(root/'extracted'/name).read_bytes()
        require(len(data)==meta['bytes'] and digest(data)==meta['sha256'],'Retained block mismatch: '+name)
    variants=[];output={}
    for module,org,block in [('BOOT',0x480,'boot_0480_10ff.bin'),('GAME',0x600,'payload_0600_bc7f.bin')]:
        reference=(root/'extracted'/block).read_bytes()
        for rel in (f'src/{module}.M65',f'src/{module}FLAT.M65',f'native/{module}.LST'):
            start,data,syms,_=assemble(read_source(root/rel))
            require(start==org and data==reference,'Source roundtrip failed: '+rel)
            variants.append({'source':rel,'origin':f'{org:04X}','bytes':len(data),'sha256':digest(data),'byte_identical':True})
        output[module]=data
        (build/f'{module}.bin').write_bytes(data)
    pieces=json.loads((root/'analysis/native_parts.json').read_text())
    joined=bytearray();part_results=[];expected=0x600
    (build/'parts').mkdir(exist_ok=True)
    for item in pieces:
        name=item['name'];raw=None
        for rel in (f'src/parts/{name}.M65',f'native/parts/{name}.LST'):
            start,data,_,_=assemble(read_source(root/rel))
            require(start==item['start']==expected,'Noncontiguous native part: '+name)
            require(data==output['GAME'][start-0x600:item['end']-0x600+1],'Native part mismatch: '+rel)
            if raw is not None:require(raw==data,'ATASCII part mismatch: '+name)
            raw=data
        joined.extend(raw);expected+=len(raw)
        (build/'parts'/f'{name}.bin').write_bytes(raw)
        part_results.append({'name':name,'bytes':len(raw),'byte_identical':True})
    require(bytes(joined)==output['GAME'],'Concatenated parts differ from the resident payload')
    header=(root/'extracted/atr_header.bin').read_bytes()
    atr=header+output['BOOT']+bytes(230*128)+output['GAME']+bytes(100*128)
    require(len(atr)==92176 and digest(atr)==EXPECTED_SHA256,'Rebuilt ATR does not match the input fingerprint')
    (build/'ZYBEX_REBUILT.ATR').write_bytes(atr)
    # Coverage is informative, not a claim of complete Atari emulation.
    trace=json.loads((root/'analysis/game_synthetic_trace.json').read_text())
    analysis=json.loads((root/'analysis/game_analysis.json').read_text())
    unseen=sorted(set(int(p,16) for p in trace['executed'])-set(analysis['code']))
    report={
        'assembler':'Included tools/mac65_subset.py; not native MAC/65, not ATasm',
        'native_toolchain_executed':False,'full_atari_emulator_executed':False,
        'variants':variants,'parts':part_results,'part_count':len(pieces),
        'rebuilt_atr_bytes':len(atr),'rebuilt_atr_sha256':digest(atr),'atr_byte_identical':True,
        'synthetic_trace_pcs_outside_static_analysis':unseen,
        'limitations':'Byte equality verifies reconstruction, not correctness of all semantic labels or complete runtime behavior.'
    }
    (build/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'OK: {len(variants)} complete source variants + {len(pieces)*2} part variants')
    print(f'OK: rebuilt ATR = {len(atr)} bytes, SHA256 {digest(atr)}')
    print('Verifier: bundled MAC/65 subset. Native MAC/65 / full Atari emulator were not run.')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT)
    a=p.parse_args()
    try:rebuild(a.root)
    except (ValueError,AssemblyError,OSError,KeyError) as e:
        print(f'ERROR: {e}',file=sys.stderr);sys.exit(1)
