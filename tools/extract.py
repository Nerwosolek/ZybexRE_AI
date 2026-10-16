#!/usr/bin/env python3
"""Extract and validate this exact Zybex ATR edition; standard library only."""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path

EXPECTED_SHA256 = '97f1aa6d09bbf6b772d8ce174a92f8b7870cfbd9efa148655af0b5557744fffe'
ROOT = Path(__file__).resolve().parents[1]

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def extract(image: Path, root: Path = ROOT) -> dict:
    data=image.read_bytes()
    if sha256(data)!=EXPECTED_SHA256:
        raise ValueError('This reconstruction is specific to the uploaded Zybex (v1).atr; SHA256 mismatch')
    if len(data)!=92176 or struct.unpack_from('<H',data)[0]!=0x0296:
        raise ValueError('Unexpected ATR header or length')
    if struct.unpack_from('<H',data,4)[0]!=128:
        raise ValueError('Expected 128-byte sectors')
    boot=data[16:16+25*128]
    payload=data[16+255*128:16+620*128]
    if any(data[16+25*128:16+255*128]) or any(data[16+620*128:]):
        raise ValueError('Expected zero-filled gaps')
    dst=root/'extracted';dst.mkdir(parents=True,exist_ok=True)
    blocks={
        'atr_header.bin':data[:16],
        'boot_0480_10ff.bin':boot,
        'payload_0600_bc7f.bin':payload,
        'resource_e400_e8ff.bin':boot[0x700-0x480:0xc00-0x480],
        'resource_ff00_ffff.bin':boot[0xc00-0x480:0xd00-0x480],
        'resource_dc00_dfff.bin':boot[0xd00-0x480:0x1100-0x480],
    }
    for name,raw in blocks.items(): (dst/name).write_bytes(raw)
    manifest={
        'image_name':image.name,'image_bytes':len(data),'image_sha256':sha256(data),
        'atr_header_hex':data[:16].hex(),'sector_count':720,'sector_size':128,
        'boot':{'sectors':[1,25],'cpu_range':['0480','10FF'],'atr_offset':16,'entry':'0488'},
        'payload':{'sectors':[256,620],'cpu_range':['0600','BC7F'],'atr_offset':16+255*128,'entry':'0C80'},
        'zero_sector_ranges':[[26,255],[621,720]],
        'blocks':{name:{'bytes':len(raw),'sha256':sha256(raw)} for name,raw in blocks.items()},
        'resource_copies':[
            {'source':'0700-0BFF','destination':'E400-E8FF','bytes':1280},
            {'source':'0C00-0CFF','destination':'FF00-FFFF','bytes':256},
            {'source':'0D00-10FF','destination':'DC00-DFFF','bytes':1024}],
        'notes':'Addresses refer to different loading phases. No relocation or decompression of main payload.'
    }
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('image',type=Path);p.add_argument('--root',type=Path,default=ROOT)
    a=p.parse_args();print(json.dumps(extract(a.image,a.root),indent=2))
