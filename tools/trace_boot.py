#!/usr/bin/env python3
"""Execute this ATR's loader with an explicitly mocked DSKINV and OS clock."""
import argparse,json,hashlib
from pathlib import Path
from cpu6502 import CPU6502,decode

def trace(image:Path,out:Path):
    b=image.read_bytes()
    if b[:2]!=b'\x96\x02' or int.from_bytes(b[4:6],'little')!=128:
        raise ValueError('Expected an ATR with 128-byte sectors')
    disk=b[16:]; count=disk[1];start=int.from_bytes(disk[2:4],'little');entry=int.from_bytes(disk[4:6],'little')
    m=bytearray(65536);m[start:start+count*128]=disk[:count*128]
    m[0xd301]=255;m[0x301]=1;m[0x302]=0x52
    c=CPU6502(m,entry); reads=[];code={}; recent=[]
    for _ in range(300000):
        if c.pc==0xc80:break
        if c.pc==0xe453:
            sec=m[0x30a]|m[0x30b]<<8;dst=m[0x304]|m[0x305]<<8
            assert m[0x302]==0x52 and 1<=sec<=len(disk)//128
            m[dst:dst+128]=disk[(sec-1)*128:sec*128]
            m[0x303]=1;c.y=1;c.flag(128,False);c.flag(2,False)
            reads.append({'sector':sec,'destination':f'{dst:04X}','file_offset':16+(sec-1)*128})
            c.rts();continue
        i=decode(m,c.pc);code[c.pc]=i.raw.hex() if i else ''
        recent.append(c.pc);recent=recent[-30:]
        c.step()
        if c.steps%200==0 and m[0xd301]&1:
            m[0x14]=(m[0x14]+1)&255
    else:raise RuntimeError(f'Loader did not finish. pc={c.pc:04X} recent={recent}')
    assert [x['sector'] for x in reads]==list(range(256,621))
    assert m[0x600:0xbc80]==disk[255*128:620*128]
    for s,d,n in [(0x700,0xe400,0x500),(0xc00,0xff00,0x100),(0xd00,0xdc00,0x400)]:
        assert m[d:d+n]==disk[s-start:s-start+n]
    out.mkdir(parents=True,exist_ok=True)
    (out/'ram_after_boot.bin').write_bytes(m)
    report={'method':'Instruction-level 6502, DSKINV mocked, OS clock synthetic; not a hardware emulation',
      'image_sha256':hashlib.sha256(b).hexdigest(),'entry':f'{entry:04X}','exit_pc':f'{c.pc:04X}',
      'instructions_executed':c.steps,'unique_instruction_addresses':len(code),'code':{f'{k:04X}':v for k,v in sorted(code.items())},
      'reads':reads,'payload_matches_disk':True,'resource_copies_match_disk':True,
      'copies':[{'from':f'{s:04X}','to':f'{d:04X}','length':n} for s,d,n in [(0x700,0xe400,0x500),(0xc00,0xff00,0x100),(0xd00,0xdc00,0x400)]]}
    (out/'boot_trace.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('code','reads')},indent=2))
    return m,report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('image',type=Path);p.add_argument('--out',type=Path,default=Path('analysis'))
    a=p.parse_args();trace(a.image,a.out)
