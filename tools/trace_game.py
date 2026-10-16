#!/usr/bin/env python3
"""Optional, synthetic control-flow exercise; NOT an Atari compatibility test.

No ANTIC renderer, DMA, POKEY sound, ROM banking or disk emulation is implemented.
VBI/DLI and inputs are deliberately supplied by a deterministic test harness.
Use only to gather evidence about reached instruction addresses and SMC.
"""
import argparse,json
from pathlib import Path
from collections import Counter,defaultdict
from cpu6502 import CPU6502,decode

class TestMemory:
    def __init__(self,raw):
        self.ram=bytearray(raw);self.frame=0;self.step=0;self.nmist=0;self.rand=0xace1
        self.fire=1;self.joy=255;self.write_log=Counter();self.pc=0
    def __getitem__(self,a):
        if isinstance(a,slice):return self.ram[a]
        if a in (0xd010,0xd011):return self.fire if a==0xd010 else 1
        if 0xd000<=a<=0xd00f:return 0 # no hardware collisions in this model
        if a in (0xd012,0xd013):return 1
        if a==0xd01f:return 7
        if a==0xd300:return self.joy
        if a==0xd20a:
            self.rand=(self.rand>>1)^((-(self.rand&1))&0xb400);return self.rand&255
        if a in (0xd20e,0xd20f):return 255
        if a==0xd40b:return (self.step//30)%156
        if a==0xd40f:return self.nmist
        return self.ram[a]
    def __setitem__(self,a,v):
        if isinstance(a,slice):self.ram[a]=v;return
        if self.ram[a]!=v and 0xc80<=a<0x7300:
            self.write_log[(self.pc,a,v)]+=1
        self.ram[a]=v
        if a==0xd40f:self.nmist=0

def run(memory_file:Path,out:Path,steps:int):
    m=TestMemory(memory_file.read_bytes());cpu=CPU6502(m,0xc80)
    reached=Counter();variants=defaultdict(Counter);interrupt_depth=0;fail=None
    mainloops=0;nmis=Counter(); landmarks=[]
    # Each frame has a VBI and up to three synthetic DLI opportunities.
    period=5000;opportunities={0:0x40,1250:0x80,2500:0x80,3750:0x80}
    for step in range(steps):
        m.step=step;m.frame=step//period
        # Start a one-player game and periodically release/press fire.
        m.fire=0 if 30<=m.frame<36 or 50<=m.frame<56 or (m.frame>80 and m.frame%40<8) else 1
        m.joy=255
        phase=step%period
        if phase in opportunities and not interrupt_depth:
            flag=opportunities[phase]
            if m.ram[0xd40e]&flag:
                vector=m.ram[0xfffa]|m.ram[0xfffb]<<8
                if vector in (0x102d,0x37db):
                    m.nmist=flag;cpu.nmi();interrupt_depth+=1;nmis[f'{flag:02X}']+=1
        pc=cpu.pc;m.pc=pc
        reached[pc]+=1;i=decode(m,pc)
        if i:variants[pc][i.raw.hex()]+=1
        if pc in (0xf5f,0x1874,0x197f,0x107a,0x1a72) and reached[pc]==1:
            landmarks.append({'pc':f'{pc:04X}','step':step,'frame':m.frame})
        if pc==0x197f:mainloops+=1
        try:cpu.step()
        except (RuntimeError,IndexError) as e:fail=str(e);break
        if i and i.mnemonic=='RTI':interrupt_depth=max(0,interrupt_depth-1)
    out.mkdir(parents=True,exist_ok=True)
    j={'method':'Synthetic instruction-level test; no real ANTIC/DMA/ROM/POKEY emulation',
       'steps':cpu.steps,'end_pc':f'{cpu.pc:04X}','unique_pcs':len(reached),'game_mainloop_visits':mainloops,
       'interrupts':dict(nmis),'failure':fail,'landmarks':landmarks,
       'executed':{f'{p:04X}':v for p,v in sorted(reached.items())},
       'variants':{f'{p:04X}':dict(v) for p,v in sorted(variants.items())},
       'writes':[{'pc':f'{pc:04X}','address':f'{a:04X}','value':f'{v:02X}','count':n}
                 for (pc,a,v),n in sorted(m.write_log.items())]}
    (out/'game_synthetic_trace.json').write_text(json.dumps(j,indent=2)+'\n')
    (out/'ram_after_synthetic_test.bin').write_bytes(m.ram)
    print(json.dumps({k:v for k,v in j.items() if k not in ('executed','variants','writes')},indent=2))
    return j
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('memory',type=Path);p.add_argument('--out',type=Path,default=Path('analysis'));p.add_argument('--steps',type=int,default=1000000)
    a=p.parse_args();run(a.memory,a.out,a.steps)
