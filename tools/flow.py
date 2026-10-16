"""Conservative direct control-flow traversal plus vector-store discovery."""
from collections import deque
from cpu6502 import decode

def analyze(memory,start,end,seeds,discover_vectors=True,phase_exits=(),nonreturning=()):
    phase_exits=set(phase_exits);nonreturning=set(nonreturning)
    code={};owners={};issues=set();edges=set();seedset=set(seeds);vector_writes=set()
    def walk(entries):
        q=deque(sorted(entries))
        while q:
            p=q.popleft()
            if p in phase_exits or p in code or not start<=p<end:continue
            if p in owners and owners[p]!=p:
                issues.add(('overlap_start',p,owners[p]));continue
            i=decode(memory,p)
            if i is None:issues.add(('illegal',p,memory[p]));continue
            if p+i.size>end or any(a in owners and owners[a]!=p for a in range(p,p+i.size)):
                issues.add(('overlap_insn',p));continue
            if i.mnemonic=='BRK':issues.add(('brk',p));continue
            code[p]=i
            for a in range(p,p+i.size):owners[a]=p
            if i.target is not None:q.append(i.target);edges.add((p,i.target,i.mnemonic))
            if i.mnemonic=='JMP':
                if i.mode=='ind':issues.add(('indirect',p,i.operand))
            elif i.mnemonic not in ('RTS','RTI') and not (i.mnemonic=='JSR' and i.target in nonreturning):q.append(i.next)
    walk(seedset)
    if discover_vectors:
        for _ in range(12):
            new=set()
            for entry in sorted(code):
                vals={'A':None,'X':None,'Y':None};v={};p=entry
                for _ in range(24):
                    if p not in code:break
                    i=code[p];mn=i.mnemonic;md=i.mode
                    if mn in ('LDA','LDX','LDY'):vals[mn[2]]=i.operand if md=='imm' else None
                    elif mn in ('TAX','TAY','TXA','TYA'):vals[mn[2]]=vals[mn[1]]
                    elif mn in ('STA','STX','STY') and md in ('abs','zp') and vals[mn[2]] is not None:
                        a=i.operand
                        if a in (0x200,0x201,0xfffa,0xfffb,0xfffe,0xffff):
                            v[a]=vals[mn[2]]
                            for base in (0x200,0xfffa,0xfffe):
                                if base in v and base+1 in v:
                                    addr=v[base]|v[base+1]<<8
                                    vector_writes.add((p,base,addr))
                                    if addr not in seedset and start<=addr<end:new.add(addr)
                    elif mn in ('ADC','SBC','AND','ORA','EOR','PLA','ASL','LSR','ROL','ROR'):vals['A']=None
                    elif mn in ('INX','DEX','TSX'):vals['X']=None
                    elif mn in ('INY','DEY'):vals['Y']=None
                    if mn in ('JSR','JMP','RTS','RTI') or md=='rel':break
                    p=i.next
            if not new:break
            seedset.update(new);walk(new)
    smc=[]
    for p,i in sorted(code.items()):
        if i.mnemonic in ('STA','STX','STY','INC','DEC','ASL','LSR','ROL','ROR') and i.mode=='abs' and i.operand in owners:
            smc.append((p,i.operand,owners[i.operand]))
    return {'code':code,'owners':owners,'edges':sorted(edges),'issues':sorted(issues),
            'seeds':sorted(seedset),'smc':smc,'vectors':sorted(vector_writes)}
