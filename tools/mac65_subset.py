#!/usr/bin/env python3
"""Assembler/verifier for the MAC/65 subset emitted by this project.

Supports official NMOS 6502, labels/equates, *=, .BYTE/.WORD/.END,
.MACRO/.ENDM, numeric macro parameters, macro-local labels, and integer
expressions. It is NOT the original MAC/65 and not a complete replacement.
Used to catch missing bytes, moved addresses, branch errors and bad operands.
"""
from __future__ import annotations
import argparse,re,json
from pathlib import Path
from dataclasses import dataclass
from cpu6502 import ENCODE,SIZES

MNEMONICS={x[0] for x in ENCODE}
DIRECTIVES={'.BYTE','.WORD','.END','.OPT'}
BRANCHES={'BCC','BCS','BEQ','BMI','BNE','BPL','BVC','BVS'}
TOKEN=re.compile(r'\s*(\$[0-9A-Fa-f]+|[0-9]+|[A-Za-z?@][A-Za-z0-9?@]*|[+\-*/<>\[\]&!^])')

class AssemblyError(ValueError): pass

class Expr:
    def __init__(self,s:str,symbols:dict[str,int],pc:int,unknown:bool=False):
        self.tokens=[];p=0
        while p<len(s):
            if not s[p:].strip():break
            m=TOKEN.match(s,p)
            if not m:raise AssemblyError('Invalid expression: '+s)
            self.tokens.append(m.group(1).upper());p=m.end()
        self.pos=0;self.syms=symbols;self.pc=pc;self.unknown=unknown
    def atom(self):
        if self.pos>=len(self.tokens):raise AssemblyError('Incomplete expression')
        t=self.tokens[self.pos];self.pos+=1
        if t in ('+','-','<','>'):
            v=self.atom()
            return v if t=='+' else -v if t=='-' else v&255 if t=='<' else (v>>8)&255
        if t=='[':
            v=self.expr(0)
            if self.pos>=len(self.tokens) or self.tokens[self.pos]!=']':raise AssemblyError('Missing ]')
            self.pos+=1;return v
        if t=='*':return self.pc
        if t.startswith('$'):return int(t[1:],16)
        if t.isdigit():return int(t)
        if t in self.syms:return self.syms[t]
        if self.unknown:return 0x1000
        raise AssemblyError('Undefined symbol: '+t)
    def expr(self,minimum):
        v=self.atom();prec={'!':1,'^':1,'&':1,'+':2,'-':2,'*':3,'/':3}
        while self.pos<len(self.tokens) and self.tokens[self.pos] in prec and prec[self.tokens[self.pos]]>=minimum:
            op=self.tokens[self.pos];self.pos+=1;rhs=self.expr(prec[op]+1)
            if op=='+':v+=rhs
            elif op=='-':v-=rhs
            elif op=='*':v*=rhs
            elif op=='/':v//=rhs
            elif op=='&':v&=rhs
            elif op=='!':v|=rhs
            else:v^=rhs
        return v
    def value(self):
        v=self.expr(0)
        if self.pos!=len(self.tokens):raise AssemblyError('Trailing expression tokens')
        return v&65535

def evaluate(s,symbols,pc,unknown=False):return Expr(s,symbols,pc,unknown).value()

def split_args(s):
    result=[];start=0;depth=0
    for i,c in enumerate(s):
        if c in '[(':depth+=1
        elif c in '])':depth-=1
        elif c==',' and depth==0:result.append(s[start:i].strip());start=i+1
    if s[start:].strip():result.append(s[start:].strip())
    return result

def clean(line):
    line=re.sub(r'^\s*\d+\s+','',line)
    return line.split(';',1)[0].strip()

def fields(line,macros=()):
    t=line.split(None,1)
    if not t:return '', '', ''
    if t[0].upper() in MNEMONICS|DIRECTIVES|set(macros):return '',t[0].upper(),t[1].strip() if len(t)>1 else ''
    label=t[0].upper()
    if len(t)==1:return label,'',''
    t2=t[1].split(None,1)
    return label,t2[0].upper(),t2[1].strip() if len(t2)>1 else ''

@dataclass
class SourceLine:
    text:str
    original:int

def expand(text):
    lines=[SourceLine(clean(x),n) for n,x in enumerate(text.splitlines(),1)]
    macros={};flat=[];i=0;invocation=0
    while i<len(lines):
        line=lines[i];s=line.text;i+=1
        if not s:continue
        if s.upper().startswith('.MACRO '):
            name=s.split()[1].upper();body=[]
            while i<len(lines) and lines[i].text.upper()!='.ENDM':body.append(lines[i]);i+=1
            if i==len(lines):raise AssemblyError('Unclosed macro '+name)
            i+=1;macros[name]=body;continue
        if s.upper()=='.ENDM':raise AssemblyError('Unmatched .ENDM')
        label,op,args=fields(s,macros)
        if op not in macros:flat.append(line);continue
        invocation+=1;params=split_args(args)
        if label:flat.append(SourceLine(label,line.original))
        local={}
        for b in macros[op]:
            lab,_,_=fields(b.text)
            if lab:local[lab]=f'Q{invocation:04X}{lab.lstrip("?@")} '
        for b in macros[op]:
            ss=b.text
            def replace_param(m):
                n=int(m.group(1))
                if not 1<=n<=len(params):raise AssemblyError('Missing macro parameter')
                return '['+params[n-1]+']'
            ss=re.sub(r'%(\d+)',replace_param,ss)
            for old,new in local.items():
                ss=re.sub(r'(?<![A-Za-z0-9?@])'+re.escape(old)+r'(?![A-Za-z0-9?@])',new.strip(),ss,flags=re.I)
            if ss:flat.append(SourceLine(ss,line.original))
    return flat

def select_mode(mn,operand,syms,pc,unknown):
    s=operand.strip()
    if mn in BRANCHES:return 'rel',evaluate(s,syms,pc,unknown)
    if not s:return 'imp',None
    if s.upper()=='A':return 'acc',None
    if s.startswith('#'):return 'imm',evaluate(s[1:],syms,pc,unknown)
    u=s.upper().replace(' ','')
    if u.startswith('('):
        if u.endswith(',X)'):return 'inx',evaluate(s[s.find('(')+1:s.upper().rfind(',X')],syms,pc,unknown)
        if u.endswith('),Y'):return 'iny',evaluate(s[s.find('(')+1:s.rfind(')')],syms,pc,unknown)
        if u.endswith(')'):return 'ind',evaluate(s[1:s.rfind(')')],syms,pc,unknown)
        raise AssemblyError('Invalid indirect operand '+s)
    index=None
    if u.endswith(',X') or u.endswith(',Y'):
        index=u[-1];s=s[:s.rfind(',')]
    v=evaluate(s,syms,pc,unknown)
    small='zp' if index is None else 'zpx' if index=='X' else 'zpy'
    large='abs' if index is None else 'abx' if index=='X' else 'aby'
    return (small if v<256 and (mn,small) in ENCODE else large),v

def assemble(text:str):
    source=expand(text);symbols={};last=None
    for iteration in range(8):
        pc=0;new=dict(symbols);defined=set();memory={};listing=[]
        strict=iteration>0
        for ln in source:
            s=ln.text
            try:
                if re.match(r'^\*\s*=',s):pc=evaluate(s.split('=',1)[1],new,pc,not strict);continue
                equ=re.match(r'^([A-Za-z?@][A-Za-z0-9?@]*)\s*=\s*(.*)$',s)
                if equ:
                    name=equ.group(1).upper()
                    if name in defined:raise AssemblyError('Duplicate symbol '+name)
                    new[name]=evaluate(equ.group(2),new,pc,not strict);defined.add(name);continue
                label,op,arg=fields(s)
                if label:
                    if label in defined:raise AssemblyError('Duplicate symbol '+label)
                    new[label]=pc;defined.add(label)
                if not op:continue
                if op=='.END':break
                if op=='.OPT':continue
                if op in ('.BYTE','.WORD'):
                    vals=[evaluate(x,new,pc,not strict) for x in split_args(arg)]
                    if op=='.BYTE':
                        if strict and any(x>255 for x in vals):raise AssemblyError('.BYTE overflow')
                        raw=bytes(x&255 for x in vals)
                    else:raw=b''.join(int(x).to_bytes(2,'little') for x in vals)
                else:
                    mode,v=select_mode(op,arg,new,pc,not strict)
                    if (op,mode) not in ENCODE:raise AssemblyError(f'Unsupported instruction {op} {arg} ({mode})')
                    opcode=ENCODE[op,mode];n=SIZES[mode]
                    if mode=='rel':
                        delta=(v-(pc+2)+32768)%65536-32768
                        if strict and not -128<=delta<=127:raise AssemblyError(f'Branch out of range: {delta}')
                        raw=bytes([opcode,delta&255])
                    elif n==1:raw=bytes([opcode])
                    elif n==2:
                        if strict and v>255:raise AssemblyError('8-bit operand overflow')
                        raw=bytes([opcode,v&255])
                    else:raw=bytes([opcode,v&255,(v>>8)&255])
                for k,b in enumerate(raw):
                    addr=pc+k
                    if addr in memory:raise AssemblyError(f'Overlapping output ${addr:04X}')
                    if addr>65535:raise AssemblyError('Address overflow')
                    memory[addr]=b
                listing.append((pc,raw,ln.original,s));pc+=len(raw)
            except (AssemblyError,ValueError,ZeroDivisionError) as e:
                raise AssemblyError(f'Line {ln.original}: {s}: {e}') from e
        signature=(tuple(sorted(new.items())),tuple(memory.items()))
        if strict and signature==last:
            if not memory:raise AssemblyError('No output')
            start=min(memory);end=max(memory)+1
            if len(memory)!=end-start:raise AssemblyError('Output contains holes')
            return start,bytes(memory[a] for a in range(start,end)),new,listing
        last=signature;symbols=new
    raise AssemblyError('Assembly did not converge')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('-o','--output',type=Path,required=True)
    a=p.parse_args();raw=a.source.read_bytes();text=raw.replace(b'\x9b',b'\n').decode('ascii')
    start,b,syms,listing=assemble(text);a.output.write_bytes(b)
    print(f'{a.source.name}: ${start:04X}-${start+len(b)-1:04X}, {len(b)} bytes, {len(syms)} symbols')
