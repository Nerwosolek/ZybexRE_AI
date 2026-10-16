#!/usr/bin/env python3
"""Recreate the reviewed MAC/65 sources from the retained binary blocks."""
from __future__ import annotations
import argparse,json,re,csv
from pathlib import Path
from collections import Counter,defaultdict
from cpu6502 import decode,operand_text,linear
from flow import analyze
from annotations import *
from mac65_subset import assemble

MACROS={
'PUSHREGS':'''        PHA
        TXA
        PHA
        TYA
        PHA''',
'POPREGS':'''        PLA
        TAY
        PLA
        TAX
        PLA''',
'SETPTRXY':'''        LDX #>%2
        LDY #<%2
        STX %1+1
        STY %1''',
'SETWORD':'''        LDA #<%2
        STA %1
        LDA #>%2
        STA %1+1''',
'COPYWORD':'''        LDA %2
        STA %1
        LDA %2+1
        STA %1+1''',
'WAITCLOCK':'''        LDA %1
        CLC
        ADC #%2
?WAIT
        CMP %1
        BNE ?WAIT''',
'SFXSTEP':'''        LDA %1+5
        BNE ?ACTIVE
        LDA #$00
        STA %3+1
        STA %1+10
        RTS
?ACTIVE
        DEC %1+5
        LDA %1+6
        BEQ ?FREQ
        LDY %1
        LDA (%2),Y
        CMP #$FF
        BNE ?ENVNEW
        LDA #$00
        STA %1+6
        JMP ?FREQ
?ENVNEW
        STA %1+7
        ORA %1+9
        STA %1+1
        INC %1
?FREQ
        LDA %1+2
        STA %1+8
        LSR %1+8
        BCC ?DOWN
        LDA %1+4
        CLC
        ADC %1+3
        STA %1+4
?DOWN
        LSR %1+8
        BCC ?OUTPUT
        LDA %1+4
        SEC
        SBC %1+3
        STA %1+4
?OUTPUT
        LDA %1+1
        STA %3+1
        LDA %1+4
        STA %3
        RTS''',
}
MACRO_HELP={
'PUSHREGS':'Zachowuje A, X, Y na stosie, dokladnie jak oryginalne 5 instrukcji.',
'POPREGS':'Odtwarza Y, X, A; nie zawiera RTI ani RTS.',
'SETPTRXY':'%1=wskaznik, %2=adres. Laduje X=high/Y=low, zapis high potem low.',
'SETWORD':'%1=komorka slowa, %2=wartosc. Zapis przez A: low potem high.',
'COPYWORD':'%1=cel, %2=zrodlo. Kopia low/high przez A.',
'WAITCLOCK':'%1=licznik, %2=delta. Czeka na dokladna rownosc modulo 256.',
'SFXSTEP':'%1=stan glosu, %2=wskaznik ZP obwiedni, %3=rejestr AUDF. 100 bajtow.',
}
WRITES={'STA','STX','STY','INC','DEC','ASL','LSR','ROL','ROR'}
MEMMODES={'zp','zpx','zpy','abs','abx','aby','inx','iny','ind'}
IMM_OVERRIDE={0x1012:'#>MENUNMI',0x1017:'#<MENUNMI',0x101c:'#>MENUEMPTYIRQ',
              0x1021:'#<MENUEMPTYIRQ',0x37b2:'#>GAMENMI',0x37b4:'#<GAMENMI',
              0x37bc:'#>GAMEEMPTYIRQ',0x37be:'#<GAMEEMPTYIRQ'}

def macro_definition(name):
    return '\n'.join(['; '+MACRO_HELP[name],'        .MACRO '+name,MACROS[name],'        .ENDM'])

def can_fit_macro(code,p,count):
    out=[]
    for _ in range(count):
        if p not in code:return []
        i=code[p];out.append(i);p=i.next
    return out

def candidates(code,p,module):
    if module=='game' and p in (0x3f2e,0x40b0):
        yield 'SFXSTEP',([0x4003,0xfe,0xd204] if p==0x3f2e else [0x4185,0xfc,0xd202]),100
    five=can_fit_macro(code,p,5)
    if len(five)==5:
        m=[i.mnemonic for i in five]
        if m==['PHA','TXA','PHA','TYA','PHA']:yield 'PUSHREGS',[],5
        if m==['PLA','TAY','PLA','TAX','PLA']:yield 'POPREGS',[],5
        a,b,c,d,e=five
        if m==['LDA','CLC','ADC','CMP','BNE'] and a.mode in ('zp','abs') and c.mode=='imm' and d.mode==a.mode and d.operand==a.operand and e.target==d.addr:
            yield 'WAITCLOCK',[a.operand,c.operand],e.next-p
    four=can_fit_macro(code,p,4)
    if len(four)==4:
        a,b,c,d=four;m=[i.mnemonic for i in four]
        if m==['LDX','LDY','STX','STY'] and a.mode==b.mode=='imm' and c.mode in ('zp','abs') and d.mode in ('zp','abs') and c.operand==d.operand+1:
            yield 'SETPTRXY',[d.operand,(a.operand<<8)|b.operand],d.next-p
        if m==['LDA','STA','LDA','STA'] and b.mode in ('zp','abs') and d.mode in ('zp','abs') and d.operand==b.operand+1:
            if a.mode==c.mode=='imm':yield 'SETWORD',[b.operand,a.operand|(c.operand<<8)],d.next-p
            elif a.mode in ('zp','abs') and c.mode in ('zp','abs') and c.operand==a.operand+1:yield 'COPYWORD',[b.operand,a.operand],d.next-p

def build_module(root,module,start,end,raw,seeds):
    mem=bytearray(65536);mem[start:end]=raw
    flow=analyze(mem,start,end,seeds,discover_vectors=(module=='game'),
                 phase_exits=({0x0c80} if module=='boot' else ()),
                 nonreturning=({0xe477} if module=='boot' else ()));code=flow['code'];owners=flow['owners']
    codeman=GAME_CODE if module=='game' else BOOT_CODE
    dataman=GAME_DATA if module=='game' else BOOT_DATA
    ramman={**GAME_ZP,**GAME_RAM} if module=='game' else BOOT_RAM
    if module=='game':
        ramman.pop(0x95,None);ramman.pop(0x9b,None)
    comments=COMMENTS[module]
    labels={a:n for a,n in codeman.items() if a in code}
    # A manual data label must never split a decoded instruction.
    for a,n in dataman.items():
        if start<=a<end:
            if a in owners:raise ValueError(f'{module}: data label {n} overlaps instruction at {a:04X}')
            labels[a]=n
    refs=defaultdict(list)
    for p,i in code.items():
        if i.target is not None:
            refs[i.target].append((p,'flow'))
            if i.target in code and i.target not in labels:
                labels[i.target]=('SUB' if i.mnemonic=='JSR' else 'L')+f'{i.target:04X}'
        if i.mode in MEMMODES and i.mnemonic not in ('JMP','JSR'):
            refs[i.operand].append((p,'memory'))
            if start<=i.operand<end:
                a=owners.get(i.operand,i.operand)
                if a not in labels:labels[a]=('SM' if a in code else 'D')+f'{a:04X}'
    for p,base,target in flow['vectors']:
        refs[target].append((p,'vector'))
    for p,t,inst in flow['smc']:
        if inst not in labels:labels[inst]='SM'+f'{inst:04X}'
    if start not in labels:labels[start]='IMAGESTART'
    wordtables=GAME_WORD_TABLES if module=='game' else BOOT_WORD_TABLES
    wordalias={}
    for base,count in wordtables.items():
        for a in range(base+1,base+2*count):
            wordalias[a]=(base,a-base)
            labels.pop(a,None)
    # External equates are accumulated only when actually used.
    equates={};macro_alias_notes={}
    def sym(a,context=None,force_word=False):
        if a in wordalias:
            base,delta=wordalias[a]
            if base in labels:return labels[base]+f'+{delta}'
            return f'${a:04X}'
        if context is not None and 0xd000<=a<0xd800:
            hw=HW_WRITE if context.mnemonic in WRITES else HW_READ
            name=hw.get(a)
            if name:equates[name]=a;return name
        if module=='game' and a in (0x95,0x9b) and context is not None and 0x169d<=context.addr<0x1874:
            name='TEXTCOL' if a==0x95 else 'TEXTROW';equates[name]=a;return name
        if a in ramman:
            name=ramman[a];equates[name]=a;return name
        if start<=a<end:
            base=owners.get(a,a)
            if base in labels:
                return labels[base]+(f'+{a-base}' if a!=base else '')
        if a in dataman:
            name=dataman[a];equates[name]=a;return name
        if a in codeman and a in code:return codeman[a]
        if a<256:name=f'ZP{a:02X}'
        else:name=f'M{a:04X}'
        equates[name]=a;return name
    def ins_operand(i):
        md=i.mode
        if md=='imp':return ''
        if md=='acc':return 'A'
        if md=='imm':return IMM_OVERRIDE.get(i.addr,f'#${i.operand:02X}') if module=='game' else f'#${i.operand:02X}'
        if md=='rel':return sym(i.target)
        # Do not turn an SMC placeholder into an apparently fixed named address.
        mutable=any(t in range(i.addr+1,i.next) for _,t,_ in flow['smc'])
        if mutable and i.mnemonic not in WRITES:
            s=f'${i.operand:02X}' if i.size==2 else f'${i.operand:04X}'
        elif mutable and i.operand in (0xff00,0xffff):s=f'${i.operand:04X}'
        else:s=sym(i.operand,i)
        if md in ('zp','abs'):return s
        if md in ('zpx','abx'):return s+',X'
        if md in ('zpy','aby'):return s+',Y'
        if md=='inx':return '('+s+',X)'
        if md=='iny':return '('+s+'),Y'
        if md=='ind':return '('+s+')'
        raise ValueError(md)
    smctargets={t for _,t,_ in flow['smc']};fold={};p=start
    while p<end:
        if p not in code:p+=1;continue
        accepted=False
        for name,args,n in candidates(code,p,module):
            e=p+n
            if not all(a in owners for a in range(p,e)):continue
            if any(p<=a<e for a in smctargets):continue
            if any(p<a<e for a in comments):continue
            if any(p<a<e for a in codeman):continue
            if any(p<a<e and any(not p<=source<e for source,_ in rr) for a,rr in refs.items()):continue
            # Assemble this invocation in isolation before accepting the fold.
            literal=','.join(f'${a:04X}' for a in args)
            trial=macro_definition(name)+f'\n        *= ${p:04X}\n        {name} {literal}\n        .END\n'
            _,bs,_,_=assemble(trial)
            if bs!=raw[p-start:e-start]:raise ValueError(f'Bad macro {name} at {p:04X}')
            fold[p]=(name,args,n);p=e;accepted=True;break
        if not accepted:p=code[p].next
    # Interior labels of macros no longer have references in source.
    for a,(name,args,n) in fold.items():
        for x in list(labels):
            if a<x<a+n:del labels[x]
    macro_uses=[]
    def macro_value(v,p,known_only=False):
        if known_only and v not in labels and v not in dataman and v not in ramman:
            return f'${v:04X}'
        text=sym(v)
        # Native MAC/65 evaluates numeric macro arguments at invocation time.
        # A forward-referenced address must not appear to be zero page in pass 1.
        # Emit a fixed-address alias before the first macro invocation instead.
        base=re.split(r'[+-]',text)[0]
        label_address=next((a for a,n in labels.items() if n==base),None)
        if label_address is not None and label_address>p:
            name=f'ADR{v:04X}';equates[name]=v;macro_alias_notes[name]=text
            return name
        return text
    def macro_operands(name,args,p):
        if name in ('PUSHREGS','POPREGS'):return ''
        if name=='WAITCLOCK':return macro_value(args[0],p)+f',${args[1]:02X}'
        if name in ('SETPTRXY','SETWORD'):
            a,v=args
            return macro_value(a,p)+','+macro_value(v,p,True)
        if name=='COPYWORD':return macro_value(args[0],p)+','+macro_value(args[1],p)
        if name=='SFXSTEP':
            reg=HW_WRITE[args[2]];equates[reg]=args[2]
            return macro_value(args[0],p)+','+macro_value(args[1],p)+','+reg
        raise ValueError(name)
    def content(use_macros):
        lines=[];p=start
        tablewords=GAME_WORD_TABLES if module=='game' else BOOT_WORD_TABLES
        while p<end:
            if p in comments:lines.append('; '+comments[p])
            if p in labels:lines.append(labels[p])
            if use_macros and p in fold:
                name,args,n=fold[p];param=macro_operands(name,args,p)
                lines.append(f'        {name} {param}'.rstrip()+f' ; ${p:04X}-${p+n-1:04X}')
                macro_uses.append({'address':p,'end':p+n-1,'name':name,'args':args,'bytes':n})
                p+=n;continue
            if p in code:
                i=code[p];op=ins_operand(i)
                lines.append(f'        {i.mnemonic} {op}'.rstrip()+f' ; ${p:04X}')
                p=i.next;continue
            if p in tablewords:
                count=tablewords[p]
                for k in range(0,count,4):
                    vals=[];n=min(4,count-k)
                    for j in range(n):
                        a=p+(k+j)*2;v=mem[a]|mem[a+1]<<8
                        vals.append(sym(v))
                    lines.append('        .WORD '+','.join(vals)+f' ; ${p+k*2:04X}')
                p+=count*2;continue
            st=p;stop=min(end,p+12)
            while p<stop:
                if p!=st and (p in code or p in labels or p in comments or p in tablewords):break
                p+=1
            vals=','.join(f'${v:02X}' for v in mem[st:p])
            lines.append('        .BYTE '+vals+f' ; ${st:04X}')
        lines.append('        .END')
        return lines
    body=content(True)
    # Flat version has all branch labels, including local targets hidden by macros.
    macro_labels=dict(labels)
    for _,target,_ in flow['edges']:
        if target in code and target not in labels:labels[target]=codeman.get(target,'L'+f'{target:04X}')
    flatbody=content(False)
    labels_flat=dict(labels);labels=macro_labels
    def header(include_macros):
        lines=['; ZYBEX - reverse engineering obrazu Zybex (v1).atr',
               '; Skladnia: OSS MAC/65. CPU: NMOS 6502. Bez instrukcji 65C02.',
               '; Etykiety sa propozycjami analityka, nie odzyskanymi nazwami autora.',
               '; Nie przenosic kodu: adresy stale, kod samomodyfikujacy i zasoby RAM.',
               '; .BYTE oznacza dane lub bajty bez dowodu wykonywania, NIE domyslnie kod.',
               '; Weryfikacja bajtowa: tools/rebuild.py. Natywny MAC/65 nie byl uruchamiany.',
               '; SHA256 ATR: 97f1aa6d09bbf6b772d8ce174a92f8b7870cfbd9efa148655af0b5557744fffe',
               '']
        for name,a in sorted(equates.items(),key=lambda x:(x[1],x[0])):
            entry=f'{name:<16} = ${a:02X}' if a<256 else f'{name:<16} = ${a:04X}'
            if name in macro_alias_notes:entry+=' ; '+macro_alias_notes[name]+' (adres dla makra)'
            lines.append(entry)
        if include_macros:
            for name in MACROS:
                if any(v[0]==name for v in fold.values()):lines+=['',macro_definition(name)]
        lines+=['',f'        *= ${start:04X}']
        return lines
    src='\n'.join(header(True)+body)+'\n';flat='\n'.join(header(False)+flatbody)+'\n'
    for text,desc in [(src,'macros'),(flat,'flat')]:
        org,bs,ss,ll=assemble(text)
        if org!=start or bs!=raw:
            bad=next((k for k in range(min(len(bs),len(raw))) if bs[k]!=raw[k]),None)
            raise ValueError(f'{module} {desc} roundtrip failed at {bad}, len={len(bs)} expected={len(raw)}')
    (root/'src'/f'{module.upper()}.M65').write_text(src,encoding='ascii')
    (root/'src'/f'{module.upper()}FLAT.M65').write_text(flat,encoding='ascii')
    native=[]
    for n,line in enumerate(src.splitlines(),1):
        # Text edition for ENTER. Large modules may need splitting/tokenization on Atari.
        if len(line)>110:
            # Comments can be split without changing source semantics.
            if line.startswith('; '):
                import textwrap
                native.extend('; '+part for part in textwrap.wrap(line[2:],105));continue
            raise ValueError(f'Native source line too long: {len(line)}: {line}')
        native.append(line)
    (root/'native').mkdir(exist_ok=True)
    numbered='\n'.join(f'{n+10} {line}' for n,line in enumerate(native))+'\n'
    (root/'native'/f'{module.upper()}.LST').write_bytes(numbered.encode('ascii').replace(b'\n',b'\x9b'))
    # Verify the literal ATASCII/numbered edition as well.
    _,nb,_,_=assemble(numbered)
    assert nb==raw
    # Readable address/byte listing. Data bytes are never decoded as instructions.
    labels=labels_flat
    listing=['; ADDRESS  BYTES      NMOS 6502 / DATA', '; '+module.upper(), '']
    p=start
    while p<end:
        if p in comments:listing.append('; '+comments[p])
        if p in labels_flat:listing.append(labels_flat[p]+':')
        if p in code:
            i=code[p];listing.append(f'{p:04X}  {i.raw.hex(" ").upper():8}  {i.mnemonic:3} {ins_operand(i)}');p=i.next
        else:
            st=p;limit=min(end,p+12)
            while p<limit:
                if p!=st and (p in code or p in labels_flat or p in comments):break
                p+=1
            rawdata=bytes(mem[st:p]);txt=''.join(chr(v) if 32<=v<127 else '.' for v in rawdata)
            listing.append(f'{st:04X}  {rawdata.hex(" ").upper():35}  .BYTE  ; {txt}')
    (root/'analysis'/f'{module}_listing.txt').write_text('\n'.join(listing)+'\n',encoding='ascii')
    if module=='boot':
        (root/'analysis/boot_unused_fragment.txt').write_text(
            '; Nieuzyty fragment; punkt $067A dobrany jako poczatek spojnosc kodu.\n'
            '; NIE jest potwierdzonym punktem wejscia. Plik tylko pomocniczy.\n'+
            '\n'.join(linear(mem,0x67a,0x6ac))+'\n')
    labels=macro_labels
    stats={'module':module,'start':start,'end':end-1,'size':len(raw),'instruction_count':len(code),
           'code_bytes':len(owners),'data_or_unknown_bytes':len(raw)-len(owners),
           'labels':len(labels),'equates':len(equates),'manual_code_labels':sum(a in code for a in codeman),
           'macro_invocations':len(fold),'macro_types':dict(Counter(x[0] for x in fold.values())),
           'macro_covered_bytes':sum(x[2] for x in fold.values()),'smc_direct_writes':len(flow['smc']),
           'smc_target_bytes':len(smctargets),'smc_instructions':len({i for _,_,i in flow['smc']}),
           'seeds':flow['seeds'],'issues':flow['issues'],'vectors':flow['vectors'],
           'source_lines':len(src.splitlines()),'native_max_line':len(native)+9,
           'roundtrip_macros':True,'roundtrip_flat':True,'roundtrip_native_text':True}
    metadata={**stats,'code':sorted(code),'edges':flow['edges'],'smc':flow['smc'],
              'symbols':{n:a for a,n in labels_flat.items()}|equates,'macros':macro_uses}
    (root/'analysis'/f'{module}_analysis.json').write_text(json.dumps(metadata,indent=2)+'\n')
    def tsv(name,rows):
        with (root/'analysis'/f'{module}_{name}.tsv').open('w',newline='') as f:csv.writer(f,delimiter='\t').writerows(rows)
    tsv('symbols',[['address','name','kind']]+[[f'{a:04X}',n,'code' if a in code else 'data'] for a,n in sorted(labels_flat.items())]+[[f'{a:04X}',n,'equate'] for n,a in sorted(equates.items(),key=lambda x:(x[1],x[0]))])
    tsv('smc',[['writer_pc','target_byte','instruction_pc','byte_offset','instruction']]+[[f'{p:04X}',f'{t:04X}',f'{i:04X}',t-i,code[i].mnemonic+' '+operand_text(code[i])] for p,t,i in flow['smc']])
    tsv('xrefs',[['from','to','kind']]+[[f'{p:04X}',f'{a:04X}',k] for a,rr in sorted(refs.items()) for p,k in sorted(rr)])
    tsv('macros',[['address','end','name','bytes']]+[[f'{x["address"]:04X}',f'{x["end"]:04X}',x['name'],x['bytes']] for x in macro_uses])
    # Code/data map, in original-file coordinates.
    rows=[['cpu_start','cpu_end','size','kind','atr_offset_start','atr_offset_end']];p=start
    filebase=16 if module=='boot' else 16+255*128
    while p<end:
        st=p;iscode=p in owners
        while p<end and (p in owners)==iscode:p+=1
        rows.append([f'{st:04X}',f'{p-1:04X}',p-st,'code' if iscode else 'data_or_unknown',
                     f'{filebase+st-start:05X}',f'{filebase+p-start-1:05X}'])
    tsv('map',rows)
    return stats

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args();r=a.root
    for d in ('src','analysis','native'): (r/d).mkdir(parents=True,exist_ok=True)
    boot=(r/'extracted/boot_0480_10ff.bin').read_bytes();game=(r/'extracted/payload_0600_bc7f.bin').read_bytes()
    stats=[]
    stats.append(build_module(r,'boot',0x480,0x1100,boot,[0x486,0x488,0x537]))
    stats.append(build_module(r,'game',0x600,0xbc80,game,[0xc80,0x102c,0x102d]))
    (r/'analysis/disassembly_summary.json').write_text(json.dumps(stats,indent=2)+'\n')
    print(json.dumps(stats,indent=2))
if __name__=='__main__':main()
