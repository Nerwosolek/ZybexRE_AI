#!/usr/bin/env python3
"""Create smaller, separately assemblable MAC/65 modules at fixed addresses.

Does not split instructions, .BYTE/.WORD lines or macro invocations.
Adds only externally referenced fixed-address symbols to each part.
Native .LST files are numbered ATASCII text for ENTER, not SAVE token files.
"""
from __future__ import annotations
import argparse, json, re
from pathlib import Path
from mac65_subset import assemble

ROOT=Path(__file__).resolve().parents[1]

def split(root:Path=ROOT,limit:int=4096):
    text=(root/'src/GAME.M65').read_text('ascii')
    origin,raw,symbols,_=assemble(text)
    before,body=text.split('        *= $0600\n',1)
    units=[];pending=[]
    for line in body.splitlines():
        if line.strip()=='.END':continue
        pending.append(line)
        match=re.search(r'; \$([0-9A-F]{4})(?:-\$[0-9A-F]{4})?$',line)
        if match and not line.startswith(';'):
            units.append((int(match.group(1),16),pending));pending=[]
    if pending:raise ValueError('Unexpected trailing source text')
    groups=[];group=[];base=origin
    for k,unit in enumerate(units):
        end=units[k+1][0] if k+1<len(units) else origin+len(raw)
        if group and end-base>limit:
            groups.append(group);group=[];base=unit[0]
        group.append(unit)
    if group:groups.append(group)
    head_symbols=set(re.findall(r'^([A-Z?@][A-Z0-9?@]*)\s*=',before,re.M))
    out=root/'src/parts';out.mkdir(exist_ok=True)
    native=root/'native/parts';native.mkdir(exist_ok=True)
    records=[]
    for k,g in enumerate(groups):
        start=g[0][0];end=groups[k+1][0][0] if k+1<len(groups) else origin+len(raw)
        bodylines=[line for _,lines in g for line in lines]
        stripped='\n'.join(line.split(';',1)[0] for line in bodylines)
        defined={line.strip() for line in stripped.splitlines() if re.fullmatch(r'[A-Z?@][A-Z0-9?@]*',line.strip())}
        # Hex literals are not symbol references.
        nohex=re.sub(r'\$[0-9A-F]+','',stripped)
        all_tokens=set(re.findall(r'[A-Z?@][A-Z0-9?@]*',nohex))
        refs=all_tokens & symbols.keys()
        needed=refs-defined-head_symbols
        external=['; Symbole z innych modulow; adresy oryginalne, bez relokacji.']
        external += [f'{name:<16} = ${symbols[name]:04X}' for name in sorted(needed)]
        shared=['; ZYBEX: osobny modul MAC/65, adresy stale.']
        shared += [line for line in before.splitlines() if re.match(r'^[A-Z?@][A-Z0-9?@]*\s*=',line) and line.split()[0] in refs]
        for macro in re.finditer(r'        \.MACRO ([A-Z0-9]+)\n.*?        \.ENDM',before,re.S):
            if macro.group(1) in all_tokens:shared.append(macro.group(0))
        source='\n'.join(shared)+'\n\n'+'\n'.join(external)+f'\n\n        *= ${start:04X}\n'+'\n'.join(bodylines)+'\n        .END\n'
        org,bs,_,_=assemble(source)
        if org!=start or bs!=raw[start-origin:end-origin]:raise ValueError(f'Part {k} does not round-trip')
        name=f'G{k:02d}'
        (out/f'{name}.M65').write_text(source,'ascii')
        # Drop comments only in the memory-constrained Atari text edition.
        lines=[line.split(';',1)[0].rstrip() for line in source.splitlines()]
        lines=[line for line in lines if line.strip()]
        numbered='\n'.join(f'{n+10} {line}' for n,line in enumerate(lines))+'\n'
        nb=numbered.encode('ascii').replace(b'\n',b'\x9b')
        (native/f'{name}.LST').write_bytes(nb)
        norg,nraw,_,_=assemble(numbered)
        assert norg==start and nraw==bs
        records.append({'name':name,'start':start,'end':end-1,'binary_bytes':len(bs),
                        'native_lines':len(lines),'text_bytes':len(nb),'external_symbols':len(needed)})
    (root/'analysis/native_parts.json').write_text(json.dumps(records,indent=2)+'\n')
    return records

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--limit',type=int,default=4096)
    a=p.parse_args();print(json.dumps(split(a.root,a.limit),indent=2))
