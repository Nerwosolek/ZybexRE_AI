"""NMOS 6502 disassembly primitives. Standard-library only."""
from dataclasses import dataclass

# MOS NMOS 6502: official opcodes only. Illegal bytes deliberately remain data.
_ROWS = '''
BRK:imp ORA:inx --- --- --- ORA:zp ASL:zp --- PHP:imp ORA:imm ASL:acc --- --- ORA:abs ASL:abs ---
BPL:rel ORA:iny --- --- --- ORA:zpx ASL:zpx --- CLC:imp ORA:aby --- --- --- ORA:abx ASL:abx ---
JSR:abs AND:inx --- --- BIT:zp AND:zp ROL:zp --- PLP:imp AND:imm ROL:acc --- BIT:abs AND:abs ROL:abs ---
BMI:rel AND:iny --- --- --- AND:zpx ROL:zpx --- SEC:imp AND:aby --- --- --- AND:abx ROL:abx ---
RTI:imp EOR:inx --- --- --- EOR:zp LSR:zp --- PHA:imp EOR:imm LSR:acc --- JMP:abs EOR:abs LSR:abs ---
BVC:rel EOR:iny --- --- --- EOR:zpx LSR:zpx --- CLI:imp EOR:aby --- --- --- EOR:abx LSR:abx ---
RTS:imp ADC:inx --- --- --- ADC:zp ROR:zp --- PLA:imp ADC:imm ROR:acc --- JMP:ind ADC:abs ROR:abs ---
BVS:rel ADC:iny --- --- --- ADC:zpx ROR:zpx --- SEI:imp ADC:aby --- --- --- ADC:abx ROR:abx ---
--- STA:inx --- --- STY:zp STA:zp STX:zp --- DEY:imp --- TXA:imp --- STY:abs STA:abs STX:abs ---
BCC:rel STA:iny --- --- STY:zpx STA:zpx STX:zpy --- TYA:imp STA:aby TXS:imp --- --- STA:abx --- ---
LDY:imm LDA:inx LDX:imm --- LDY:zp LDA:zp LDX:zp --- TAY:imp LDA:imm TAX:imp --- LDY:abs LDA:abs LDX:abs ---
BCS:rel LDA:iny --- --- LDY:zpx LDA:zpx LDX:zpy --- CLV:imp LDA:aby TSX:imp --- LDY:abx LDA:abx LDX:aby ---
CPY:imm CMP:inx --- --- CPY:zp CMP:zp DEC:zp --- INY:imp CMP:imm DEX:imp --- CPY:abs CMP:abs DEC:abs ---
BNE:rel CMP:iny --- --- --- CMP:zpx DEC:zpx --- CLD:imp CMP:aby --- --- --- CMP:abx DEC:abx ---
CPX:imm SBC:inx --- --- CPX:zp SBC:zp INC:zp --- INX:imp SBC:imm NOP:imp --- CPX:abs SBC:abs INC:abs ---
BEQ:rel SBC:iny --- --- --- SBC:zpx INC:zpx --- SED:imp SBC:aby --- --- --- SBC:abx INC:abx ---
'''
OPCODES = {i:tuple(t.split(':')) for i,t in enumerate(_ROWS.split()) if t!='---'}
assert len(_ROWS.split()) == 256 and len(OPCODES)==151
SIZES={'imp':1,'acc':1,'imm':2,'zp':2,'zpx':2,'zpy':2,'inx':2,'iny':2,'rel':2,'abs':3,'abx':3,'aby':3,'ind':3}
ENCODE={v:k for k,v in OPCODES.items()}
@dataclass(frozen=True)
class Instruction:
    addr:int
    opcode:int
    mnemonic:str
    mode:str
    size:int
    operand:int|None
    raw:bytes
    @property
    def next(self): return (self.addr+self.size)&65535
    @property
    def target(self):
        if self.mode=='rel': return (self.addr+2+(self.operand if self.operand<128 else self.operand-256))&65535
        if self.mnemonic in ('JSR','JMP') and self.mode=='abs':return self.operand
        return None

def decode(mem,addr):
    op=mem[addr]
    if op not in OPCODES:return None
    mn,mode=OPCODES[op]; n=SIZES[mode]
    raw=bytes(mem[(addr+i)&65535] for i in range(n))
    val=None if n==1 else raw[1] if n==2 else raw[1]|raw[2]<<8
    return Instruction(addr,op,mn,mode,n,val,raw)

def operand_text(ins,symbols=None):
    symbols=symbols or {}; md=ins.mode; v=ins.operand
    if md=='imp':return ''
    if md=='acc':return 'A'
    if md=='imm':return f'#${v:02X}'
    if md=='rel':return symbols.get(ins.target,f'${ins.target:04X}')
    s=symbols.get(v,f'${v:02X}' if md in ('zp','zpx','zpy','inx','iny') else f'${v:04X}')
    if md in ('zp','abs'):return s
    if md in ('zpx','abx'):return s+',X'
    if md in ('zpy','aby'):return s+',Y'
    if md=='inx':return '('+s+',X)'
    if md=='iny':return '('+s+'),Y'
    if md=='ind':return '('+s+')'
    raise ValueError(md)

def linear(mem,start,end):
    p=start
    while p<end:
        ins=decode(mem,p)
        if ins is None or p+ins.size>end:
            yield f'{p:04X}  {mem[p]:02X}        .BYTE ${mem[p]:02X}';p+=1
        else:
            yield f'{p:04X}  {ins.raw.hex(" ").upper():8}  {ins.mnemonic:3} {operand_text(ins)}'
            p+=ins.size

class CPU6502:
    """Small instruction-level NMOS 6502 interpreter for reproducible analysis.

    Not an Atari hardware emulator. Timing is a scheduling approximation, not a
    cycle-accurate model. BRK and undocumented opcodes stop the analysis.
    Memory may implement read/write hooks using __getitem__/__setitem__.
    """
    C,Z,I,D,B,U,V,N=1,2,4,8,16,32,64,128
    def __init__(self,memory,pc=0):
        self.m=memory; self.pc=pc; self.a=self.x=self.y=0
        self.sp=0xfd; self.p=0x24; self.steps=0; self.cycles=0
    def nz(self,v):
        v&=255; self.p=(self.p&~0x82)|(v&128)|(2 if not v else 0);return v
    def flag(self,f,v):self.p=(self.p|f) if v else (self.p&~f)
    def push(self,v): self.m[0x100+self.sp]=v&255;self.sp=(self.sp-1)&255
    def pop(self):self.sp=(self.sp+1)&255;return self.m[0x100+self.sp]
    def word(self,a):return self.m[a&65535]|self.m[(a+1)&65535]<<8
    def nmi(self):
        self.push(self.pc>>8);self.push(self.pc);self.push((self.p&~16)|32)
        self.p|=4;self.pc=self.word(0xfffa);self.cycles+=7
    def rts(self):self.pc=((self.pop()|(self.pop()<<8))+1)&65535
    def step(self):
        pc=self.pc; op=self.m[pc]
        if op not in OPCODES:raise RuntimeError(f'Illegal opcode ${op:02X} at ${pc:04X}')
        mn,md=OPCODES[op];n=SIZES[md];p1=self.m[(pc+1)&65535] if n>1 else 0
        val=(p1|(self.m[(pc+2)&65535]<<8)) if n>2 else p1
        self.pc=(pc+n)&65535;self.steps+=1;self.cycles+=2+n
        ea=None
        if md=='zp':ea=val
        elif md=='zpx':ea=(val+self.x)&255
        elif md=='zpy':ea=(val+self.y)&255
        elif md in ('abs','ind'):ea=val
        elif md=='abx':ea=(val+self.x)&65535
        elif md=='aby':ea=(val+self.y)&65535
        elif md=='inx':
            z=(val+self.x)&255;ea=self.m[z]|self.m[(z+1)&255]<<8
        elif md=='iny':ea=((self.m[val]|self.m[(val+1)&255]<<8)+self.y)&65535
        if mn.startswith('B') and mn not in ('BIT','BRK'):
            flag={'BPL':128,'BMI':128,'BVC':64,'BVS':64,'BCC':1,'BCS':1,'BNE':2,'BEQ':2}[mn]
            want=mn in ('BMI','BVS','BCS','BEQ')
            if bool(self.p&flag)==want:self.pc=(self.pc+(val if val<128 else val-256))&65535;self.cycles+=1
            return
        if mn=='JMP':
            self.pc=(self.m[ea]|self.m[(ea&0xff00)|((ea+1)&255)]<<8) if md=='ind' else ea;return
        if mn=='JSR':
            ret=(self.pc-1)&65535;self.push(ret>>8);self.push(ret);self.pc=ea;self.cycles+=1;return
        if mn=='RTS':self.rts();self.cycles+=3;return
        if mn=='RTI':self.p=self.pop()|32;self.pc=self.pop()|(self.pop()<<8);self.cycles+=3;return
        if mn=='BRK':raise RuntimeError(f'BRK at ${pc:04X}')
        if mn=='STA':self.m[ea]=self.a;return
        if mn=='STX':self.m[ea]=self.x;return
        if mn=='STY':self.m[ea]=self.y;return
        if mn in ('PHA','PHP'):
            self.push(self.a if mn=='PHA' else self.p|48);return
        if mn=='PLA':self.a=self.nz(self.pop());return
        if mn=='PLP':self.p=self.pop()|32;return
        if mn in ('TAX','TAY','TXA','TYA','TSX','TXS'):
            src={'TAX':'a','TAY':'a','TXA':'x','TYA':'y','TSX':'sp','TXS':'x'}[mn]
            dst={'TAX':'x','TAY':'y','TXA':'a','TYA':'a','TSX':'x','TXS':'sp'}[mn]
            v=getattr(self,src);setattr(self,dst,v if mn=='TXS' else self.nz(v));return
        if mn in ('INX','INY','DEX','DEY'):
            r=mn[-1].lower();v=getattr(self,r)+(1 if mn[0]=='I' else -1);setattr(self,r,self.nz(v));return
        if mn in ('CLC','SEC','CLI','SEI','CLD','SED','CLV'):
            f={'CLC':1,'SEC':1,'CLI':4,'SEI':4,'CLD':8,'SED':8,'CLV':64}[mn]
            self.flag(f,mn.startswith('SE'));return
        if mn=='NOP':return
        v=self.a if md=='acc' else val if md=='imm' else self.m[ea]
        if mn in ('LDA','LDX','LDY'):setattr(self,mn[-1].lower(),self.nz(v));return
        if mn=='BIT':self.p=(self.p&~0xc2)|(v&0xc0)|(2 if not(self.a&v) else 0);return
        if mn in ('CMP','CPX','CPY'):
            lhs=self.a if mn=='CMP' else self.x if mn=='CPX' else self.y
            self.flag(1,lhs>=v);self.nz(lhs-v);return
        if mn in ('AND','ORA','EOR'):
            self.a=self.nz(self.a&v if mn=='AND' else self.a|v if mn=='ORA' else self.a^v);return
        if mn in ('ADC','SBC'):
            a=self.a;c=self.p&1
            if mn=='ADC':
                raw=a+v+c;self.flag(64,(~(a^v)&(a^raw)&128)!=0)
                if self.p&8:
                    # NMOS ADC: Z from binary sum, N/V from pre-high-adjust result.
                    low=(a&15)+(v&15)+c
                    if low>9:low+=6
                    t=(a&240)+(v&240)+(low&15)+(16 if low>15 else 0)
                    self.flag(2,(raw&255)==0);self.flag(128,t&128)
                    self.flag(64,(~(a^v)&(a^t)&128)!=0)
                    if t>=0xa0:t+=0x60
                    self.flag(1,t>255);self.a=t&255
                else:self.flag(1,raw>255);self.a=self.nz(raw)
            else:
                raw=a-v-(1-c);self.flag(64,((a^v)&(a^raw)&128)!=0)
                self.flag(1,raw>=0);self.nz(raw)
                if self.p&8:
                    lo=(a&15)-(v&15)-(1-c);hi=(a>>4)-(v>>4)
                    if lo<0:lo-=6;hi-=1
                    if hi<0:hi-=6
                    self.a=((hi<<4)|(lo&15))&255
                else:self.a=raw&255
            return
        if mn in ('ASL','LSR','ROL','ROR','INC','DEC'):
            c=self.p&1
            if mn=='ASL':self.flag(1,v&128);v<<=1
            elif mn=='LSR':self.flag(1,v&1);v>>=1
            elif mn=='ROL':self.flag(1,v&128);v=(v<<1)|c
            elif mn=='ROR':self.flag(1,v&1);v=(v>>1)|(c<<7)
            elif mn=='INC':v+=1
            elif mn=='DEC':v-=1
            v=self.nz(v)
            if md=='acc':self.a=v
            else:self.m[ea]=v
            return
        raise RuntimeError((pc,mn,md))
