#!/usr/bin/env python3
"""Small regression tests; not a certified 6502 compatibility suite."""
from pathlib import Path
import json, unittest
from cpu6502 import CPU6502, OPCODES, SIZES, decode, operand_text
from mac65_subset import assemble, AssemblyError

ROOT=Path(__file__).resolve().parents[1]

class ReconstructionTests(unittest.TestCase):
    def test_all_official_encodings(self):
        self.assertEqual(len(OPCODES),151)
        for opcode,(mn,mode) in OPCODES.items():
            with self.subTest(opcode=opcode,mnemonic=mn,mode=mode):
                n=SIZES[mode];raw=bytes([opcode,0x42,0x12][:n])
                mem=bytearray(65536);mem[0x2000:0x2000+n]=raw
                ins=decode(mem,0x2000)
                src=f'        *= $2000\n        {mn} {operand_text(ins)}\n        .END\n'
                org,data,_,_=assemble(src)
                self.assertEqual(org,0x2000);self.assertEqual(data,raw)

    def test_decimal_results_and_carry(self):
        # Exhaust every valid two-digit BCD input; flags N/V/Z need wider suites.
        bcd=lambda n:((n//10)<<4)|(n%10)
        mem=bytearray(65536);cpu=CPU6502(mem,0x2000)
        for opcode in (0x69,0xe9):
            mem[0x2000]=opcode
            for a in range(100):
                for b in range(100):
                    for carry in (0,1):
                        cpu.pc=0x2000;cpu.a=bcd(a);cpu.p=0x28|carry
                        mem[0x2001]=bcd(b);cpu.step()
                        val=a+b+carry if opcode==0x69 else a-b-(1-carry)
                        self.assertEqual(cpu.a,bcd(val%100))
                        expected=val>=100 if opcode==0x69 else val>=0
                        self.assertEqual(bool(cpu.p&1),expected)

    def test_nmos_jmp_page_wrap(self):
        m=bytearray(65536);m[0x2000:0x2003]=bytes.fromhex('6c ff 30')
        m[0x30ff]=0x34;m[0x3000]=0x12;m[0x3100]=0xab
        c=CPU6502(m,0x2000);c.step();self.assertEqual(c.pc,0x1234)

    def test_nmi_rti_stack(self):
        m=bytearray(65536);m[0xfffa]=0;m[0xfffb]=0x30;m[0x3000]=0x40
        c=CPU6502(m,0x2345);c.p=0x21;sp=c.sp;c.nmi();c.step()
        self.assertEqual((c.pc,c.sp,c.p),(0x2345,sp,0x21))

    def test_reject_branch_overflow(self):
        with self.assertRaises(AssemblyError):assemble(' *= $2000\n BNE $3000\n .END\n')

    def test_macro_local_labels(self):
        src=' .MACRO SPIN\n?WAIT DEX\n BNE ?WAIT\n .ENDM\n *= $2000\n SPIN\n SPIN\n .END\n'
        _,data,_,_=assemble(src);self.assertEqual(data,bytes.fromhex('ca d0 fd ca d0 fd'))

    def test_dynamic_coverage(self):
        static=json.loads((ROOT/'analysis/game_analysis.json').read_text())
        trace=json.loads((ROOT/'analysis/game_synthetic_trace.json').read_text())
        self.assertFalse(set(int(p,16) for p in trace['executed'])-set(static['code']))
        self.assertIsNone(trace['failure']);self.assertEqual(trace['game_mainloop_visits'],62)
        variants=trace['variants']['164F']
        self.assertIn('ee9d3d',variants);self.assertIn('ce9d3d',variants)

if __name__=='__main__':unittest.main(verbosity=2)
