from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class SandwichArithmeticPassStack(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-2]):
            seq = insns[i: i + 3]
            if seq[0].mnemonic != "push":
                continue
            if seq[1].mnemonic not in ("not", "neg") or seq[1].op_str != "dword ptr [esp]":
                continue
            if seq[2].mnemonic != "pop" or seq[2].op_str != seq[0].op_str:
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        instr = f"{insns[match + 1].mnemonic} {insns[match].op_str}"
        try:
            subs = {match: self._assemble(instr, insns[match].address), match + 1: None, match + 2: None}
        except:
            print(instr, match)
            pprint(insns)
            raise
        return subs
