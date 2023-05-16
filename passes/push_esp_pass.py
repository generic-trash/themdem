from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class IndirectPushEspPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-2]):
            nextinsn = insns[i + 1]
            nexttonext = insns[i + 2]
            if (insn.mnemonic != "sub" or insn.op_str != "esp, 4") and (insn.mnemonic != "push"):
                continue
            if nextinsn.mnemonic != "mov" or nextinsn.op_str != "dword ptr [esp], esp":
                continue
            if nexttonext.mnemonic != "add" or nexttonext.op_str != "dword ptr [esp], 4":
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        instr = "push esp"
        subs = {match: self._assemble(instr, insns[match].address), match + 1: None, match + 2: None}
        return subs
