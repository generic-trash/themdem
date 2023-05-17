from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class IndirectPopPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-1]):
            nextinsn = insns[i + 1]

            if insn.mnemonic != "mov" or not insn.op_str.endswith("dword ptr [esp]") or insn.op_str.startswith("esp"):
                continue
            if nextinsn.mnemonic != "add" or nextinsn.op_str != "esp, 4":
                continue

            matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        pushed = insns[match].operands[0]
        if pushed.type == CS_OP_REG:
            instr = f"pop {self.md.reg_name(pushed.reg)}"
        else:
            raise Exception("Invalid")
        subs = {match: self._assemble(instr, insns[match].address), match + 1: None}
        return subs
