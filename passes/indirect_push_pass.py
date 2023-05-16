from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class IndirectPushPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-1]):
            nextinsn = insns[i + 1]
            if (insn.mnemonic != "sub" or insn.op_str != "esp, 4") and (insn.mnemonic != "push"):
                continue
            if nextinsn.mnemonic != "mov" or not nextinsn.op_str.startswith("dword ptr [esp]") or \
                    nextinsn.op_str.endswith("esp"):
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        pushed = insns[match + 1].operands[1]
        if pushed.type == CS_OP_REG:
            instr = f"push {self.md.reg_name(pushed.reg)}"
        elif pushed.type == CS_OP_IMM:
            instr = f"push {hex(pushed.imm)}"
        else:
            raise Exception("Invalid")
        subs = {match: self._assemble(instr, insns[match].address), match + 1: None}
        return subs
