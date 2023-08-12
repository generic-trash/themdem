from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class SandwichArithmeticPassStack2(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-3]):
            seq = insns[i: i + 4]
            if seq[0].mnemonic != "push":
                continue
            if seq[1].mnemonic != "mov" or not seq[1].op_str.startswith(seq[0].op_str) or not \
                    seq[1].operands[1].type == CS_OP_IMM:
                continue
            if seq[2].mnemonic not in ("add", "sub", "xor", "and", "or", "shr", "mov") or not seq[2].op_str.endswith(seq[0].op_str) or \
                    "[esp + 4]" not in seq[2].op_str:
                continue
            if seq[3].mnemonic != "pop" or seq[3].op_str != seq[0].op_str:
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        imm = insns[match + 1].operands[1].imm
        instr = f"{insns[match + 2].mnemonic} dword ptr [esp], {hex(imm)}"
        try:
            subs = {match: self._assemble(instr, insns[match].address), match + 1: None, match + 2: None, match + 3: None}
        except:
            print(instr, match)
            pprint(insns)
            raise
        return subs
