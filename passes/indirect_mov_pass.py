from .base_pass import *

class IndirectMovPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-1]):
            nextinsn = insns[i + 1]

            if insn.mnemonic != "push":
                continue
            if nextinsn.mnemonic != "pop":
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        if insns[match + 1].op_str != insns[match].op_str:
            instr = f"mov {insns[match + 1].op_str}, {insns[match].op_str}"
            subs = {
                match: self._assemble(instr, insns[match].address),
                match + 1: None,
            }
        else:
            subs = {
                match: None,
                match + 1: None
            }
        return subs