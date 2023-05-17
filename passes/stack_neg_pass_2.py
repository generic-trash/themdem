from .base_pass import *

class StackNegPassLarge(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-4]):
            seq = insns[i: i + 5]
            if seq[0].mnemonic != "push":
                continue
            if seq[1].mnemonic != "mov" or seq[1].op_str != f"{seq[0].op_str}, 0":
                continue
            if seq[2].mnemonic != "sub" or not seq[2].op_str.startswith(seq[0].op_str):
                continue
            if seq[3].mnemonic != "xchg" or seq[0].op_str not in seq[3].op_str:
                continue
            if seq[4].mnemonic != "pop" or seq[4].op_str != seq[0].op_str:
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        instr = f"neg {self.md.reg_name(insns[match + 2].operands[1].reg)}"
        subs = {
            match: self._assemble(instr, insns[match].address),
            match + 1: None,
            match + 2: None,
            match + 3: None,
            match + 4: None,
        }
        return subs