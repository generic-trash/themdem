from .base_pass import *

class StackNegPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-2]):
            seq = insns[i: i + 3]
            if seq[0].mnemonic != "push" or seq[0].op_str != "0":
                continue
            if seq[1].mnemonic != "sub" or not seq[1].op_str.startswith("dword ptr [esp], "):
                continue
            if seq[2].mnemonic != "pop" or not seq[1].op_str.endswith(seq[2].op_str):
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        instr = f"neg {insns[match + 2].op_str}"
        subs = {
            match: self._assemble(instr, insns[match].address),
            match + 1: None,
            match + 2: None
        }
        return subs