from .base_pass import *


class PopEspPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns):
            if insn.mnemonic == "pop" and insn.op_str == "esp":
                matches.append(i)
        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        instr = f"mov esp, dword ptr [esp]"
        subs = {match: self._assemble(instr, insns[match].address)}
        return subs
