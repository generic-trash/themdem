from .base_pass import *
class IndirectXchgPassStack(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-2]):
            seq = insns[i: i + 3]
            if seq[0].mnemonic != "push" or seq[0].operands[0].type != CS_OP_REG:
                continue
            if seq[1].mnemonic != "mov" or seq[1].op_str != f"{seq[0].op_str}, dword ptr [esp + 4]":
                continue
            if seq[2].mnemonic != "pop" or seq[2].op_str != "dword ptr [esp]":
                continue
            matches.append(i)

        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        instr = f"xchg dword ptr [esp], {insns[match].op_str}"
        subs = {
            match: self._assemble(instr, insns[match].address),
            match + 1: None,
            match + 2: None,
        }
        return subs