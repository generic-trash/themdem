from .base_pass import *


class IndirectXchgPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-2]):
            seq = insns[i: i + 3]
            if seq[0].mnemonic != "xor" or seq[0].operands[0].type == CS_OP_IMM or seq[0].operands[1].type == CS_OP_IMM:
                continue
            commasplit = [i.strip() for i in seq[0].op_str.split(',')]
            if seq[1].mnemonic != "xor" or commasplit[0] not in seq[1].op_str or commasplit[1] not in seq[1].op_str:
                continue
            if seq[2].mnemonic != "xor" or seq[2].op_str != seq[0].op_str:
                continue
            matches.append(i)

        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        instr = f"xchg {insns[match].op_str}"
        subs = {
            match: self._assemble(instr, insns[match].address),
            match + 1: None,
            match + 2: None,
        }
        return subs
