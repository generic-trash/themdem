from .base_pass import *


class IndirectXchgPassStackLarge(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-10]):
            seq = insns[i: i + 11]
            if seq[0].mnemonic != "pushfd":
                continue
            if seq[1].mnemonic != "push" or seq[1].operands[0].type != CS_OP_IMM:
                continue
            if seq[2].mnemonic != "push" or seq[2].operands[0].type != CS_OP_IMM:
                continue
            if seq[3].mnemonic != "push" or seq[3].operands[0].type != CS_OP_REG:
                continue
            if seq[4].mnemonic != "push" or seq[4].operands[0].type != CS_OP_REG:
                continue
            regpool = (seq[3].op_str, seq[4].op_str)
            if seq[5].mnemonic != "mov" or seq[5].op_str != f"{regpool[0]}, dword ptr [esp + 0x10]":
                continue
            if seq[6].mnemonic != "mov" or seq[6].op_str != f"{regpool[1]}, dword ptr [esp + 8]":
                continue
            if seq[7].mnemonic != "mov" or seq[7].op_str != f"dword ptr [esp + 8], {regpool[0]}":
                continue
            if seq[8].mnemonic != "mov" or seq[8].op_str != f"dword ptr [esp + 0x10], {regpool[1]}":
                continue
            if seq[9].mnemonic != "pop" or seq[9].op_str != regpool[1]:
                continue
            if seq[10].mnemonic != "pop" or seq[10].op_str != regpool[0]:
                continue
            matches.append(i)

        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        subs = {
            match: self._disassemble(insns[match + 2].bytes, insns[match].address),
            match + 2: self._disassemble(insns[match].bytes, insns[match + 2].address),
            match + 3: None,
            match + 4: None,
            match + 5: None,
            match + 6: None,
            match + 7: None,
            match + 8: None,
            match + 9: None,
            match + 10: None,
        }
        return subs
