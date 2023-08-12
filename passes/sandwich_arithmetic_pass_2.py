from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class SandwichArithmeticPass2(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-2]):
            seq = insns[i: i + 3]
            if seq[0].mnemonic not in ('add', 'sub') or seq[0].operands[1].type != CS_OP_IMM:
                continue
            if seq[1].mnemonic not in ('add', 'sub') or seq[1].operands[0].type != CS_OP_REG or \
                    seq[1].operands[0].reg != seq[0].operands[0].reg:
                continue
            if seq[2].mnemonic not in ('add', 'sub') or seq[2].operands[0].type != CS_OP_REG or \
                    seq[2].operands[0].reg != seq[0].operands[0].reg or seq[2].operands[1].type != CS_OP_IMM or \
                seq[0].operands[1].imm != seq[2].operands[1].imm or seq[2].mnemonic == seq[0].mnemonic:
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        subs = {
            match: None,
            match + 2: None
        }
        return subs
