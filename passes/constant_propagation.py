from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class ConstantPropagationPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-1]):
            nextinsn = insns[i + 1]

            if insn.mnemonic != "mov" or insn.operands[0].type != CS_OP_REG or insn.operands[1].type != CS_OP_IMM:
                continue
            if nextinsn.mnemonic not in ("add", "sub", "xor", "or", "and", "shl", "shr", "not", "neg") or \
                    nextinsn.operands[0].type != CS_OP_REG or nextinsn.operands[0].reg != insn.operands[0].reg or \
                    (len(nextinsn.operands) != 1 and nextinsn.operands[1].type != CS_OP_IMM):
                continue

            matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        insn = insns[match]
        nextinsn = insns[match + 1]
        op0 = insn.operands[1].imm
        try:
            op1 = nextinsn.operands[1].imm
        except:
            op1 = 0
        if nextinsn.mnemonic == "not":
            val = ~op0
        elif nextinsn.mnemonic == "neg":
            val = -op0
        elif nextinsn.mnemonic == "add":
            val = op0 + op1
        elif nextinsn.mnemonic == "sub":
            val = op0 - op1
        elif nextinsn.mnemonic == "and":
            val = op0 & op1
        elif nextinsn.mnemonic == "or":
            val = op0 | op1
        elif nextinsn.mnemonic == "xor":
            val = op0 ^ op1
        elif nextinsn.mnemonic == "shr":
            val = op0 | op1
        elif nextinsn.mnemonic == "shl":
            val = op0 ^ op1
        else:
            raise ValueError
        instr = f"mov {self.md.reg_name(insn.operands[0].reg)}, {hex(val & 0xffffffff)}"
        subs = {match: self._assemble(instr, insns[match].address), match + 1: None}
        return subs
