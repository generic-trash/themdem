from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class LeaCreatePass(BasePass):
    def match_instructions(self, insns: List[CsInsn]):
        matches = []
        for i, insn in enumerate(insns):
            if insn.mnemonic != "add":
                continue
            if insn.operands[0].type != CS_OP_REG:
                continue
            reg = insn.operands[0].reg
            if insn.operands[1].type != CS_OP_IMM:
                continue
            # print(reg)
            for j, espmov in enumerate(insns[i - 1::-1]):
                if not self._writes(espmov, [self._largest_register(reg)]):
                    continue

                if espmov.mnemonic != "mov":
                    break
                if espmov.operands[0].type != CS_OP_REG or espmov.operands[0].reg != reg:
                    continue
                if espmov.operands[1].type != CS_OP_REG or espmov.operands[1].reg != X86_REG_EBP:
                    break


                # print(espmov, espmov.regs_write)
                matches.append([i, i - j - 1, reg, insn.operands[1].imm])
                break
            # matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        # instr = "sub esp, 4"
        # subs = {
        #     match: self._assemble(instr, insns[match].address),
        #     match + 1: None,
        #     match + 2: None,
        #     match + 3: None,
        #     match + 4: None,
        #     match + 5: None,
        # }
        instr = f'lea {self.md.reg_name(match[2])}, [ebp + {hex(match[3])}]'

        subs = {
            match[0]: self._assemble(instr, insns[match[1]].address)
        }
        return subs
