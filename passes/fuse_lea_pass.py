from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *
from re import *

class FuseLeaPass(BasePass):
    def match_instructions(self, insns: List[CsInsn]):
        matches = []
        for i, insn in enumerate(insns):
            memop = 0
            for operand in insn.operands:
                if operand.type == CS_OP_MEM:
                    memop = operand.mem.base
            if memop == 0:
                continue
            # print(reg)
            for j, espmov in enumerate(insns[i - 1::-1]):
                if not self._writes(espmov, [BasePass._largest_register(memop)]):
                    continue
                if espmov.mnemonic != "lea":
                    break

                # print(espmov, espmov.regs_write)
                replaced = sub('\[.*\]', search('\[.*\]', espmov.op_str).group(0), insn.op_str)
                matches.append([i, f"{insn.mnemonic} {replaced}"])
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

        subs = {
            match[0]: self._assemble(match[1], insns[match[0]].address)
        }
        return subs
