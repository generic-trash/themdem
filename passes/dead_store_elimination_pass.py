from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *
from triton import *



class DSEPass(BasePass):
    ctx = TritonContext(ARCH.X86)

    def match_instructions(self, insns: List[CsInsn]):
        matches = []
        self.highlights = []
        for i, insn in enumerate(insns[:-1]):
            targops = []
            if insn.mnemonic in ["push", "pop", "xchg"]:
                continue
            for operand in insn.operands:
                if operand.type != CS_OP_REG:
                    continue
                if operand.access & CS_AC_WRITE:
                    targops.append(operand.reg)
            if len(targops) > 1:
                continue

            for j, overwriter in enumerate(insns[i + 1:]):
                if overwriter.mnemonic in ["pushfd"]:
                    break
                if self._reads(overwriter, targops):
                    break
                if self._writes(overwriter, targops):
                    matches.append(i)
                    self.highlights.append(i + 1 + j)
                    break
        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        subs = {match: None}
        return subs
