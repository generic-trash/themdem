from .base_pass import *


class DoubleXchgPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-2]):
            seq = insns[i: i + 3]
            if seq[0].mnemonic != "xchg" or "ptr" in seq[0].op_str:
                continue
            if seq[1].mnemonic not in ("inc", "dec", "not", "neg") or seq[1].op_str not in seq[0].op_str:
                continue
            if seq[2].mnemonic != "xchg" or seq[2].op_str != seq[0].op_str:
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns: List[CsInsn], match):
        reg = insns[match + 1].operands[0].reg
        for read in insns[match].operands:
            if read.reg != reg:
                reg = read.reg
                break
        else:
            print(insns)
            raise ValueError
        instr = f"{insns[match + 1].mnemonic} {self.md.reg_name(reg)}"

        subs = {
            match: self._assemble(instr, insns[match].address),
            match + 1: None,
            match + 2: None
        }
        return subs
