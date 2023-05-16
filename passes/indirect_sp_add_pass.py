from capstone import *
from keystone import *
from .base_pass import *
from capstone.x86_const import *


class IndirectSpAddPass(BasePass):
    def match_instructions(self, insns):
        matches = []
        for i, insn in enumerate(insns[:-5]):
            seq = insns[i: i + 6]
            if seq[0].mnemonic != "push":
                continue
            if seq[1].mnemonic != "mov" or seq[1].op_str != f"{seq[0].op_str}, esp":
                continue
            if seq[2].mnemonic != "add" or seq[2].op_str != f"{seq[0].op_str}, 4":
                continue
            if seq[3].mnemonic != "add" or seq[3].op_str != f"{seq[0].op_str}, 4":
                continue
            if seq[4].mnemonic != "xchg" or seq[4].op_str not in \
                    (f"{seq[0].op_str}, dword ptr [esp]", f"dword ptr [esp], {seq[0].op_str}"):
                continue
            if seq[5].mnemonic != "mov" or seq[5].op_str != "esp, dword ptr [esp]":
                continue
            matches.append(i)
        return matches

    def generate_substitution(self, insns, match):
        instr = "add esp, 4"
        subs = {
            match: self._assemble(instr, insns[match].address),
            match + 1: None,
            match + 2: None,
            match + 3: None,
            match + 4: None,
            match + 5: None,
        }
        return subs
