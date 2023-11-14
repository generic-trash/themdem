from capstone import *
from keystone import *
from typing import List
from .validation import *
from pprint import pprint
from colorama import *
from capstone.x86_const import *

reglut = {
    X86_REG_AX: X86_REG_EAX,
    X86_REG_BX: X86_REG_EBX,
    X86_REG_CX: X86_REG_ECX,
    X86_REG_DX: X86_REG_EDX,
    X86_REG_AL: X86_REG_EAX,
    X86_REG_BL: X86_REG_EBX,
    X86_REG_CL: X86_REG_ECX,
    X86_REG_DL: X86_REG_EDX,
    X86_REG_AH: X86_REG_EAX,
    X86_REG_BH: X86_REG_EBX,
    X86_REG_CH: X86_REG_ECX,
    X86_REG_DH: X86_REG_EDX,
    X86_REG_DIL: X86_REG_EDI,
    X86_REG_DI: X86_REG_EDI,
    X86_REG_SIL: X86_REG_ESI,
    X86_REG_SI: X86_REG_ESI,
}


class BasePass:
    def __init__(self, md: Cs, ks: Ks):
        self.highlights = []
        self.md = md
        self.ks = ks

    def _assemble(self, insn, address):
        try:
            assembled = self.ks.asm(insn.encode())
        except KsError:
            print(insn)
            raise
        return self._disassemble(bytes(assembled[0]), address)

    def _disassemble(self, data, address):
        return list(self.md.disasm(data, address))[0]

    @staticmethod
    def _sanitize_instructions(insns):
        sanitized = []
        for insn in insns:
            if insn is not None:
                sanitized.append(insn)

        return sanitized

    @staticmethod
    def _to_bytes(insns):
        seq = b""
        for insn in insns:
            seq += insn.bytes
        return seq

    def _substitute_instructions(self, insns, subpoints, singlestep_subpoints, normal):
        try:
            addr = insns[0].address
        except:
            print(insns)
            print(normal)
            raise
        if len(subpoints) == 0:
            return insns
        good = self._to_bytes(insns)
        goodasm = list(self.md.disasm(good, addr))

        for loc, sub in subpoints.items():
            insns[loc] = sub

        sanitized = self._sanitize_instructions(insns)
        bad = self._to_bytes(sanitized)

        if not validate(good, bad):
            if normal:
                for sub in singlestep_subpoints:
                    goodasm_sub = list(self.md.disasm(good, addr))

                    self._substitute_instructions(goodasm_sub, sub, [], False)
            else:
                for i, insn in enumerate(goodasm):
                    try:
                        if subpoints[i] is None:
                            print(Fore.RED, Style.BRIGHT, "-", insn)
                        elif subpoints[i]:
                            print(Fore.RED, Style.BRIGHT, "-", insn)
                            print(Fore.GREEN, Style.BRIGHT, "+", subpoints[i])
                    except KeyError:
                        if i in self.highlights:
                            print(Fore.BLUE, Style.BRIGHT, insn)
                        else:
                            print(Style.RESET_ALL, insn)
                print(Style.RESET_ALL)

            raise AssertionError("value is not same for pass, ", self.__class__.__name__)
        return sanitized

    def _match_instructions(self, insns, pattern):
        pass

    def match_instructions(self, insns):
        return []

    def generate_substitution(self, insns: List[CsInsn], match):
        return {}

    def __call__(self, insns: List[CsInsn], profile=False, profile_sub=False):
        matches = self.match_instructions(insns)
        substitutions = {}
        substitutions_singlestep = []
        for match in matches:
            sub = self.generate_substitution(insns, match)
            substitutions.update(sub)
            substitutions_singlestep.append(sub)
        start = len(insns)
        substituted = self._substitute_instructions(insns, substitutions, substitutions_singlestep, True)
        end = len(substituted)
        if profile:
            print("REDUCTION BY PASS ", self.__class__.__name__, "is", start - end)
        return substituted

    @staticmethod
    def _reads(insn: CsInsn, targops):
        if len(targops) == 0:
            return False
        for operand in insn.operands:
            if operand.type == CS_OP_REG and BasePass._largest_register(
                    operand.reg) == BasePass._largest_register(targops[0]) and operand.access & CS_AC_READ:
                return True
            if operand.type == CS_OP_MEM and {operand.mem.base, operand.mem.index}.intersection({BasePass._largest_register(targops[0])}):
                return True
        return False

    @staticmethod
    def _writes(insn: CsInsn, targops):
        if len(targops) == 0:
            return False
        for operand in insn.operands:
            if operand.type == CS_OP_REG and operand.reg in {BasePass._largest_register(targops[0])} and operand.access & CS_AC_WRITE:
                return True
        return False

    @staticmethod
    def _largest_register(reg):
        try:
            return reglut[reg]
        except KeyError:
            return reg
