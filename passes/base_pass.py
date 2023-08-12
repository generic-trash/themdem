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

    def _substitute_instructions(self, insns, subpoints):
        addr = insns[0].address
        if len(subpoints) == 0:
            return insns
        good = self._to_bytes(insns)
        for loc, sub in subpoints.items():
            insns[loc] = sub

        sanitized = self._sanitize_instructions(insns)
        bad = self._to_bytes(sanitized)
        goodasm = list(self.md.disasm(good, addr))
        if not validate(good, bad):
            # print("-" * 80)
            # pprint(list(self.md.disasm(good, insns[0].address)))
            # print("-" * 80)
            # pprint(sanitized)
            # print("-" * 80)
            # pprint(subpoints)
            # pprint([list(self.md.disasm(good, insns[0].address))[i] for i in subpoints.keys()])
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
        for match in matches:
            substitutions.update(self.generate_substitution(insns, match))
        start = len(insns)
        substituted = self._substitute_instructions(insns, substitutions)
        end = len(substituted)
        if profile:
            print("REDUCTION BY PASS ", self.__class__.__name__, "is", start - end)
        return substituted

    @staticmethod
    def _reads(insn: CsInsn, targops):
        for operand in insn.operands:
            if operand.type == CS_OP_REG and BasePass._largest_register(
                    operand.reg) in targops and operand.access & CS_AC_READ:
                return True
            if operand.type == CS_OP_MEM and {operand.mem.base, operand.mem.index}.intersection(targops):
                return True
        return False

    @staticmethod
    def _writes(insn: CsInsn, targops):
        for operand in insn.operands:
            if operand.type == CS_OP_REG and (
                    operand.reg) in targops and operand.access & CS_AC_WRITE:
                return True
        return False

    @staticmethod
    def _largest_register(reg):
        try:
            return reglut[reg]
        except KeyError:
            return reg
