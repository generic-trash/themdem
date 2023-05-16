from capstone import *
from keystone import *
from typing import List
from .validation import *


class BasePass:
    def __init__(self, md: Cs, ks: Ks):
        self.md = md
        self.ks = ks

    def _assemble(self, insn, address):
        assembled = self.ks.asm(insn.encode())
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
        good = self._to_bytes(insns)

        for loc, sub in subpoints.items():
            insns[loc] = sub

        sanitized = self._sanitize_instructions(insns)
        bad = self._to_bytes(sanitized)
        assert validate(good, bad)
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
