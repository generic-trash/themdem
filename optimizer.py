import angr
import lief.PE
from angr import *
from capstone import *
from keystone import *
from passes import *
from pprint import pprint
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

path = "windows_rootfs/vc_example_protected_fish_white.exe"
fdesc = open(path, "rb")
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
ks = Ks(KS_ARCH_X86, KS_MODE_32)

project = angr.Project(path)
mem = project.loader.memory
pefile = lief.PE.parse(fdesc)
loc_db = LocationDB()
cont = Container.from_stream(fdesc, loc_db)
machine = Machine(cont.arch)
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
addrs = [
    0x2771615,
    0x276a57f,
    0x27380dc,
    0x27aaf9d,
    0x27adc9b,
    0x27833ab,
    0x27499ab
]

locs = []

for addr in addrs:
    asmcfg = mdis.dis_multiblock(addr)

    locs += [block.get_range() for block in asmcfg.blocks]
allpass = AllPass(md, ks)

for start, end in locs:
    size = end - start
    data = mem.load(start, size)
    insns = list(md.disasm(data, start))
    lastinsn = insns[-1]
    if lastinsn.group(CS_GRP_CALL) or lastinsn.group(CS_GRP_JUMP):
        insns = insns[:-1]
        size -= lastinsn.size
    # pprint(insns)
    # print("=" * 80)
    insns = allpass(insns, profile=True, profile_sub=False)
    print("=" * 80)
    pprint(insns)
    print("=" * 80)
    print("=" * 80)

    seq = b""
    for insn in insns:
        if insn.mnemonic == "mov" and insn.op_str == "esp, dword ptr [esp]":
            raise Exception("esp write detected")
        seq += insn.bytes

    seq += b"\x90" * (size - len(seq))
    pefile.patch_address(start, list(seq))

pefile.write("vc_example_protected_demutated.exe")
