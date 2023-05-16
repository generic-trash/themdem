import angr
from angr import *
from capstone import *
from keystone import *
from passes import *
from pprint import pprint

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
ks = Ks(KS_ARCH_X86, KS_MODE_32)

project = angr.Project("windows_rootfs/vc_example_protected_debug.exe")
mem = project.loader.memory

locs = [(0x269360c, 0x269370d)]
allpass = AllPass(md, ks)

for start, end in locs:
    size = end - start
    data = mem.load(start, size)
    insns = list(md.disasm(data, start))
    pprint(insns)
    print("=" * 80)
    insns = allpass(insns, profile=True, profile_sub=False)
    print("=" * 80)
    pprint(insns)
