from unicorn import *
from unicorn.x86_const import *
from capstone import *
from pprint import *
md = Cs(CS_ARCH_X86, CS_MODE_32)
ADDRESS = 0x1000000
regs = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
        UC_X86_REG_ESP]
ORIG_SP = ADDRESS + 2 * 1024 * 2048 - 0x200


def trap(emu: Uc, type: int, address: int, size: int, value: int, user_data):
    emu.traps.append((type, address, size, value))
    emu.mem_map(address & 0xfffff000, 4096)
    return True


def read_trap(emu: Uc, type: int, address: int, size: int, value: int, user_data):
    emu.traps.append((type, address, size, value))
    emu.mem_map(address & 0xfffff000, 4096)
    return True


def setup_unicorn(code):
    emu = Uc(UC_ARCH_X86, UC_MODE_32)
    emu.traps = []
    emu.mem_map(ADDRESS, 4096)
    # emu.mem_map(0, 2 * 1024 * 2048)
    emu.mem_map(ORIG_SP & 0xfffff000, 8192)
    emu.mem_write(ADDRESS, code)
    for i, reg in enumerate(regs):
        emu.reg_write(reg, 0x69420 + i)
    emu.reg_write(UC_X86_REG_ESP, ORIG_SP)
    emu.hook_add(UC_HOOK_MEM_READ_INVALID, read_trap)
    emu.hook_add(UC_HOOK_MEM_WRITE_INVALID, trap)

    emu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, trap)
    emu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, read_trap)
    # emu.hook_add(UC_HOOK_MEM_WRITE, trap)
    return emu


setup_unicorn(b"\x90")


def emulate(code):
    emu = setup_unicorn(code)
    emu.emu_start(ADDRESS, ADDRESS + len(code), timeout=30000)
    return emu


def validate(good, bad):
    try:
        goodstate = emulate(good)
    except:
        pprint(list(md.disasm(good, ADDRESS)))
        raise
    badstate = emulate(bad)

    for reg in regs:
        if goodstate.reg_read(reg) != badstate.reg_read(reg):
            print("Register Comparison Failed", md.reg_name(reg), hex(goodstate.reg_read(reg)), hex(badstate.reg_read(reg)))
            return False
    sp = goodstate.reg_read(UC_X86_REG_ESP)
    try:
        # goodstack = goodstate.mem_read(sp, ORIG_SP + 0x20 - sp)
        # badstack = badstate.mem_read(sp, ORIG_SP + 0x20 - sp)
        # if goodstack != badstack:
        #     print("Stack Comparison Failed", goodstack, badstack)
        #     return False
        pass
    except UcError:
        return True
    # if goodstate.traps != badstate.traps:
    #     print("Traps Are Not Equal")
    #     print(goodstate.traps, badstate.traps)
    #     return False
    return True
