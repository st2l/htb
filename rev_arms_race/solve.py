from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import *
from capstone import *
import binascii

from pwn import *

io = remote('94.237.57.1', 37382)

for _ in range(50):
    io.recvuntil(b': ')

    HEX = io.recvline().decode('utf-8').strip()
    log.warn(HEX)

    CODE = binascii.unhexlify(HEX)

    BASE = 0x1000
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    # map 4KB for code + a little slack
    mu.mem_map(BASE, 0x3000)
    mu.mem_write(BASE, CODE)

    # optional: disassemble so we can see progress
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

    # start with clean registers (not required, but nice)
    for r in [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
            UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
            UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
            UC_ARM_REG_R12, UC_ARM_REG_R14]:
        mu.reg_write(r, 0)

    # Step through each instruction and track r0
    pc = BASE
    end = BASE + len(CODE)

    print("Disassembly + r0 after each step:")
    for insn in md.disasm(CODE, BASE):
        # execute just this 4-byte instruction
        mu.reg_write(UC_ARM_REG_PC, pc)
        try:
            mu.emu_start(pc, pc+4)
        except Exception as e:
            print(f"Emulation error at 0x{pc:x}: {e}")
            break
        r0 = mu.reg_read(UC_ARM_REG_R0)
        print(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str:24s} | r0=0x{r0:08x}")
        pc += 4
        if pc >= end:
            break

    final_r0 = mu.reg_read(UC_ARM_REG_R0)
    log.warn(f"\nFINAL r0 = {hex(final_r0)}")

    io.sendlineafter(b'Register r0:', str(final_r0))

io.interactive()
