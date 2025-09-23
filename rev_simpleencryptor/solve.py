#!/usr/bin/env python3
# decrypt_flag.py
# Usage: python3 decrypt_flag.py flag.enc flag.dec

import sys
import ctypes
from ctypes import c_uint, c_int

def get_libc():
    """
    Return a libc-like handle exposing srand(int) and rand() functions.
    Works on Linux (libc.so.6) and Windows (msvcrt.dll).
    """
    import platform
    system = platform.system()
    if system == "Windows":
        return ctypes.CDLL("msvcrt.dll")
    else:
        # Linux / most Unixes
        return ctypes.CDLL("libc.so.6")

def ror8(x, r):
    x &= 0xFF
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF

def rol8(x, r):
    x &= 0xFF
    r &= 7
    return (( (x << r) & 0xFF) | (x >> (8 - r))) & 0xFF

def decrypt_file(in_path, out_path, try_both_endian=False):
    libc = get_libc()
    # declare argument/return types
    libc.srand.argtypes = [c_uint]
    libc.srand.restype = None
    libc.rand.argtypes = []
    libc.rand.restype = c_int

    data = open(in_path, "rb").read()
    if len(data) < 4:
        raise SystemExit("input too small")

    # first 4 bytes are seed (little-endian in typical C on x86). We'll try little-endian
    def attempt(seed):
        libc.srand(c_uint(seed))
        ciphertext = data[4:]
        out = bytearray(len(ciphertext))
        # For each ciphertext byte we do the same sequence of two rand() calls used in the C code
        for i, cb in enumerate(ciphertext):
            r1 = libc.rand() & 0xFFFFFFFF  # rand() returns positive int (implementation dependent)
            r2 = libc.rand() & 0xFFFFFFFF
            rot = r2 & 7
            t = ror8(cb, rot)    # undo rol
            pb = (t ^ (r1 & 0xFF)) & 0xFF   # rand() is full int; in original code they XOR byte with rand() (C will promote)
            # Important: the original code did: *((_BYTE *)ptr + i) ^= rand();
            # That XOR with a full rand() is equivalent to XOR with low 8 bits of rand() for a byte.
            out[i] = pb
        return bytes(out)

    # try little-endian first
    seed_le = int.from_bytes(data[:4], "little")
    plaintext = attempt(seed_le)

    # Basic heuristic: check ascii-printability ratio to guess correct decryption
    def printable_ratio(b):
        if not b:
            return 0.0
        good = sum(1 for x in b if 32 <= x < 127 or x in (9,10,13))
        return good / len(b)

    ratio = printable_ratio(plaintext)
    if try_both_endian and ratio < 0.5:
        # try big-endian seed as a fallback
        seed_be = int.from_bytes(data[:4], "big")
        plaintext2 = attempt(seed_be)
        ratio2 = printable_ratio(plaintext2)
        if ratio2 > ratio:
            print(f"Chose big-endian seed {seed_be} (ratio {ratio2:.2f}) over little-endian {seed_le} (ratio {ratio:.2f})")
            plaintext = plaintext2
        else:
            print(f"Chose little-endian seed {seed_le} (ratio {ratio:.2f})")
    else:
        print(f"Used little-endian seed {seed_le} (printable ratio {ratio:.2f})")

    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"Wrote decrypted output to {out_path}")

if __name__ == "__main__":
    if len(sys.argv) not in (2,3):
        print("Usage: python3 decrypt_flag.py flag.enc [flag.dec]")
        sys.exit(1)
    in_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) == 3 else "flag.dec"
    decrypt_file(in_path, out_path, try_both_endian=True)
