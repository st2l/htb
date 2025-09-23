#!/usr/bin/env python3
import argparse
import socket
from typing import Tuple

KEY = b"ef39f4f20e76e33bd25f4db338e81b10"          # ASCII bytes (32B)
NONCE = b"d4c270a3"                               # ASCII bytes (8B)
CIPH_PASSWORD = bytes.fromhex(
    "05055fb1a329a8d558d9f556a6cb31f324432a31c99dec72e33eb66f62ad1bf9"
)
CIPH_FLAG = bytes.fromhex(
    "193978899768a08f66d39017b2e040c237193763c581e261"
)

def _rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))

def _salsa20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    if len(key) not in (16, 32):
        raise ValueError("Salsa20 key must be 16 or 32 bytes")
    if len(key) == 16:
        const = b"expand 16-byte k"
        words = [int.from_bytes(key[i:i+4], "little") for i in range(0, 16, 4)] * 2
    else:
        const = b"expand 32-byte k"
        words = [int.from_bytes(key[i:i+4], "little") for i in range(0, 32, 4)]
    n0 = int.from_bytes(nonce[0:4], "little")
    n1 = int.from_bytes(nonce[4:8], "little")
    c0 = int.from_bytes(const[0:4], "little")
    c1 = int.from_bytes(const[4:8], "little")
    c2 = int.from_bytes(const[8:12], "little")
    c3 = int.from_bytes(const[12:16], "little")
    ctr0 = counter & 0xFFFFFFFF
    ctr1 = (counter >> 32) & 0xFFFFFFFF

    state = [
        c0, words[0], words[1], words[2], words[3], c1,
        n0, n1, ctr0, ctr1, c2, words[4], words[5], words[6], words[7], c3
    ]
    x = state.copy()

    for _ in range(10):   # 20 rounds (column+row)
        x[4] ^= _rotl32((x[0] + x[12]) & 0xFFFFFFFF, 7)
        x[8] ^= _rotl32((x[4] + x[0]) & 0xFFFFFFFF, 9)
        x[12] ^= _rotl32((x[8] + x[4]) & 0xFFFFFFFF, 13)
        x[0] ^= _rotl32((x[12] + x[8]) & 0xFFFFFFFF, 18)

        x[9] ^= _rotl32((x[5] + x[1]) & 0xFFFFFFFF, 7)
        x[13] ^= _rotl32((x[9] + x[5]) & 0xFFFFFFFF, 9)
        x[1] ^= _rotl32((x[13] + x[9]) & 0xFFFFFFFF, 13)
        x[5] ^= _rotl32((x[1] + x[13]) & 0xFFFFFFFF, 18)

        x[14] ^= _rotl32((x[10] + x[6]) & 0xFFFFFFFF, 7)
        x[2] ^= _rotl32((x[14] + x[10]) & 0xFFFFFFFF, 9)
        x[6] ^= _rotl32((x[2] + x[14]) & 0xFFFFFFFF, 13)
        x[10] ^= _rotl32((x[6] + x[2]) & 0xFFFFFFFF, 18)

        x[3] ^= _rotl32((x[15] + x[11]) & 0xFFFFFFFF, 7)
        x[7] ^= _rotl32((x[3] + x[15]) & 0xFFFFFFFF, 9)
        x[11] ^= _rotl32((x[7] + x[3]) & 0xFFFFFFFF, 13)
        x[15] ^= _rotl32((x[11] + x[7]) & 0xFFFFFFFF, 18)

        x[1] ^= _rotl32((x[0] + x[3]) & 0xFFFFFFFF, 7)
        x[2] ^= _rotl32((x[1] + x[0]) & 0xFFFFFFFF, 9)
        x[3] ^= _rotl32((x[2] + x[1]) & 0xFFFFFFFF, 13)
        x[0] ^= _rotl32((x[3] + x[2]) & 0xFFFFFFFF, 18)

        x[6] ^= _rotl32((x[5] + x[4]) & 0xFFFFFFFF, 7)
        x[7] ^= _rotl32((x[6] + x[5]) & 0xFFFFFFFF, 9)
        x[4] ^= _rotl32((x[7] + x[6]) & 0xFFFFFFFF, 13)
        x[5] ^= _rotl32((x[4] + x[7]) & 0xFFFFFFFF, 18)

        x[11] ^= _rotl32((x[10] + x[9]) & 0xFFFFFFFF, 7)
        x[8] ^= _rotl32((x[11] + x[10]) & 0xFFFFFFFF, 9)
        x[9] ^= _rotl32((x[8] + x[11]) & 0xFFFFFFFF, 13)
        x[10] ^= _rotl32((x[9] + x[8]) & 0xFFFFFFFF, 18)

        x[12] ^= _rotl32((x[15] + x[14]) & 0xFFFFFFFF, 7)
        x[13] ^= _rotl32((x[12] + x[15]) & 0xFFFFFFFF, 9)
        x[14] ^= _rotl32((x[13] + x[12]) & 0xFFFFFFFF, 13)
        x[15] ^= _rotl32((x[14] + x[13]) & 0xFFFFFFFF, 18)

    return b"".join(
        ((x[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
        for i in range(16)
    )

def salsa20_crypt(data: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    out = bytearray()
    block = counter
    idx = 0
    while idx < len(data):
        keystream = _salsa20_block(key, nonce, block)
        chunk = data[idx:idx + 64]
        out.extend(a ^ b for a, b in zip(chunk, keystream))
        idx += len(chunk)
        block += 1
    return bytes(out)

def recover_secrets() -> Tuple[bytes, bytes]:
    password = salsa20_crypt(CIPH_PASSWORD, KEY, NONCE)
    flag = salsa20_crypt(CIPH_FLAG, KEY, NONCE)
    return password, flag

def main():
    parser = argparse.ArgumentParser(description="Solve the rauth challenge.")
    parser.add_argument("--host", help="Remote host (omit to skip network interaction)")
    parser.add_argument("--port", type=int, help="Remote port")
    args = parser.parse_args()

    password, flag = recover_secrets()
    print(f"[+] Password: {password.decode()}")
    print(f"[+] Flag    : {flag.decode()}")


if __name__ == "__main__":
    main()