#!/usr/bin/env python3
# solve.py — OpConsole: decrypt the launcher's xorshift64* keystream.
#
# usage: python3 solve.py ./opconsole
# dependency: pyelftools
import sys
from elftools.elf.elffile import ELFFile

with open(sys.argv[1], 'rb') as f:
    e = ELFFile(f)
    section = e.get_section_by_name('.rodata')
    offset = 0x40e0d0 - section['sh_addr']
    ciphertext = section.data()[offset:offset + 25]

mask = (1 << 64) - 1
state = 0x052c03586b73f22b
flag = bytearray()
for byte in ciphertext:
    state ^= state >> 12
    state ^= (state << 25) & mask
    state ^= state >> 27
    key = ((state * 0x2545f4914f6cdd1d) & mask) >> 56
    flag.append(byte ^ key)
print(flag.decode())
