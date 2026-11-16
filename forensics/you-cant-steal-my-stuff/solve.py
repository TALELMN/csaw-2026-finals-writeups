#!/usr/bin/env python3
# solve.py — You Can't Steal My Stuff: Vigenere-over-base64 fragments.
import base64


def vig_decrypt(ciphertext, key):
    result = []
    i = 0
    for ch in ciphertext:
        if ch.isascii() and ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[i % len(key)]) - ord("a")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            i += 1          # only letters advance the key position
        else:
            result.append(ch)
    return "".join(result)


key = "almostthere"

metadata = "Y0MgrX9swKRRfF8="      # ICRD field
spoken = "bIxtsWGHgeV9"            # forward speech, ~16.8 s onward

middle_b64 = vig_decrypt(metadata, key)
last_b64 = vig_decrypt(spoken, key)

middle = base64.b64decode(middle_b64).decode("ascii")
last = base64.b64decode(last_b64).decode("ascii")

print("Metadata:", metadata, "->", middle_b64, "->", middle)
print("Speech:  ", spoken, "->", last_b64, "->", last)
print("Flag:", "csaw{but_y0u_" + middle + last)
